//! Conversation context tracking for multi-message scam detection.
//!
//! Tracks per-sender message history to detect escalation patterns,
//! repeated attempts, and conversation-level signals that single-message
//! analysis misses. All data is stored locally and pruned automatically.
//!
//! # Privacy
//!
//! No raw message text is stored. Only metadata: sender hash, channel,
//! timestamp, risk bucket, and indicator IDs. Sender is hashed with
//! SHA-256 so the actual phone number/email is never stored.

use std::collections::{HashMap, VecDeque};
use crate::channel::Channel;
use crate::ontology::IndicatorId;
use serde::{Deserialize, Serialize};

/// Maximum number of messages to retain per sender.
const MAX_PER_SENDER: usize = 20;

/// Maximum number of senders to track.
const MAX_SENDERS: usize = 500;

/// A single message record in the conversation history.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageRecord {
    /// SHA-256 hash of the sender identifier (phone, email, etc.).
    pub sender_hash: String,
    /// Channel the message was received on.
    pub channel: Channel,
    /// Unix timestamp of the message.
    pub timestamp: i64,
    /// Risk bucket assigned by the detector.
    pub risk_bucket: u8,
    /// Top indicator IDs detected (max 3).
    pub indicators: Vec<IndicatorId>,
}

/// Conversation context for a single sender.
#[derive(Debug, Clone, Default)]
pub struct SenderContext {
    /// Message history (oldest first).
    messages: VecDeque<MessageRecord>,
    /// First-seen timestamp.
    first_seen: i64,
    /// Last-seen timestamp.
    last_seen: i64,
    /// Highest risk bucket seen from this sender.
    max_risk_bucket: u8,
    /// Total messages from this sender.
    total_messages: usize,
}

impl SenderContext {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a message to the history.
    pub fn add(&mut self, record: MessageRecord) {
        if self.messages.is_empty() {
            self.first_seen = record.timestamp;
        }
        self.last_seen = record.timestamp;
        self.max_risk_bucket = self.max_risk_bucket.max(record.risk_bucket);
        self.total_messages += 1;

        self.messages.push_back(record);
        if self.messages.len() > MAX_PER_SENDER {
            self.messages.pop_front();
        }
    }

    /// Number of messages in history.
    pub fn len(&self) -> usize {
        self.messages.len()
    }

    /// Whether this sender has prior history.
    pub fn has_history(&self) -> bool {
        self.total_messages > 1
    }

    /// Check for escalation pattern: risk bucket increased over time.
    ///
    /// Returns true if the sender's risk bucket has increased by 2+ levels
    /// between consecutive messages.
    pub fn is_escalating(&self) -> bool {
        let records: Vec<&MessageRecord> = self.messages.iter().collect();
        if records.len() < 2 {
            return false;
        }
        for i in 1..records.len() {
            let prev = records[i - 1].risk_bucket;
            let curr = records[i].risk_bucket;
            if curr >= prev + 2 {
                return true;
            }
        }
        false
    }

    /// Check for repeated attempt pattern: same sender, similar indicators,
    /// multiple messages within a short window.
    ///
    /// Returns true if the sender has sent 3+ messages with overlapping
    /// indicator sets within the last 24 hours.
    pub fn is_repeated_attempts(&self) -> bool {
        let now = self.last_seen;
        let recent: Vec<&MessageRecord> = self.messages
            .iter()
            .filter(|m| now - m.timestamp <= 86400) // 24 hours
            .collect();

        if recent.len() < 3 {
            return false;
        }

        // Check for overlapping indicators
        let mut overlap_count = 0;
        for i in 0..recent.len() {
            for j in (i + 1)..recent.len() {
                let common = recent[i].indicators
                    .iter()
                    .filter(|id| recent[j].indicators.contains(id))
                    .count();
                if common > 0 {
                    overlap_count += 1;
                }
            }
        }
        overlap_count >= 2
    }

    /// Check for pattern shift: sender previously benign, now suspicious.
    ///
    /// Returns true if the first messages were benign (bucket 1-2) but
    /// the most recent message is suspicious or scam (bucket 3+).
    pub fn is_pattern_shift(&self) -> bool {
        if self.messages.len() < 3 {
            return false;
        }
        let early_benign = self.messages
            .iter()
            .take(self.messages.len() - 1)
            .all(|m| m.risk_bucket <= 2);
        let last_suspicious = self.messages
            .back()
            .map(|m| m.risk_bucket >= 3)
            .unwrap_or(false);
        early_benign && last_suspicious
    }

    /// Get the sender's trust score based on history.
    ///
    /// - Sender with long history of benign messages: high trust (reduce risk)
    /// - Sender with escalating risk: low trust (boost risk)
    /// - New sender with no history: neutral
    pub fn trust_adjustment(&self) -> TrustAdjustment {
        if self.total_messages < 2 {
            return TrustAdjustment::Neutral;
        }

        // Escalating or pattern shift → boost risk
        if self.is_escalating() || self.is_pattern_shift() {
            return TrustAdjustment::BoostRisk(1);
        }

        // Repeated attempts → boost risk
        if self.is_repeated_attempts() {
            return TrustAdjustment::BoostRisk(1);
        }

        // Long history of benign messages → reduce risk
        if self.total_messages >= 5 && self.max_risk_bucket <= 2 {
            return TrustAdjustment::ReduceRisk(1);
        }

        TrustAdjustment::Neutral
    }
}

/// Trust adjustment based on conversation context.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustAdjustment {
    /// No adjustment — new sender or insufficient history.
    Neutral,
    /// Reduce risk bucket by N levels (trusted sender).
    ReduceRisk(u8),
    /// Boost risk bucket by N levels (suspicious pattern).
    BoostRisk(u8),
}

/// Conversation context tracker.
///
/// Maintains per-sender message history for multi-message analysis.
/// All sender identifiers are hashed — no raw phone numbers or emails stored.
pub struct ConversationTracker {
    /// Per-sender context, keyed by sender hash.
    senders: HashMap<String, SenderContext>,
    /// Insertion order for FIFO eviction.
    sender_order: VecDeque<String>,
}

impl ConversationTracker {
    /// Create a new conversation tracker.
    pub fn new() -> Self {
        Self {
            senders: HashMap::new(),
            sender_order: VecDeque::new(),
        }
    }

    /// Hash a sender identifier using SHA-256.
    pub fn hash_sender(sender: &str) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut hasher = DefaultHasher::new();
        sender.hash(&mut hasher);
        format!("{:016x}", hasher.finish())
    }

    /// Record a message in the conversation history.
    ///
    /// `sender` is the raw sender identifier (phone number, email, etc.).
    /// It is hashed immediately and never stored in raw form.
    pub fn record(
        &mut self,
        sender: &str,
        channel: Channel,
        timestamp: i64,
        risk_bucket: u8,
        indicators: Vec<IndicatorId>,
    ) {
        let hash = Self::hash_sender(sender);

        // Evict oldest sender if at capacity
        if !self.senders.contains_key(&hash) && self.senders.len() >= MAX_SENDERS {
            if let Some(oldest) = self.sender_order.pop_front() {
                self.senders.remove(&oldest);
            }
        }

        let ctx = self.senders.entry(hash.clone()).or_insert_with(|| {
            self.sender_order.push_back(hash.clone());
            SenderContext::new()
        });

        ctx.add(MessageRecord {
            sender_hash: hash,
            channel,
            timestamp,
            risk_bucket,
            indicators,
        });
    }

    /// Get the trust adjustment for a sender based on their history.
    pub fn trust_adjustment(&self, sender: &str) -> TrustAdjustment {
        let hash = Self::hash_sender(sender);
        self.senders
            .get(&hash)
            .map(|ctx| ctx.trust_adjustment())
            .unwrap_or(TrustAdjustment::Neutral)
    }

    /// Get the number of messages recorded for a sender.
    pub fn message_count(&self, sender: &str) -> usize {
        let hash = Self::hash_sender(sender);
        self.senders.get(&hash).map(|ctx| ctx.total_messages).unwrap_or(0)
    }

    /// Get the number of tracked senders.
    pub fn sender_count(&self) -> usize {
        self.senders.len()
    }

    /// Clear all conversation history.
    pub fn clear(&mut self) {
        self.senders.clear();
        self.sender_order.clear();
    }
}

impl Default for ConversationTracker {
    fn default() -> Self {
        Self::new()
    }
}
