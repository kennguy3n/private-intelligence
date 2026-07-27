//! Family construct — family unit protection with per-member sensitivity
//! thresholds, guardian alerts, and shared scam awareness.
//!
//! KinShield protects a family group. Shared alerts notify guardians when
//! any member receives a high-risk detection. Per-member thresholds allow
//! different sensitivity levels for elderly, children, and teens.

use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use crate::channel::Channel;
use crate::detection::DetectionResult;
use crate::ontology::IndicatorId;

/// A family circle — a group of members protected together.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FamilyCircle {
    /// Unique identifier for the family circle.
    pub id: String,
    /// Family members in this circle.
    pub members: Vec<FamilyMember>,
    /// Whether alerts are shared across the family.
    pub shared_alerts: bool,
    /// Minimum risk bucket to trigger a family-wide alert.
    pub alert_threshold: u8,
    /// Pre-registered emergency contacts (phone numbers, emails, handles).
    /// Messages from these contacts are treated as "known sender" and
    /// receive a risk reduction, lowering false positives for trusted sources.
    /// Never transmitted — stored locally only.
    pub emergency_contacts: Vec<EmergencyContact>,
}

impl FamilyCircle {
    /// Create a new family circle with default settings.
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            members: Vec::new(),
            shared_alerts: true,
            alert_threshold: 4,
            emergency_contacts: Vec::new(),
        }
    }

    /// Add a member to the family circle.
    pub fn add_member(&mut self, member: FamilyMember) {
        self.members.push(member);
    }

    /// Find a member by ID.
    pub fn member(&self, id: &str) -> Option<&FamilyMember> {
        self.members.iter().find(|m| m.id == id)
    }

    /// Find a member by ID (mutable).
    pub fn member_mut(&mut self, id: &str) -> Option<&mut FamilyMember> {
        self.members.iter_mut().find(|m| m.id == id)
    }

    /// Get all guardians in the circle.
    pub fn guardians(&self) -> Vec<&FamilyMember> {
        self.members.iter().filter(|m| m.role.is_guardian()).collect()
    }

    /// Add an emergency contact to the family circle.
    pub fn add_emergency_contact(&mut self, contact: EmergencyContact) {
        self.emergency_contacts.push(contact);
    }

    /// Check if a sender identifier matches any emergency contact.
    /// Returns the matched contact if found.
    pub fn find_emergency_contact(&self, sender: &str) -> Option<&EmergencyContact> {
        let sender_lower = sender.to_lowercase();
        self.emergency_contacts.iter().find(|c| {
            c.identifier.to_lowercase() == sender_lower
        })
    }

    /// Check if a detection should trigger a family alert for a specific member.
    pub fn check_alert(&self, member_id: &str, result: &DetectionResult) -> Option<FamilyAlert> {
        let member = self.member(member_id)?;

        // Check per-member threshold
        let threshold = member.sensitivity.risk_threshold;
        if result.risk_bucket < threshold {
            return None;
        }

        // Check per-channel overrides
        if let Some(&channel_threshold) = member.sensitivity.channel_overrides.get(&result.channel) {
            if result.risk_bucket < channel_threshold {
                return None;
            }
        }

        // Check blocked indicators — if all detected indicators are blocked, skip
        if !member.sensitivity.blocked_indicators.is_empty() {
            let all_blocked = result.indicators.iter().all(|h| {
                member.sensitivity.blocked_indicators.contains(&h.id)
            });
            if all_blocked {
                return None;
            }
        }

        // Determine alert targets
        let alert_targets: Vec<String> = if member.alert_guardian {
            // Alert the designated guardian
            if let Some(ref guardian_id) = member.guardian_id {
                vec![guardian_id.clone()]
            } else {
                // No specific guardian — alert all guardians
                self.guardians().iter().map(|g| g.id.clone()).collect()
            }
        } else {
            Vec::new()
        };

        Some(FamilyAlert {
            family_id: self.id.clone(),
            member_id: member_id.to_string(),
            risk_bucket: result.risk_bucket,
            channel: result.channel,
            scam_type: result.scam_type,
            alert_targets,
            timestamp: chrono::Utc::now(),
        })
    }
}

/// A family member with role-based sensitivity configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FamilyMember {
    /// Unique identifier for this member.
    pub id: String,
    /// Display name (local only, never transmitted).
    pub name: String,
    /// Role within the family.
    pub role: MemberRole,
    /// Sensitivity configuration for this member.
    pub sensitivity: SensitivityConfig,
    /// Whether to alert a guardian for this member's detections.
    pub alert_guardian: bool,
    /// Designated guardian's member ID (if alert_guardian is true).
    pub guardian_id: Option<String>,
}

impl FamilyMember {
    /// Create a new family member with role-appropriate defaults.
    pub fn new(id: impl Into<String>, name: impl Into<String>, role: MemberRole) -> Self {
        let sensitivity = SensitivityConfig::for_role(&role);
        let alert_guardian = role.needs_guardian();

        Self {
            id: id.into(),
            name: name.into(),
            role,
            sensitivity,
            alert_guardian,
            guardian_id: None,
        }
    }

    /// Set the guardian for this member.
    pub fn with_guardian(mut self, guardian_id: impl Into<String>) -> Self {
        self.guardian_id = Some(guardian_id.into());
        self
    }
}

/// Member role within the family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MemberRole {
    /// Adult guardian — can receive alerts about other members.
    Adult,
    /// Elderly member — may need higher sensitivity (lower threshold).
    Elderly,
    /// Teenager — moderate sensitivity.
    Teen,
    /// Child — highest sensitivity, always alerts guardian.
    Child,
}

impl MemberRole {
    /// Whether this role is a guardian.
    pub fn is_guardian(&self) -> bool {
        matches!(self, MemberRole::Adult)
    }

    /// Whether this role needs a guardian.
    pub fn needs_guardian(&self) -> bool {
        matches!(self, MemberRole::Child | MemberRole::Elderly | MemberRole::Teen)
    }

    /// Human-readable label.
    pub fn label(&self) -> &'static str {
        match self {
            MemberRole::Adult => "Adult",
            MemberRole::Elderly => "Elderly",
            MemberRole::Teen => "Teen",
            MemberRole::Child => "Child",
        }
    }
}

/// Per-member sensitivity configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SensitivityConfig {
    /// Minimum risk bucket to trigger an alert for this member.
    pub risk_threshold: u8,
    /// Per-channel threshold overrides.
    pub channel_overrides: HashMap<Channel, u8>,
    /// Indicators to ignore for this member (e.g., reduce false positives
    /// for a member who receives many legitimate financial messages).
    pub blocked_indicators: Vec<IndicatorId>,
}

impl SensitivityConfig {
    /// Create default config for a role.
    pub fn for_role(role: &MemberRole) -> Self {
        match role {
            MemberRole::Adult => Self {
                risk_threshold: 4,
                channel_overrides: HashMap::new(),
                blocked_indicators: Vec::new(),
            },
            MemberRole::Elderly => Self {
                // Lower threshold — elderly are more vulnerable
                risk_threshold: 3,
                channel_overrides: {
                    let mut m = HashMap::new();
                    // SMS and calls are primary scam vectors for elderly
                    m.insert(Channel::Sms, 3);
                    m.insert(Channel::Call, 3);
                    m
                },
                blocked_indicators: Vec::new(),
            },
            MemberRole::Teen => Self {
                risk_threshold: 3,
                channel_overrides: {
                    let mut m = HashMap::new();
                    // Messaging apps are primary vector for teens
                    m.insert(Channel::Messaging, 3);
                    m
                },
                blocked_indicators: Vec::new(),
            },
            MemberRole::Child => Self {
                // Lowest threshold — children are most vulnerable
                risk_threshold: 2,
                channel_overrides: {
                    let mut m = HashMap::new();
                    m.insert(Channel::Sms, 2);
                    m.insert(Channel::Messaging, 2);
                    m.insert(Channel::Browser, 3);
                    m
                },
                blocked_indicators: Vec::new(),
            },
        }
    }

    /// Create a custom sensitivity config.
    pub fn custom(threshold: u8) -> Self {
        Self {
            risk_threshold: threshold,
            channel_overrides: HashMap::new(),
            blocked_indicators: Vec::new(),
        }
    }

    /// Add a channel-specific threshold override.
    pub fn with_channel_override(mut self, channel: Channel, threshold: u8) -> Self {
        self.channel_overrides.insert(channel, threshold);
        self
    }

    /// Add an indicator to block (ignore) for this member.
    pub fn with_blocked_indicator(mut self, indicator: IndicatorId) -> Self {
        self.blocked_indicators.push(indicator);
        self
    }
}

/// A family alert triggered by a high-risk detection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FamilyAlert {
    /// Family circle ID.
    pub family_id: String,
    /// Member who triggered the alert.
    pub member_id: String,
    /// Risk bucket that triggered the alert.
    pub risk_bucket: u8,
    /// Channel of the detected message.
    pub channel: Channel,
    /// Predicted scam type.
    pub scam_type: Option<crate::taxonomy::ScamType>,
    /// Member IDs who should receive the alert (guardians).
    pub alert_targets: Vec<String>,
    /// When the alert was generated.
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

impl FamilyAlert {
    /// Serialize to JSON.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
}

impl std::fmt::Display for FamilyAlert {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "FamilyAlert {{")?;
        writeln!(f, "  family: {}", self.family_id)?;
        writeln!(f, "  member: {}", self.member_id)?;
        writeln!(f, "  risk: {}/5", self.risk_bucket)?;
        writeln!(f, "  channel: {}", self.channel)?;
        if let Some(ref t) = self.scam_type {
            writeln!(f, "  scam_type: {}", t)?;
        }
        writeln!(f, "  targets: {:?}", self.alert_targets)?;
        write!(f, "}}")
    }
}

/// A pre-registered emergency contact for the family circle.
///
/// Messages from emergency contacts are treated as "known sender" and
/// receive a risk reduction to lower false positives. The identifier
/// can be a phone number, email address, or messaging handle.
/// Stored locally only — never transmitted.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmergencyContact {
    /// Contact identifier (phone number, email, or handle).
    pub identifier: String,
    /// Display name for the contact (local only).
    pub name: String,
    /// Relationship to the family (e.g., "family doctor", "school").
    pub relationship: String,
    /// Associated channel (if applicable).
    pub channel: Option<Channel>,
}

impl EmergencyContact {
    /// Create a new emergency contact.
    pub fn new(
        identifier: impl Into<String>,
        name: impl Into<String>,
        relationship: impl Into<String>,
    ) -> Self {
        Self {
            identifier: identifier.into(),
            name: name.into(),
            relationship: relationship.into(),
            channel: None,
        }
    }

    /// Set the associated channel for this contact.
    pub fn with_channel(mut self, channel: Channel) -> Self {
        self.channel = Some(channel);
        self
    }
}
