//! Detection module — orchestrates indicator detection, risk scoring,
//! and scam type classification.

pub mod keyword;
pub mod embedding;
pub mod url;
pub mod scoring;

use serde::{Deserialize, Serialize};
use crate::channel::Channel;
use crate::ontology::{IndicatorHit, IndicatorHitExplained};
use crate::taxonomy::ScamType;
use crate::family::FamilyAlert;
use crate::decision_trace::DecisionTrace;

/// The predicted outcome of a detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PredictedOutcome {
    Scam,
    Suspicious,
    Benign,
}

impl PredictedOutcome {
    pub fn as_str(&self) -> &'static str {
        match self {
            PredictedOutcome::Scam => "scam",
            PredictedOutcome::Suspicious => "suspicious",
            PredictedOutcome::Benign => "benign",
        }
    }
}

impl std::fmt::Display for PredictedOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Result of a scam detection analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionResult {
    /// Unique ID for this detection (used for feedback correlation).
    pub id: String,
    /// Predicted outcome: scam, suspicious, or benign.
    pub predicted_outcome: PredictedOutcome,
    /// Predicted scam type (if outcome is Scam or Suspicious).
    pub scam_type: Option<ScamType>,
    /// Risk bucket 1-5 (1=benign, 5=very likely scam).
    pub risk_bucket: u8,
    /// Top indicators (max 3) with their strengths.
    pub indicators: Vec<IndicatorHit>,
    /// Top indicators with user-facing explanations and contribution ranks.
    pub indicator_explanations: Vec<IndicatorHitExplained>,
    /// Detection channel.
    pub channel: Channel,
    /// Coarse language bucket.
    pub language_bucket: String,
    /// Model version used for detection.
    pub model_version: String,
    /// Prompt version (for UX bias measurement).
    pub prompt_version: String,
    /// Duration of detection in milliseconds.
    pub duration_ms: u64,
    /// Family alert triggered by this detection (if any).
    /// Only present when a family circle is configured and the
    /// detection exceeds the member's threshold.
    pub family_alert: Option<FamilyAlert>,
    /// Privacy-bounded decision trace for this detection.
    /// Contains no raw text, sender, or sensitive metadata.
    pub decision_trace: Option<DecisionTrace>,
}
impl DetectionResult {
    /// Whether this detection should trigger a family alert.
    pub fn should_alert(&self, threshold: u8) -> bool {
        self.risk_bucket >= threshold
    }
}
