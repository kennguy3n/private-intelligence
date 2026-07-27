//! Bounded decision trace — privacy-preserving structured record of
//! each detection event.
//!
//! **Explicitly excluded:** sender, domain, URL, message length, exact
//! timestamp, exact location, contact status, raw probability vector,
//! persistent device identifier, embeddings, token-level probabilities,
//! attention maps, hidden states, SHAP vectors, full logits, per-example
//! gradients, free-text explanations.

use serde::{Deserialize, Serialize};
use crate::ontology::IndicatorHit;
use crate::feedback::FeedbackKind;
use crate::detection::DetectionResult;
use crate::ontology::ONTOLOGY_VERSION;
use crate::taxonomy::SCAM_TAXONOMY_VERSION;

/// A local-only correlation ID used to link feedback to traces.
/// This field is stripped before transmission for aggregation.
/// It is never sent off-device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalCorrelationId(pub String);

/// Trust level of the label associated with a decision trace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LabelConfidence {
    /// Low-medium trust — user thumb feedback.
    UserFeedback,
    /// Medium trust — user explicitly reported scam.
    UserReport,
    /// Medium-high — multiple independent user reports.
    MultipleReports,
    /// High — bank, telco, platform, or analyst confirmation.
    ExternallyConfirmed,
    /// Highest — controlled honeypot evidence.
    Honeypot,
}

impl LabelConfidence {
    pub fn as_str(&self) -> &'static str {
        match self {
            LabelConfidence::UserFeedback => "user_feedback",
            LabelConfidence::UserReport => "user_report",
            LabelConfidence::MultipleReports => "multiple_reports",
            LabelConfidence::ExternallyConfirmed => "externally_confirmed",
            LabelConfidence::Honeypot => "honeypot",
        }
    }

    /// Numeric trust weight (0.0-1.0).
    pub fn trust_weight(&self) -> f32 {
        match self {
            LabelConfidence::UserFeedback => 0.3,
            LabelConfidence::UserReport => 0.5,
            LabelConfidence::MultipleReports => 0.7,
            LabelConfidence::ExternallyConfirmed => 0.9,
            LabelConfidence::Honeypot => 1.0,
        }
    }
}

impl std::fmt::Display for LabelConfidence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Aggregation schema version identifier.
pub const AGGREGATION_SCHEMA_VERSION: &str = "1.0.0";

/// A privacy-bounded decision trace for a single detection event.
///
/// This is the ONLY data structure that may be transmitted for aggregation.
/// It contains no raw message content, no sender info, no exact timestamps.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionTrace {
    /// Local-only correlation ID — links feedback to this trace.
    /// **Never transmitted.** Stripped before aggregation.
    #[serde(skip_serializing)]
    pub local_id: Option<String>,
    /// Model version used for detection.
    pub model_version: String,
    /// Detection channel (coarse: "sms", "email", "browser", "messaging", "call").
    pub channel: String,
    /// Coarse language bucket ("en", "vi", "th", "id", "ms", "tl", "km", "zh", "other").
    pub language: String,
    /// Predicted outcome: "scam", "suspicious", "benign".
    pub predicted_outcome: String,
    /// Predicted scam type from taxonomy (if scam or suspicious).
    pub predicted_type: Option<String>,
    /// Risk bucket 1-5 (not an exact probability).
    pub risk_bucket: u8,
    /// Top indicators (max 3) as (indicator_id, strength) pairs.
    pub indicators: Vec<(String, String)>,
    /// User feedback (filled later, initially None).
    pub feedback: Option<FeedbackKind>,
    /// Corrected scam type if user provided WrongType feedback with a correction.
    /// Filled later, initially None.
    pub corrected_type: Option<String>,
    /// Prompt version (for UX bias measurement).
    pub prompt_version: String,
    /// Label confidence / trust level.
    pub label_confidence: LabelConfidence,
    /// Indicator ontology schema version (for forward compatibility).
    pub indicator_schema_version: String,
    /// Scam taxonomy schema version (for forward compatibility).
    pub taxonomy_schema_version: String,
    /// Aggregation schema version (for forward compatibility).
    pub aggregation_schema_version: String,
}

impl DecisionTrace {
    /// Build a decision trace from a detection result.
    pub fn from_detection(
        result: &DetectionResult,
        indicators: &[IndicatorHit],
    ) -> Self {
        let indicator_pairs: Vec<(String, String)> = indicators
            .iter()
            .map(|h| (h.id.as_str().to_string(), h.strength.as_str().to_string()))
            .collect();

        Self {
            local_id: Some(result.id.clone()),
            model_version: result.model_version.clone(),
            channel: result.channel.as_str().to_string(),
            language: result.language_bucket.clone(),
            predicted_outcome: result.predicted_outcome.as_str().to_string(),
            predicted_type: result.scam_type.map(|t| t.as_str().to_string()),
            risk_bucket: result.risk_bucket,
            indicators: indicator_pairs,
            feedback: None,
            corrected_type: None,
            prompt_version: result.prompt_version.clone(),
            label_confidence: LabelConfidence::UserFeedback,
            indicator_schema_version: ONTOLOGY_VERSION.to_string(),
            taxonomy_schema_version: SCAM_TAXONOMY_VERSION.to_string(),
            aggregation_schema_version: AGGREGATION_SCHEMA_VERSION.to_string(),
        }
    }

    /// Serialize to JSON string for transmission (local_id stripped).
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Strip local-only fields before aggregation/transmission.
    pub fn strip_local(&mut self) {
        self.local_id = None;
    }

    /// Deserialize from JSON string.
    pub fn from_json(s: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(s)
    }
}

impl std::fmt::Display for DecisionTrace {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "DecisionTrace {{")?;
        writeln!(f, "  model_version: {}", self.model_version)?;
        writeln!(f, "  channel: {}", self.channel)?;
        writeln!(f, "  language: {}", self.language)?;
        writeln!(f, "  predicted_outcome: {}", self.predicted_outcome)?;
        if let Some(ref t) = self.predicted_type {
            writeln!(f, "  predicted_type: {}", t)?;
        }
        writeln!(f, "  risk_bucket: {}", self.risk_bucket)?;
        writeln!(f, "  indicators: [")?;
        for (id, strength) in &self.indicators {
            writeln!(f, "    ({}, {})", id, strength)?;
        }
        writeln!(f, "  ]")?;
        if let Some(ref fb) = self.feedback {
            writeln!(f, "  feedback: {}", fb)?;
        }
        writeln!(f, "  label_confidence: {}", self.label_confidence)?;
        writeln!(f, "  indicator_schema_version: {}", self.indicator_schema_version)?;
        writeln!(f, "  taxonomy_schema_version: {}", self.taxonomy_schema_version)?;
        write!(f, "}}")
    }
}
