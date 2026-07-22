//! Structured feedback system with separated learning targets.
//!
//! A generic thumbs-up or thumbs-down is ambiguous. This module defines
//! five feedback kinds that separate three learning targets:
//!
//! 1. **Detection correctness** — Was it a scam at all? (Correct vs. NotAScam)
//! 2. **Classification correctness** — Was the scam type right? (WrongType)
//! 3. **Explanation correctness** — Were the indicators right? (WrongReasons)

use serde::{Deserialize, Serialize};
use crate::taxonomy::ScamType;

/// Structured feedback kind from the user.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FeedbackKind {
    /// Thumb up — detection was correct.
    Correct,
    /// Thumb down → "Not a scam" — false positive.
    NotAScam,
    /// Thumb down → "Scam, but wrong type" — classification error.
    WrongType,
    /// Thumb down → "Scam, but reasons were wrong" — explanation error.
    WrongReasons,
    /// Thumb down → "Not sure" — ambiguous feedback.
    Uncertain,
}

impl FeedbackKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            FeedbackKind::Correct => "correct",
            FeedbackKind::NotAScam => "false_positive",
            FeedbackKind::WrongType => "wrong_type",
            FeedbackKind::WrongReasons => "wrong_reasons",
            FeedbackKind::Uncertain => "uncertain",
        }
    }

    /// Whether this feedback indicates a false positive (not a scam).
    pub fn is_false_positive(&self) -> bool {
        matches!(self, FeedbackKind::NotAScam)
    }

    /// Whether this feedback confirms the detection was correct.
    pub fn is_correct(&self) -> bool {
        matches!(self, FeedbackKind::Correct)
    }

    /// Whether this feedback indicates a classification error.
    pub fn is_wrong_type(&self) -> bool {
        matches!(self, FeedbackKind::WrongType)
    }

    /// Whether this feedback indicates an explanation error.
    pub fn is_wrong_reasons(&self) -> bool {
        matches!(self, FeedbackKind::WrongReasons)
    }

    /// Human-readable label for UI.
    pub fn label(&self) -> &'static str {
        match self {
            FeedbackKind::Correct => "Correct detection",
            FeedbackKind::NotAScam => "Not a scam",
            FeedbackKind::WrongType => "Scam, but wrong type",
            FeedbackKind::WrongReasons => "Scam, but reasons were wrong",
            FeedbackKind::Uncertain => "Not sure",
        }
    }

    /// Map to a label trust level for weighting in calibration.
    pub fn trust_level(&self) -> LabelTrust {
        match self {
            FeedbackKind::Correct => LabelTrust::Low,
            FeedbackKind::NotAScam => LabelTrust::Medium,
            FeedbackKind::WrongType => LabelTrust::Medium,
            FeedbackKind::WrongReasons => LabelTrust::Medium,
            FeedbackKind::Uncertain => LabelTrust::Exclude,
        }
    }

    /// Numeric trust weight (0.0–1.0) for calibration updates.
    pub fn trust_weight(&self) -> f32 {
        self.trust_level().weight()
    }

    /// Effective trust weight combining feedback kind and source.
    ///
    /// Expert reviews and external threat intelligence sources bump
    /// the trust level up one tier (e.g., Low → Medium, Medium → High).
    pub fn effective_trust_weight(&self, source: FeedbackSource) -> f32 {
        let base = self.trust_level();
        if base == LabelTrust::Exclude {
            return 0.0;
        }
        let adjusted = match source {
            FeedbackSource::User => base,
            FeedbackSource::ExpertReview | FeedbackSource::ExternalThreatIntel => {
                match base {
                    LabelTrust::Low => LabelTrust::Medium,
                    LabelTrust::Medium => LabelTrust::High,
                    other => other,
                }
            }
        };
        adjusted.weight()
    }
}

impl std::fmt::Display for FeedbackKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// A complete feedback record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeedbackRecord {
    /// Detection ID this feedback applies to.
    pub detection_id: String,
    /// The feedback kind.
    pub feedback: FeedbackKind,
    /// If WrongType, the user-selected correct scam type.
    pub corrected_type: Option<ScamType>,
    /// When the feedback was submitted.
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// Source of the feedback (affects trust weighting).
    #[serde(default = "default_feedback_source")]
    pub source: FeedbackSource,
}

fn default_feedback_source() -> FeedbackSource {
    FeedbackSource::User
}

/// Source of a feedback label (affects trust weighting).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FeedbackSource {
    /// End-user thumbs up/down.
    User,
    /// Expert analyst review.
    ExpertReview,
    /// External threat intelligence confirmation.
    ExternalThreatIntel,
}

impl Default for FeedbackSource {
    fn default() -> Self {
        Self::User
    }
}

/// Label trust level for weighting feedback in calibration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LabelTrust {
    /// Exclude from learning entirely.
    Exclude,
    /// Low trust — thumbs-up only.
    Low,
    /// Medium trust — corrected family, missed scam report.
    Medium,
    /// High trust — external confirmation, expert review.
    High,
}

impl LabelTrust {
    /// Numeric weight (0.0–1.0) for calibration updates.
    pub fn weight(&self) -> f32 {
        match self {
            LabelTrust::Exclude => 0.0,
            LabelTrust::Low => 0.3,
            LabelTrust::Medium => 0.7,
            LabelTrust::High => 1.0,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            LabelTrust::Exclude => "exclude",
            LabelTrust::Low => "low",
            LabelTrust::Medium => "medium",
            LabelTrust::High => "high",
        }
    }
}

impl std::fmt::Display for LabelTrust {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl FeedbackRecord {
    /// Which learning target does this feedback contribute to?
    pub fn learning_target(&self) -> LearningTarget {
        match self.feedback {
            FeedbackKind::Correct | FeedbackKind::NotAScam => LearningTarget::Detection,
            FeedbackKind::WrongType => LearningTarget::Classification,
            FeedbackKind::WrongReasons => LearningTarget::Explanation,
            FeedbackKind::Uncertain => LearningTarget::None,
        }
    }
}

/// The three separate learning targets from feedback.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LearningTarget {
    /// Detection correctness: was it a scam at all?
    Detection,
    /// Classification correctness: was the scam type right?
    Classification,
    /// Explanation correctness: were the indicators right?
    Explanation,
    /// No learning value (uncertain feedback).
    None,
}

/// The feedback UI interaction flow.
///
/// Thumb up → Correct
/// Thumb down → open selector:
///   - Not a scam → NotAScam
///   - Scam, but wrong type → WrongType (then ask user to select correct type)
///   - Scam, but reasons were wrong → WrongReasons
///   - Not sure → Uncertain
pub struct FeedbackFlow;

impl FeedbackFlow {
    /// Get the selector options for a thumb-down interaction.
    pub fn thumb_down_options() -> &'static [(&'static str, FeedbackKind)] {
        &[
            ("Not a scam", FeedbackKind::NotAScam),
            ("Scam, but wrong type", FeedbackKind::WrongType),
            ("Scam, but reasons were wrong", FeedbackKind::WrongReasons),
            ("Not sure", FeedbackKind::Uncertain),
        ]
    }

    /// Get the scam type options for a WrongType selection.
    pub fn scam_type_options() -> Vec<(&'static str, ScamType)> {
        ScamType::all()
            .iter()
            .map(|&t| (t.label(), t))
            .collect()
    }
}
