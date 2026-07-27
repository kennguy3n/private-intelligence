//! Report missed scam mechanism.
//!
//! When a user identifies an undetected scam, the engine re-extracts
//! indicators locally and stores the result as a false-negative example
//! for calibration. This is critical for improving recall, since
//! thumbs-feedback only measures precision.

use serde::{Deserialize, Serialize};
use crate::channel::Channel;
use crate::ontology::IndicatorHit;
use crate::taxonomy::ScamType;

/// A report of a scam that was not detected by the engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MissedScamReport {
    /// Channel through which the scam was received.
    pub channel: Channel,
    /// Coarse language bucket.
    pub language: String,
    /// Indicators re-extracted locally from the message.
    pub indicators: Vec<IndicatorHit>,
    /// The actual scam type (user-selected, if known).
    pub actual_scam_type: Option<ScamType>,
    /// Coarse timestamp bucket (e.g., "2024-W29") — no exact timestamp.
    pub timestamp_bucket: String,
}

impl MissedScamReport {
    /// Serialize to JSON.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
}

impl std::fmt::Display for MissedScamReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "MissedScamReport {{")?;
        writeln!(f, "  channel: {}", self.channel)?;
        writeln!(f, "  language: {}", self.language)?;
        writeln!(f, "  indicators: [")?;
        for ind in &self.indicators {
            writeln!(f, "    {} ({})", ind.id, ind.strength)?;
        }
        writeln!(f, "  ]")?;
        if let Some(ref t) = self.actual_scam_type {
            writeln!(f, "  actual_scam_type: {}", t)?;
        }
        writeln!(f, "  timestamp_bucket: {}", self.timestamp_bucket)?;
        write!(f, "}}")
    }
}
