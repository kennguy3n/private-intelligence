//! Persistent counter tables for local aggregation.
//!
//! Instead of holding raw `DecisionTrace` instances in memory until flush,
//! the engine immediately converts each trace + feedback pair into bounded
//! counter increments across 5 table types. The tables can be snapshotted,
//! serialized, and merged with other devices' counters for secure aggregation.
//!
//! **Privacy:** Counter tables contain no raw text, no sender, no exact
//! timestamp, and no persistent device identifier. Only coarse, quantized
//! counts keyed by (channel, language, risk_bucket, indicator_id, family).

use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use crate::decision_trace::DecisionTrace;
use crate::feedback::FeedbackKind;

/// The 5 persistent counter tables.
///
/// Each table is a `HashMap` from a coarse key to a count. The keys are
/// deliberately coarse to prevent re-identification while remaining
/// useful for calibration and model improvement.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CounterTables {
    /// A. Risk calibration: "channel|language|risk_bucket|feedback_kind" → count
    pub risk_calibration: HashMap<String, usize>,
    /// B. Scam-family accuracy: "predicted_family|feedback_kind" → count
    pub family_accuracy: HashMap<String, usize>,
    /// C. Indicator usefulness: "indicator_id|indicator_strength|feedback_kind" → count
    pub indicator_usefulness: HashMap<String, usize>,
    /// D. Family confusion matrix: "predicted_family|corrected_family" → count
    /// Keys from `update_from_trace` use format "predicted|feedback_kind".
    /// Keys from `update_confusion` use format "predicted|corrected_family".
    /// Consumers must distinguish by checking if the second segment is a known
    /// feedback kind string ("correct", "false_positive", etc.) or a scam family name.
    pub family_confusion: HashMap<String, usize>,
    /// E. Model-version comparison: "model_version|channel|feedback_kind" → count
    pub model_version_stats: HashMap<String, usize>,
    /// Metadata: total events recorded.
    pub total_events: usize,
    /// Metadata: last update timestamp (ISO week bucket, not exact).
    pub last_updated_week: String,
}

impl CounterTables {
    /// Create empty counter tables.
    pub fn new() -> Self {
        Self::default()
    }

    /// Update all 5 tables from a decision trace and optional feedback.
    ///
    /// Called immediately after `detect()` (with `feedback=None`) and again
    /// after `submit_feedback()` (with `feedback=Some(...)`).
    pub fn update_from_trace(&mut self, trace: &DecisionTrace, feedback: Option<FeedbackKind>) {
        let fb_str = feedback.map(|f| f.as_str().to_string()).unwrap_or_else(|| "none".to_string());
        let week = current_week_bucket();

        // A. Risk calibration
        let rk_key = format!("{}|{}|{}|{}", trace.channel, trace.language, trace.risk_bucket, fb_str);
        *self.risk_calibration.entry(rk_key).or_insert(0) += 1;

        // B. Family accuracy
        if let Some(ref family) = trace.predicted_type {
            let fa_key = format!("{}|{}", family, fb_str);
            *self.family_accuracy.entry(fa_key).or_insert(0) += 1;
        }

        // C. Indicator usefulness
        for (ind_id, strength) in &trace.indicators {
            let iu_key = format!("{}|{}|{}", ind_id, strength, fb_str);
            *self.indicator_usefulness.entry(iu_key).or_insert(0) += 1;
        }

        // D. Family confusion matrix — track predicted × feedback_kind.
        // The engine separately calls update_confusion() with the corrected
        // family when WrongType feedback is provided.
        if let Some(ref family) = trace.predicted_type {
            let fc_key = format!("fb:{}|{}", family, fb_str);
            *self.family_confusion.entry(fc_key).or_insert(0) += 1;
        }

        // E. Model-version comparison
        let mv_key = format!("{}|{}|{}", trace.model_version, trace.channel, fb_str);
        *self.model_version_stats.entry(mv_key).or_insert(0) += 1;

        self.total_events += if feedback.is_none() { 1 } else { 0 };
        self.last_updated_week = week;
    }

    /// Update family confusion matrix with explicit corrected family.
    ///
    /// Called when the user provides `WrongType` feedback with a corrected scam type.
    pub fn update_confusion(&mut self, predicted_family: &str, corrected_family: &str) {
        let key = format!("cf:{}|{}", predicted_family, corrected_family);
        *self.family_confusion.entry(key).or_insert(0) += 1;
    }

    /// Merge another device's counter tables into ours (for aggregation).
    pub fn merge(&mut self, other: &CounterTables) {
        for (k, v) in &other.risk_calibration {
            *self.risk_calibration.entry(k.clone()).or_insert(0) += v;
        }
        for (k, v) in &other.family_accuracy {
            *self.family_accuracy.entry(k.clone()).or_insert(0) += v;
        }
        for (k, v) in &other.indicator_usefulness {
            *self.indicator_usefulness.entry(k.clone()).or_insert(0) += v;
        }
        for (k, v) in &other.family_confusion {
            *self.family_confusion.entry(k.clone()).or_insert(0) += v;
        }
        for (k, v) in &other.model_version_stats {
            *self.model_version_stats.entry(k.clone()).or_insert(0) += v;
        }
        self.total_events += other.total_events;
    }

    /// Serialize to JSON for transmission.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Deserialize from JSON.
    pub fn from_json(s: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(s)
    }

    /// Clear all tables after successful contribution.
    pub fn clear(&mut self) {
        self.risk_calibration.clear();
        self.family_accuracy.clear();
        self.indicator_usefulness.clear();
        self.family_confusion.clear();
        self.model_version_stats.clear();
        self.total_events = 0;
        self.last_updated_week = String::new();
    }

    /// Total number of counter cells across all tables.
    pub fn total_cells(&self) -> usize {
        self.risk_calibration.len()
            + self.family_accuracy.len()
            + self.indicator_usefulness.len()
            + self.family_confusion.len()
            + self.model_version_stats.len()
    }
}

/// Get the current ISO week bucket (e.g., "2024-W29").
fn current_week_bucket() -> String {
    chrono::Utc::now().format("%Y-W%V").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decision_trace::{DecisionTrace, LabelConfidence, AGGREGATION_SCHEMA_VERSION};
    use crate::ontology::ONTOLOGY_VERSION;
    use crate::taxonomy::SCAM_TAXONOMY_VERSION;
    use crate::feedback::FeedbackKind;

    fn make_trace() -> DecisionTrace {
        DecisionTrace {
            local_id: Some("test-1".to_string()),
            model_version: "1.0.0".to_string(),
            channel: "sms".to_string(),
            language: "vi".to_string(),
            predicted_outcome: "scam".to_string(),
            predicted_type: Some("bank_impersonation".to_string()),
            risk_bucket: 5,
            indicators: vec![
                ("urgency".to_string(), "high".to_string()),
                ("financial_request".to_string(), "high".to_string()),
            ],
            feedback: None,
            corrected_type: None,
            prompt_version: "1.0.0".to_string(),
            label_confidence: LabelConfidence::UserFeedback,
            indicator_schema_version: ONTOLOGY_VERSION.to_string(),
            taxonomy_schema_version: SCAM_TAXONOMY_VERSION.to_string(),
            aggregation_schema_version: AGGREGATION_SCHEMA_VERSION.to_string(),
        }
    }

    #[test]
    fn test_counter_tables_update() {
        let mut tables = CounterTables::new();
        let trace = make_trace();
        tables.update_from_trace(&trace, None);
        tables.update_from_trace(&trace, Some(FeedbackKind::Correct));

        assert_eq!(tables.total_events, 1);
        assert!(tables.risk_calibration.contains_key("sms|vi|5|correct"));
        assert!(tables.family_accuracy.contains_key("bank_impersonation|correct"));
        assert_eq!(tables.indicator_usefulness.len(), 4);
    }

    #[test]
    fn test_counter_tables_merge() {
        let mut t1 = CounterTables::new();
        let mut t2 = CounterTables::new();
        let trace = make_trace();

        t1.update_from_trace(&trace, None);
        t2.update_from_trace(&trace, None);

        t1.merge(&t2);

        assert_eq!(t1.total_events, 2);
        assert_eq!(t1.risk_calibration.len(), 1);
    }

    #[test]
    fn test_counter_tables_clear() {
        let mut tables = CounterTables::new();
        let trace = make_trace();
        tables.update_from_trace(&trace, None);
        assert!(tables.total_events > 0);

        tables.clear();
        assert_eq!(tables.total_events, 0);
        assert_eq!(tables.total_cells(), 0);
    }

    #[test]
    fn test_counter_tables_serialization() {
        let mut tables = CounterTables::new();
        let trace = make_trace();
        tables.update_from_trace(&trace, None);

        let json = tables.to_json().unwrap();
        let parsed = CounterTables::from_json(&json).unwrap();

        assert_eq!(parsed.total_events, tables.total_events);
        assert_eq!(parsed.risk_calibration.len(), tables.risk_calibration.len());
    }

    #[test]
    fn test_counter_tables_no_raw_content() {
        let mut tables = CounterTables::new();
        let trace = make_trace();
        tables.update_from_trace(&trace, Some(FeedbackKind::Correct));

        let json = tables.to_json().unwrap();
        assert!(!json.contains("text"), "Counter tables should not contain raw text");
        assert!(!json.contains("sender"), "Counter tables should not contain sender");
        assert!(!json.contains("local_id"), "Counter tables should not contain local_id");
        assert!(!json.contains("timestamp"), "Counter tables should not contain exact timestamp");
    }
}
