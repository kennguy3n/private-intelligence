//! On-device calibration layer.
//!
//! Adjusts risk score thresholds based on local feedback history.
//! Only adjusts the small calibration layer — never the core semantic
//! detector. The core model is not retrained from device feedback.

use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use crate::channel::Channel;
use crate::ontology::{IndicatorId, IndicatorStrength};
use crate::feedback::{FeedbackKind, FeedbackRecord, FeedbackSource};
use crate::report_missed::MissedScamReport;

/// Calibration layer for risk score adjustment.
pub struct CalibrationLayer {
    /// Calibration version (matches model version).
    version: String,
    /// Per (channel, language, risk_bucket) → observed confirmation rate.
    calibration_table: HashMap<(String, String, u8), CalibrationEntry>,
    /// Per indicator → false-positive count and total count.
    indicator_stats: HashMap<IndicatorId, IndicatorStats>,
    /// Per indicator pair → false-positive count and total count.
    indicator_pair_stats: HashMap<(IndicatorId, IndicatorId), IndicatorStats>,
    /// Total feedback records processed.
    total_feedback: usize,
    /// Total false negatives reported.
    total_false_negatives: usize,
}

/// Calibration entry for a (channel, language, risk_bucket) combination.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CalibrationEntry {
    total: f32,
    confirmed: f32,
    false_positive: f32,
}

/// Per-indicator statistics.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct IndicatorStats {
    total: f32,
    confirmed: f32,
    false_positive: f32,
}

/// Public calibration statistics for inspection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CalibrationStats {
    pub version: String,
    pub total_feedback: usize,
    pub total_false_negatives: usize,
    pub indicator_fp_rates: Vec<(String, f32)>,
    pub risk_bucket_confirmation: Vec<(u8, f32)>,
}

impl CalibrationLayer {
    /// Create a new calibration layer.
    pub fn new(version: &str) -> Self {
        Self {
            version: version.to_string(),
            calibration_table: HashMap::new(),
            indicator_stats: HashMap::new(),
            indicator_pair_stats: HashMap::new(),
            total_feedback: 0,
            total_false_negatives: 0,
        }
    }

    /// Record a feedback event and update calibration tables.
    pub fn record_feedback(&mut self, _record: &FeedbackRecord) {
        self.total_feedback += 1;

        // Update calibration table (we don't have channel/language here
        // from the record alone — in practice, the engine would pass these)
        // For now, we track indicator-level stats

        // The feedback record doesn't carry indicators directly.
        // The engine updates calibration_table separately via update_calibration.
    }

    /// Update calibration from a detection + feedback pair.
    /// Applies trust-level weighting: Uncertain feedback is excluded,
    /// Correct gets weight 0.3, explicit corrections get weight 0.7.
    /// Expert/external sources bump trust up one tier.
    pub fn update_calibration(
        &mut self,
        channel: Channel,
        language: &str,
        risk_bucket: u8,
        indicators: &[(IndicatorId, IndicatorStrength)],
        feedback: FeedbackKind,
        source: FeedbackSource,
    ) {
        let weight = feedback.effective_trust_weight(source);
        if weight == 0.0 {
            return;
        }

        let ch = channel.as_str().to_string();
        let lang = language.to_string();

        // Update calibration table
        let entry = self
            .calibration_table
            .entry((ch, lang, risk_bucket))
            .or_insert(CalibrationEntry {
                total: 0.0,
                confirmed: 0.0,
                false_positive: 0.0,
            });
        entry.total += weight;
        match feedback {
            FeedbackKind::Correct => entry.confirmed += weight,
            FeedbackKind::NotAScam => entry.false_positive += weight,
            _ => {}
        }

        // Update per-indicator stats
        for (ind_id, _) in indicators {
            let stats = self
                .indicator_stats
                .entry(*ind_id)
                .or_insert_with(IndicatorStats::default);
            stats.total += weight;
            match feedback {
                FeedbackKind::Correct => stats.confirmed += weight,
                FeedbackKind::NotAScam => stats.false_positive += weight,
                _ => {}
            }
        }

        // Update per-indicator-pair stats
        for i in 0..indicators.len() {
            for j in (i + 1)..indicators.len() {
                let pair = (indicators[i].0, indicators[j].0);
                let stats = self
                    .indicator_pair_stats
                    .entry(pair)
                    .or_insert_with(IndicatorStats::default);
                stats.total += weight;
                match feedback {
                    FeedbackKind::Correct => stats.confirmed += weight,
                    FeedbackKind::NotAScam => stats.false_positive += weight,
                    _ => {}
                }
            }
        }
    }

    /// Record a false negative (missed scam) for calibration.
    pub fn record_false_negative(&mut self, _report: &MissedScamReport) {
        self.total_false_negatives += 1;
    }

    /// Calibrate a raw risk bucket using local feedback history.
    ///
    /// Adjusts the bucket based on observed confirmation rates for
    /// the given channel and language. Returns the adjusted bucket (1-5).
    pub fn calibrate(&self, raw_bucket: u8, channel: Channel, language: &str) -> u8 {
        let key = (
            channel.as_str().to_string(),
            language.to_string(),
            raw_bucket,
        );

        if let Some(entry) = self.calibration_table.get(&key) {
            if entry.total < 10.0 {
                // Not enough data to calibrate — return raw bucket
                return raw_bucket;
            }

            let confirmation_rate = entry.confirmed / entry.total;
            let fp_rate = entry.false_positive / entry.total;

            // If this bucket has high false-positive rate, reduce
            if fp_rate > 0.5 {
                return (raw_bucket.saturating_sub(1)).max(1);
            }

            // If this bucket has high confirmation rate, boost
            if confirmation_rate > 0.8 && raw_bucket < 5 {
                return (raw_bucket + 1).min(5);
            }
        }

        raw_bucket
    }

    /// Get indicator weights based on observed false-positive rates.
    ///
    /// Indicators with high false-positive rates get reduced weight.
    pub fn indicator_weights(&self) -> HashMap<IndicatorId, f32> {
        self.indicator_stats
            .iter()
            .map(|(&id, stats)| {
                let weight = if stats.total < 5.0 {
                    1.0 // Not enough data
                } else {
                    let fp_rate = stats.false_positive / stats.total;
                    (1.0 - fp_rate * 0.5).max(0.3)
                };
                (id, weight)
            })
            .collect()
    }

    /// Get calibration statistics for inspection.
    pub fn stats(&self) -> CalibrationStats {
        let indicator_fp_rates: Vec<(String, f32)> = self
            .indicator_stats
            .iter()
            .map(|(&id, stats)| {
                let rate = if stats.total > 0.0 {
                    stats.false_positive / stats.total
                } else {
                    0.0
                };
                (id.as_str().to_string(), rate)
            })
            .collect();

        let risk_bucket_confirmation: Vec<(u8, f32)> = {
            // Aggregate by risk_bucket across all channels/languages
            let mut bucket_stats: HashMap<u8, (f32, f32)> = HashMap::new();
            for ((_, _, bucket), entry) in &self.calibration_table {
                let stats = bucket_stats.entry(*bucket).or_insert((0.0, 0.0));
                stats.0 += entry.total;
                stats.1 += entry.confirmed;
            }
            let mut result: Vec<(u8, f32)> = bucket_stats
                .into_iter()
                .map(|(bucket, (total, confirmed))| {
                    let rate = if total > 0.0 {
                        confirmed / total
                    } else {
                        0.0
                    };
                    (bucket, rate)
                })
                .collect();
            result.sort_by_key(|(b, _)| *b);
            result
        };

        CalibrationStats {
            version: self.version.clone(),
            total_feedback: self.total_feedback,
            total_false_negatives: self.total_false_negatives,
            indicator_fp_rates,
            risk_bucket_confirmation,
        }
    }

    /// Version identifier.
    pub fn version(&self) -> &str {
        &self.version
    }
}
