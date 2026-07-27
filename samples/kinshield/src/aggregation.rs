//! Local aggregation buffer with contribution caps.
//!
//! Collects decision traces locally, applies per-device contribution caps,
//! and produces aggregate histograms (not individual traces) for future
//! secure aggregation.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use crate::decision_trace::DecisionTrace;
use crate::feedback::FeedbackKind;
use crate::counter_tables::CounterTables;

/// Maximum contributions per device per day.
const DEFAULT_MAX_CONTRIBUTIONS_PER_DAY: usize = 50;

/// Minimum batch size before flush is allowed.
const DEFAULT_MIN_BATCH_SIZE: usize = 20;

/// Local aggregation buffer for decision traces.
pub struct AggregationBuffer {
    /// Pending decision traces (not yet flushed).
    traces: Vec<DecisionTrace>,
    /// Maximum contributions per day per device.
    max_contributions_per_day: usize,
    /// Minimum batch size before flush.
    min_batch_size: usize,
    /// Contributions made today.
    contributions_today: usize,
    /// Last reset date (for daily cap reset).
    last_reset_date: chrono::NaiveDate,
    /// Persistent counter tables (immediate conversion from traces).
    counter_tables: CounterTables,
    /// Total times the daily contribution cap was hit (system health).
    caps_hit: usize,
    /// Total aggregation rounds completed (system health).
    aggregation_rounds: usize,
    /// Total suppressed cohorts reported by server (system health).
    suppressed_cohorts: usize,
    /// Total failed aggregation attempts (system health).
    failed_aggregations: usize,
    /// Last successful flush ISO week bucket.
    last_flush_week: Option<String>,
}

impl AggregationBuffer {
    /// Create a new aggregation buffer with default settings.
    pub fn new() -> Self {
        Self {
            traces: Vec::new(),
            max_contributions_per_day: DEFAULT_MAX_CONTRIBUTIONS_PER_DAY,
            min_batch_size: DEFAULT_MIN_BATCH_SIZE,
            contributions_today: 0,
            last_reset_date: chrono::Utc::now().date_naive(),
            counter_tables: CounterTables::new(),
            caps_hit: 0,
            aggregation_rounds: 0,
            suppressed_cohorts: 0,
            failed_aggregations: 0,
            last_flush_week: None,
        }
    }

    /// Create with custom limits.
    pub fn with_limits(max_per_day: usize, min_batch: usize) -> Self {
        Self {
            traces: Vec::new(),
            max_contributions_per_day: max_per_day,
            min_batch_size: min_batch,
            contributions_today: 0,
            last_reset_date: chrono::Utc::now().date_naive(),
            counter_tables: CounterTables::new(),
            caps_hit: 0,
            aggregation_rounds: 0,
            suppressed_cohorts: 0,
            failed_aggregations: 0,
            last_flush_week: None,
        }
    }

    /// Reset daily contribution counter if the date has changed.
    fn maybe_reset_daily(&mut self) {
        let today = chrono::Utc::now().date_naive();
        if today != self.last_reset_date {
            self.contributions_today = 0;
            self.last_reset_date = today;
        }
    }

    /// Add a decision trace to the local buffer.
    ///
    /// Returns `true` if the trace was accepted, `false` if the daily
    /// contribution cap has been reached (anti-manipulation measure).
    pub fn add(&mut self, trace: DecisionTrace) -> bool {
        self.maybe_reset_daily();

        if self.contributions_today >= self.max_contributions_per_day {
            tracing::warn!(
                contributions = self.contributions_today,
                max = self.max_contributions_per_day,
                "daily contribution cap reached, trace dropped"
            );
            self.caps_hit += 1;
            return false;
        }

        // Immediately update counter tables (persistent aggregation)
        self.counter_tables.update_from_trace(&trace, None);

        self.traces.push(trace);
        self.contributions_today += 1;
        true
    }

    /// Update feedback for a trace in the buffer.
    ///
    /// Finds the trace by its local correlation ID and sets the feedback.
    /// Returns true if a matching trace was found and updated.
    pub fn update_feedback(&mut self, detection_id: &str, feedback: FeedbackKind, corrected_type: Option<&str>) -> bool {
        if let Some(trace) = self.traces.iter_mut().find(|t| {
            t.local_id.as_deref() == Some(detection_id) && t.feedback.is_none()
        }) {
            trace.feedback = Some(feedback);
            if let Some(corrected) = corrected_type {
                trace.corrected_type = Some(corrected.to_string());
            }
            // Update counter tables with feedback
            self.counter_tables.update_from_trace(trace, Some(feedback));
            true
        } else {
            tracing::warn!(
                detection_id = detection_id,
                "no matching trace found for feedback update"
            );
            false
        }
    }

    /// Update family confusion matrix with corrected family.
    pub fn update_confusion(&mut self, predicted_family: &str, corrected_family: &str) {
        self.counter_tables.update_confusion(predicted_family, corrected_family);
    }

    /// Get a snapshot of the persistent counter tables.
    pub fn counter_tables(&self) -> &CounterTables {
        &self.counter_tables
    }

    /// Take ownership of counter tables (for transmission) and reset.
    pub fn take_counter_tables(&mut self) -> CounterTables {
        let taken = std::mem::take(&mut self.counter_tables);
        self.counter_tables = CounterTables::new();
        taken
    }

    /// System health: total times the daily cap was hit.
    pub fn caps_hit(&self) -> usize {
        self.caps_hit
    }

    /// System health: total aggregation rounds completed.
    pub fn aggregation_rounds(&self) -> usize {
        self.aggregation_rounds
    }

    /// System health: total suppressed cohorts from server responses.
    pub fn suppressed_cohorts(&self) -> usize {
        self.suppressed_cohorts
    }

    /// System health: total failed aggregation attempts.
    pub fn failed_aggregations(&self) -> usize {
        self.failed_aggregations
    }

    /// System health: last successful flush ISO week bucket.
    pub fn last_flush_week(&self) -> Option<&str> {
        self.last_flush_week.as_deref()
    }

    /// Record the result of a server aggregation submission.
    /// Call this after submitting counter tables to the aggregation server.
    pub fn record_aggregation_result(&mut self, suppressed: usize, failed: bool) {
        self.suppressed_cohorts += suppressed;
        if failed {
            self.failed_aggregations += 1;
        }
    }

    /// Check if buffer is ready to flush (meets minimum batch size).
    pub fn ready_to_flush(&self) -> bool {
        self.traces.len() >= self.min_batch_size
    }

    /// Flush traces and return only the requested aggregate report type.
    ///
    /// Generates only the requested report and clears the trace buffer.
    /// Each query consumes one privacy budget unit. Returns None if the
    /// buffer is empty.
    pub fn flush_query(&mut self, query: AggregateQuery) -> Option<AggregateReport> {
        if self.traces.is_empty() {
            return None;
        }

        // Strip local-only fields before aggregation
        for trace in &mut self.traces {
            trace.strip_local();
        }

        let report = match query {
            AggregateQuery::ConfirmationRateByBucket => {
                Some(self.aggregate_confirmation_rate())
            }
            AggregateQuery::FalsePositiveRateByIndicator => {
                Some(self.aggregate_fp_rate_by_indicator())
            }
            AggregateQuery::ScamTypeConfusionMatrix => {
                Some(self.aggregate_confusion_matrix())
            }
            AggregateQuery::IndicatorPairPerformance => {
                Some(self.aggregate_indicator_pairs())
            }
            AggregateQuery::PerformanceByLangChannel => {
                Some(self.aggregate_lang_channel())
            }
            AggregateQuery::RegressionByModelVersion => {
                Some(self.aggregate_model_version_comparison())
            }
            AggregateQuery::IndicatorStrengthFeedback => {
                Some(self.aggregate_indicator_strength_feedback())
            }
            AggregateQuery::ExplanationQuality => {
                Some(self.aggregate_explanation_quality())
            }
        };

        // Only clear the buffer if we actually produced a report
        if report.is_some() {
            self.traces.clear();
            self.aggregation_rounds += 1;
            self.last_flush_week = Some(current_week_bucket());
        }

        report
    }

    /// Number of pending traces in the buffer.
    pub fn pending_count(&self) -> usize {
        self.traces.len()
    }

    /// Flush traces as aggregate reports (histograms, not individual traces).
    ///
    /// Clears the buffer after producing aggregates.
    pub fn flush_aggregates(&mut self) -> Vec<AggregateReport> {
        if self.traces.is_empty() {
            return Vec::new();
        }

        // Strip local-only fields before aggregation
        for trace in &mut self.traces {
            trace.strip_local();
        }

        let mut reports = Vec::new();

        // 1. Confirmation rate by risk bucket × channel × language
        reports.push(self.aggregate_confirmation_rate());

        // 2. False-positive rate by top indicator
        reports.push(self.aggregate_fp_rate_by_indicator());

        // 3. Scam-type confusion matrix
        reports.push(self.aggregate_confusion_matrix());

        // 4. Indicator pair performance
        reports.push(self.aggregate_indicator_pairs());

        // 5. Performance by language × channel
        reports.push(self.aggregate_lang_channel());

        // 6. Indicator strength × feedback breakdown
        reports.push(self.aggregate_indicator_strength_feedback());

        // 7. Explanation quality
        reports.push(self.aggregate_explanation_quality());

        // 8. Model-version comparison
        reports.push(self.aggregate_model_version_comparison());

        // Clear buffer
        self.traces.clear();
        self.aggregation_rounds += 1;
        self.last_flush_week = Some(current_week_bucket());

        reports
    }

    /// Aggregate: confirmation rate by risk bucket × channel × language.
    fn aggregate_confirmation_rate(&self) -> AggregateReport {
        let mut buckets: HashMap<(String, String, u8), (usize, usize)> = HashMap::new();
        // (channel, language, risk_bucket) → (total, confirmed)

        for trace in &self.traces {
            let key = (
                trace.channel.clone(),
                trace.language.clone(),
                trace.risk_bucket,
            );
            let entry = buckets.entry(key).or_insert((0, 0));
            entry.0 += 1;
            if let Some(FeedbackKind::Correct) = trace.feedback {
                entry.1 += 1;
            }
        }

        let data: Vec<ConfirmationRateEntry> = buckets
            .into_iter()
            .map(|((channel, language, risk_bucket), (total, confirmed))| {
                ConfirmationRateEntry {
                    channel,
                    language,
                    risk_bucket,
                    total,
                    confirmed,
                    confirmation_rate: if total > 0 {
                        confirmed as f32 / total as f32
                    } else {
                        0.0
                    },
                }
            })
            .collect();

        AggregateReport::ConfirmationRateByBucket(data)
    }

    /// Aggregate: false-positive rate by top indicator.
    fn aggregate_fp_rate_by_indicator(&self) -> AggregateReport {
        let mut indicator_stats: HashMap<String, (usize, usize)> = HashMap::new();
        // indicator_id → (total, false_positives)

        for trace in &self.traces {
            for (indicator_id, _) in &trace.indicators {
                let entry = indicator_stats
                    .entry(indicator_id.clone())
                    .or_insert((0, 0));
                entry.0 += 1;
                if let Some(FeedbackKind::NotAScam) = trace.feedback {
                    entry.1 += 1;
                }
            }
        }

        let data: Vec<IndicatorFpRate> = indicator_stats
            .into_iter()
            .map(|(indicator, (total, false_pos))| IndicatorFpRate {
                indicator,
                total,
                false_positives: false_pos,
                false_positive_rate: if total > 0 {
                    false_pos as f32 / total as f32
                } else {
                    0.0
                },
            })
            .collect();

        AggregateReport::FalsePositiveRateByIndicator(data)
    }

    /// Aggregate: scam-type confusion matrix.
    fn aggregate_confusion_matrix(&self) -> AggregateReport {
        // (predicted_type, corrected_type) → count
        let mut matrix: HashMap<(String, Option<String>), usize> = HashMap::new();

        for trace in &self.traces {
            if let Some(ref predicted) = trace.predicted_type {
                let corrected = match trace.feedback {
                    Some(FeedbackKind::Correct) => Some(predicted.clone()),
                    Some(FeedbackKind::WrongType) => trace.corrected_type.clone()
                        .or_else(|| Some("corrected_by_user".to_string())),
                    Some(FeedbackKind::NotAScam) => Some("not_a_scam".to_string()),
                    _ => None,
                };
                let key = (predicted.clone(), corrected);
                *matrix.entry(key).or_insert(0) += 1;
            }
        }

        let data: Vec<ConfusionMatrixEntry> = matrix
            .into_iter()
            .map(|((predicted, corrected), count)| ConfusionMatrixEntry {
                predicted_type: predicted,
                corrected_type: corrected,
                count,
            })
            .collect();

        AggregateReport::ScamTypeConfusionMatrix(data)
    }

    /// Aggregate: indicator pair performance.
    fn aggregate_indicator_pairs(&self) -> AggregateReport {
        let mut pair_stats: HashMap<(String, String), (usize, usize)> = HashMap::new();

        for trace in &self.traces {
            let indicators: Vec<&String> = trace.indicators.iter().map(|(id, _)| id).collect();
            for i in 0..indicators.len() {
                for j in (i + 1)..indicators.len() {
                    let key = (indicators[i].clone(), indicators[j].clone());
                    let entry = pair_stats.entry(key).or_insert((0, 0));
                    entry.0 += 1;
                    if let Some(FeedbackKind::Correct) = trace.feedback {
                        entry.1 += 1;
                    }
                }
            }
        }

        let data: Vec<IndicatorPairPerf> = pair_stats
            .into_iter()
            .map(|((ind_a, ind_b), (total, confirmed))| IndicatorPairPerf {
                indicator_a: ind_a,
                indicator_b: ind_b,
                total,
                confirmed,
                confirmation_rate: if total > 0 {
                    confirmed as f32 / total as f32
                } else {
                    0.0
                },
            })
            .collect();

        AggregateReport::IndicatorPairPerformance(data)
    }

    /// Aggregate: performance by language × channel.
    fn aggregate_lang_channel(&self) -> AggregateReport {
        let mut stats: HashMap<(String, String), (usize, usize, usize)> = HashMap::new();
        // (language, channel) → (total, confirmed, false_positive)

        for trace in &self.traces {
            let key = (trace.language.clone(), trace.channel.clone());
            let entry = stats.entry(key).or_insert((0, 0, 0));
            entry.0 += 1;
            match trace.feedback {
                Some(FeedbackKind::Correct) => entry.1 += 1,
                Some(FeedbackKind::NotAScam) => entry.2 += 1,
                _ => {}
            }
        }

        let data: Vec<LangChannelPerf> = stats
            .into_iter()
            .map(|((language, channel), (total, confirmed, false_pos))| LangChannelPerf {
                language,
                channel,
                total,
                confirmed,
                false_positives: false_pos,
            })
            .collect();

        AggregateReport::PerformanceByLangChannel(data)
    }

    /// Aggregate: indicator strength × feedback breakdown.
    fn aggregate_indicator_strength_feedback(&self) -> AggregateReport {
        let mut stats: HashMap<(String, String, String), usize> = HashMap::new();
        // (indicator, strength, feedback_type) → count

        for trace in &self.traces {
            let fb_str = trace
                .feedback
                .map(|f| f.as_str().to_string())
                .unwrap_or_else(|| "none".to_string());
            for (ind_id, strength) in &trace.indicators {
                let key = (ind_id.clone(), strength.clone(), fb_str.clone());
                *stats.entry(key).or_insert(0) += 1;
            }
        }

        let data: Vec<IndicatorStrengthFb> = stats
            .into_iter()
            .map(|((indicator, strength, feedback_type), count)| IndicatorStrengthFb {
                indicator,
                strength,
                feedback_type,
                count,
            })
            .collect();

        AggregateReport::IndicatorStrengthFeedback(data)
    }

    /// Aggregate: explanation quality (wrong-reasons rate by indicator).
    fn aggregate_explanation_quality(&self) -> AggregateReport {
        let mut stats: HashMap<String, (usize, usize)> = HashMap::new();
        // indicator → (total_feedback, wrong_reasons_count)

        for trace in &self.traces {
            if trace.feedback.is_none() {
                continue;
            }
            for (ind_id, _) in &trace.indicators {
                let entry = stats.entry(ind_id.clone()).or_insert((0, 0));
                entry.0 += 1;
                if let Some(FeedbackKind::WrongReasons) = trace.feedback {
                    entry.1 += 1;
                }
            }
        }

        let data: Vec<ExplanationQualityEntry> = stats
            .into_iter()
            .map(|(indicator, (total_feedback, wrong_reasons))| ExplanationQualityEntry {
                indicator,
                total_feedback,
                wrong_reasons,
                wrong_reasons_rate: if total_feedback > 0 {
                    wrong_reasons as f32 / total_feedback as f32
                } else {
                    0.0
                },
            })
            .collect();

        AggregateReport::ExplanationQuality(data)
    }

    /// Aggregate: model-version comparison.
    fn aggregate_model_version_comparison(&self) -> AggregateReport {
        let mut stats: HashMap<(String, String, String), usize> = HashMap::new();
        // (model_version, channel, feedback_type) → count

        for trace in &self.traces {
            let fb_str = trace
                .feedback
                .map(|f| f.as_str().to_string())
                .unwrap_or_else(|| "none".to_string());
            let key = (trace.model_version.clone(), trace.channel.clone(), fb_str);
            *stats.entry(key).or_insert(0) += 1;
        }

        let data: Vec<ModelVersionEntry> = stats
            .into_iter()
            .map(|((model_version, channel, feedback_type), count)| ModelVersionEntry {
                model_version,
                channel,
                feedback_type,
                count,
            })
            .collect();

        AggregateReport::ModelVersionComparison(data)
    }
}

impl Default for AggregationBuffer {
    fn default() -> Self {
        Self::new()
    }
}

/// Aggregate report types (histograms, never individual traces).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AggregateReport {
    /// P(user confirms scam | risk_bucket, channel, language, model_version)
    ConfirmationRateByBucket(Vec<ConfirmationRateEntry>),
    /// False-positive rate by top indicator.
    FalsePositiveRateByIndicator(Vec<IndicatorFpRate>),
    /// Scam-type confusion matrix.
    ScamTypeConfusionMatrix(Vec<ConfusionMatrixEntry>),
    /// Indicator pair performance.
    IndicatorPairPerformance(Vec<IndicatorPairPerf>),
    /// Performance by coarse language × channel.
    PerformanceByLangChannel(Vec<LangChannelPerf>),
    /// Indicator strength × feedback breakdown.
    IndicatorStrengthFeedback(Vec<IndicatorStrengthFb>),
    /// Explanation quality (wrong-reasons rate by indicator).
    ExplanationQuality(Vec<ExplanationQualityEntry>),
    /// Model-version comparison.
    ModelVersionComparison(Vec<ModelVersionEntry>),
}

/// Predefined aggregate queries (controlled set, not every possible combination).
#[derive(Debug, Clone, Copy)]
pub enum AggregateQuery {
    /// Confirmation rate by risk bucket.
    ConfirmationRateByBucket,
    /// False-positive rate by top indicator.
    FalsePositiveRateByIndicator,
    /// Scam-type confusion matrix.
    ScamTypeConfusionMatrix,
    /// Indicator pair performance.
    IndicatorPairPerformance,
    /// Performance by coarse language and channel.
    PerformanceByLangChannel,
    /// Regression by model version.
    RegressionByModelVersion,
    /// Indicator strength × feedback breakdown.
    IndicatorStrengthFeedback,
    /// Explanation quality (wrong-reasons rate by indicator).
    ExplanationQuality,
}

/// Confirmation rate entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfirmationRateEntry {
    pub channel: String,
    pub language: String,
    pub risk_bucket: u8,
    pub total: usize,
    pub confirmed: usize,
    pub confirmation_rate: f32,
}

/// False-positive rate by indicator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndicatorFpRate {
    pub indicator: String,
    pub total: usize,
    pub false_positives: usize,
    pub false_positive_rate: f32,
}

/// Confusion matrix entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfusionMatrixEntry {
    pub predicted_type: String,
    /// User-corrected scam type (if WrongType feedback was given).
    pub corrected_type: Option<String>,
    pub count: usize,
}

/// Indicator pair performance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndicatorPairPerf {
    pub indicator_a: String,
    pub indicator_b: String,
    pub total: usize,
    pub confirmed: usize,
    pub confirmation_rate: f32,
}

/// Performance by language × channel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LangChannelPerf {
    pub language: String,
    pub channel: String,
    pub total: usize,
    pub confirmed: usize,
    pub false_positives: usize,
}

/// Indicator strength × feedback breakdown.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndicatorStrengthFb {
    pub indicator: String,
    pub strength: String,
    pub feedback_type: String,
    pub count: usize,
}

/// Explanation quality entry (wrong-reasons rate by indicator).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExplanationQualityEntry {
    pub indicator: String,
    pub total_feedback: usize,
    pub wrong_reasons: usize,
    pub wrong_reasons_rate: f32,
}

/// Model-version comparison entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelVersionEntry {
    pub model_version: String,
    pub channel: String,
    pub feedback_type: String,
    pub count: usize,
}

/// Get the current ISO week bucket (e.g., "2024-W29").
fn current_week_bucket() -> String {
    chrono::Utc::now().format("%Y-W%V").to_string()
}
