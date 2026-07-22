//! Weekly contribution limits and per-cell caps.
//!
//! Prevents any single device from dominating the aggregated signal.
//! Limits are enforced on a per-week (ISO week) basis and cover:
//! - Total feedback events per week
//! - Total missed-scam reports per week
//! - Per-indicator cell contributions per week
//! - Per-scam-family cell contributions per week
//! - Total contributions per week

use std::collections::HashMap;
use crate::ontology::IndicatorId;
use crate::taxonomy::ScamType;

/// Default limits (per device, per week).
const DEFAULT_MAX_FEEDBACK_PER_WEEK: usize = 20;
const DEFAULT_MAX_MISSED_REPORTS_PER_WEEK: usize = 5;
const DEFAULT_MAX_PER_INDICATOR_CELL_PER_WEEK: usize = 5;
const DEFAULT_MAX_PER_FAMILY_CELL_PER_WEEK: usize = 5;
const DEFAULT_MAX_TOTAL_PER_WEEK: usize = 50;

/// Contribution limits for a single device.
#[derive(Debug, Clone)]
pub struct ContributionLimits {
    /// Maximum feedback events per week.
    pub max_feedback_per_week: usize,
    /// Maximum missed-scam reports per week.
    pub max_missed_reports_per_week: usize,
    /// Maximum contributions per (indicator, week) cell.
    pub max_per_indicator_cell: usize,
    /// Maximum contributions per (scam_family, week) cell.
    pub max_per_family_cell: usize,
    /// Maximum total contributions per week (all types combined).
    pub max_total_per_week: usize,
    /// Current ISO week bucket (e.g., "2024-W29").
    current_week: String,
    /// Feedback events this week.
    feedback_this_week: usize,
    /// Missed-scam reports this week.
    missed_reports_this_week: usize,
    /// Per-indicator cell counts: (indicator_id, week) → count.
    indicator_cells: HashMap<String, usize>,
    /// Per-family cell counts: (family, week) → count.
    family_cells: HashMap<String, usize>,
    /// Total contributions this week.
    total_this_week: usize,
}

impl ContributionLimits {
    /// Create with default limits.
    pub fn new() -> Self {
        Self {
            max_feedback_per_week: DEFAULT_MAX_FEEDBACK_PER_WEEK,
            max_missed_reports_per_week: DEFAULT_MAX_MISSED_REPORTS_PER_WEEK,
            max_per_indicator_cell: DEFAULT_MAX_PER_INDICATOR_CELL_PER_WEEK,
            max_per_family_cell: DEFAULT_MAX_PER_FAMILY_CELL_PER_WEEK,
            max_total_per_week: DEFAULT_MAX_TOTAL_PER_WEEK,
            current_week: current_week_bucket(),
            feedback_this_week: 0,
            missed_reports_this_week: 0,
            indicator_cells: HashMap::new(),
            family_cells: HashMap::new(),
            total_this_week: 0,
        }
    }

    /// Create with custom limits.
    pub fn with_limits(
        feedback: usize,
        missed: usize,
        ind_cell: usize,
        fam_cell: usize,
        total: usize,
    ) -> Self {
        Self {
            max_feedback_per_week: feedback,
            max_missed_reports_per_week: missed,
            max_per_indicator_cell: ind_cell,
            max_per_family_cell: fam_cell,
            max_total_per_week: total,
            current_week: current_week_bucket(),
            feedback_this_week: 0,
            missed_reports_this_week: 0,
            indicator_cells: HashMap::new(),
            family_cells: HashMap::new(),
            total_this_week: 0,
        }
    }

    /// Reset weekly counters if the ISO week has changed.
    fn maybe_reset_week(&mut self) {
        let week = current_week_bucket();
        if week != self.current_week {
            self.current_week = week;
            self.feedback_this_week = 0;
            self.missed_reports_this_week = 0;
            self.indicator_cells.clear();
            self.family_cells.clear();
            self.total_this_week = 0;
        }
    }

    /// Check if a feedback event can be submitted.
    ///
    /// Returns `Ok(())` if allowed, or an error describing which limit was hit.
    /// Resets weekly counters if the ISO week has changed.
    pub fn check_feedback(
        &mut self,
        indicators: &[IndicatorId],
        scam_type: Option<ScamType>,
    ) -> Result<(), ContributionLimitError> {
        self.maybe_reset_week();
        if self.feedback_this_week >= self.max_feedback_per_week {
            return Err(ContributionLimitError::WeeklyFeedbackCap {
                current: self.feedback_this_week,
                max: self.max_feedback_per_week,
            });
        }
        if self.total_this_week >= self.max_total_per_week {
            return Err(ContributionLimitError::WeeklyTotalCap {
                current: self.total_this_week,
                max: self.max_total_per_week,
            });
        }
        for ind in indicators {
            let key = format!("{}:{}", ind.as_str(), self.current_week);
            let count = self.indicator_cells.get(&key).copied().unwrap_or(0);
            if count >= self.max_per_indicator_cell {
                return Err(ContributionLimitError::IndicatorCellCap {
                    indicator: ind.as_str().to_string(),
                    current: count,
                    max: self.max_per_indicator_cell,
                });
            }
        }
        if let Some(st) = scam_type {
            let key = format!("{}:{}", st.as_str(), self.current_week);
            let count = self.family_cells.get(&key).copied().unwrap_or(0);
            if count >= self.max_per_family_cell {
                return Err(ContributionLimitError::FamilyCellCap {
                    family: st.as_str().to_string(),
                    current: count,
                    max: self.max_per_family_cell,
                });
            }
        }
        Ok(())
    }

    /// Record a feedback event. Call after `check_feedback` returns Ok.
    pub fn record_feedback(
        &mut self,
        indicators: &[IndicatorId],
        scam_type: Option<ScamType>,
    ) {
        self.maybe_reset_week();
        self.feedback_this_week += 1;
        self.total_this_week += 1;
        for ind in indicators {
            let key = format!("{}:{}", ind.as_str(), self.current_week);
            *self.indicator_cells.entry(key).or_insert(0) += 1;
        }
        if let Some(st) = scam_type {
            let key = format!("{}:{}", st.as_str(), self.current_week);
            *self.family_cells.entry(key).or_insert(0) += 1;
        }
    }

    /// Check if a missed-scam report can be submitted.
    /// Resets weekly counters if the ISO week has changed.
    pub fn check_missed_report(&mut self) -> Result<(), ContributionLimitError> {
        self.maybe_reset_week();
        if self.missed_reports_this_week >= self.max_missed_reports_per_week {
            return Err(ContributionLimitError::MissedReportCap {
                current: self.missed_reports_this_week,
                max: self.max_missed_reports_per_week,
            });
        }
        if self.total_this_week >= self.max_total_per_week {
            return Err(ContributionLimitError::WeeklyTotalCap {
                current: self.total_this_week,
                max: self.max_total_per_week,
            });
        }
        Ok(())
    }

    /// Record a missed-scam report. Call after `check_missed_report` returns Ok.
    pub fn record_missed_report(&mut self) {
        self.maybe_reset_week();
        self.missed_reports_this_week += 1;
        self.total_this_week += 1;
    }

    /// Get current week's usage stats.
    pub fn usage(&self) -> ContributionUsage {
        ContributionUsage {
            week: self.current_week.clone(),
            feedback_this_week: self.feedback_this_week,
            missed_reports_this_week: self.missed_reports_this_week,
            total_this_week: self.total_this_week,
            max_feedback: self.max_feedback_per_week,
            max_missed: self.max_missed_reports_per_week,
            max_total: self.max_total_per_week,
        }
    }
}

impl Default for ContributionLimits {
    fn default() -> Self {
        Self::new()
    }
}

/// Usage stats for the current week.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ContributionUsage {
    pub week: String,
    pub feedback_this_week: usize,
    pub missed_reports_this_week: usize,
    pub total_this_week: usize,
    pub max_feedback: usize,
    pub max_missed: usize,
    pub max_total: usize,
}

/// Error when a contribution limit is exceeded.
#[derive(Debug, Clone)]
pub enum ContributionLimitError {
    /// Weekly feedback cap exceeded.
    WeeklyFeedbackCap { current: usize, max: usize },
    /// Weekly missed-scam report cap exceeded.
    MissedReportCap { current: usize, max: usize },
    /// Per-indicator cell cap exceeded.
    IndicatorCellCap { indicator: String, current: usize, max: usize },
    /// Per-family cell cap exceeded.
    FamilyCellCap { family: String, current: usize, max: usize },
    /// Weekly total contribution cap exceeded.
    WeeklyTotalCap { current: usize, max: usize },
}

impl std::fmt::Display for ContributionLimitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WeeklyFeedbackCap { current, max } => {
                write!(f, "weekly feedback cap exceeded: {}/{}", current, max)
            }
            Self::MissedReportCap { current, max } => {
                write!(f, "weekly missed-report cap exceeded: {}/{}", current, max)
            }
            Self::IndicatorCellCap { indicator, current, max } => {
                write!(f, "indicator cell cap exceeded for {}: {}/{}", indicator, current, max)
            }
            Self::FamilyCellCap { family, current, max } => {
                write!(f, "family cell cap exceeded for {}: {}/{}", family, current, max)
            }
            Self::WeeklyTotalCap { current, max } => {
                write!(f, "weekly total contribution cap exceeded: {}/{}", current, max)
            }
        }
    }
}

impl std::error::Error for ContributionLimitError {}

/// Get the current ISO week bucket (e.g., "2024-W29").
fn current_week_bucket() -> String {
    chrono::Utc::now().format("%Y-W%V").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_feedback_limit() {
        let mut limits = ContributionLimits::with_limits(2, 5, 5, 5, 50);
        let indicators = vec![IndicatorId::Urgency];

        assert!(limits.check_feedback(&indicators, None).is_ok());
        limits.record_feedback(&indicators, None);

        assert!(limits.check_feedback(&indicators, None).is_ok());
        limits.record_feedback(&indicators, None);

        let result = limits.check_feedback(&indicators, None);
        assert!(result.is_err());
        match result.unwrap_err() {
            ContributionLimitError::WeeklyFeedbackCap { current, max } => {
                assert_eq!(current, 2);
                assert_eq!(max, 2);
            }
            _ => panic!("expected WeeklyFeedbackCap"),
        }
    }

    #[test]
    fn test_indicator_cell_limit() {
        let mut limits = ContributionLimits::with_limits(50, 5, 2, 5, 100);
        let indicators = vec![IndicatorId::Urgency];

        limits.record_feedback(&indicators, None);
        limits.record_feedback(&indicators, None);

        let result = limits.check_feedback(&indicators, None);
        assert!(result.is_err());
        match result.unwrap_err() {
            ContributionLimitError::IndicatorCellCap { indicator, .. } => {
                assert_eq!(indicator, "urgency");
            }
            _ => panic!("expected IndicatorCellCap"),
        }
    }

    #[test]
    fn test_missed_report_limit() {
        let mut limits = ContributionLimits::with_limits(50, 1, 5, 5, 100);

        assert!(limits.check_missed_report().is_ok());
        limits.record_missed_report();

        assert!(limits.check_missed_report().is_err());
    }

    #[test]
    fn test_total_limit() {
        let mut limits = ContributionLimits::with_limits(50, 5, 5, 5, 2);
        let indicators = vec![IndicatorId::Urgency];

        limits.record_feedback(&indicators, None);
        limits.record_feedback(&indicators, None);

        let result = limits.check_feedback(&indicators, None);
        assert!(result.is_err());
        match result.unwrap_err() {
            ContributionLimitError::WeeklyTotalCap { current, max } => {
                assert_eq!(current, 2);
                assert_eq!(max, 2);
            }
            _ => panic!("expected WeeklyTotalCap"),
        }
    }

    #[test]
    fn test_usage() {
        let mut limits = ContributionLimits::new();
        let indicators = vec![IndicatorId::Urgency];
        limits.record_feedback(&indicators, Some(ScamType::BankImpersonation));
        limits.record_missed_report();

        let usage = limits.usage();
        assert_eq!(usage.feedback_this_week, 1);
        assert_eq!(usage.missed_reports_this_week, 1);
        assert_eq!(usage.total_this_week, 2);
    }
}
