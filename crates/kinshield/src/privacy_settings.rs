//! User privacy settings and local event retention.
//!
//! Provides per-contribution-type opt-out controls and automatic
//! expiry of local data based on configurable retention periods.

use serde::{Deserialize, Serialize};

/// Default maximum age for local decision traces (in days).
const DEFAULT_MAX_AGE_DAYS: usize = 14;
/// Default maximum age for pending aggregate data (in days).
const DEFAULT_MAX_PENDING_AGGREGATE_DAYS: usize = 7;

/// User-configurable privacy settings.
///
/// Controls which types of data the device is allowed to contribute
/// to the aggregation system. All settings default to `true` (opt-in).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivacySettings {
    /// Whether to contribute aggregate counter tables.
    pub contribute_aggregates: bool,
    /// Whether to contribute structured feedback.
    pub contribute_feedback: bool,
    /// Whether to contribute missed-scam reports.
    pub contribute_missed_reports: bool,
    /// Event retention configuration.
    pub retention: EventRetention,
}

impl Default for PrivacySettings {
    fn default() -> Self {
        Self {
            contribute_aggregates: true,
            contribute_feedback: true,
            contribute_missed_reports: true,
            retention: EventRetention::default(),
        }
    }
}

impl PrivacySettings {
    /// Create with all contributions enabled (default).
    pub fn new() -> Self {
        Self::default()
    }

    /// Create with all contributions disabled (full opt-out).
    pub fn opt_out_all() -> Self {
        Self {
            contribute_aggregates: false,
            contribute_feedback: false,
            contribute_missed_reports: false,
            retention: EventRetention::default(),
        }
    }

    /// Check if any contributions are allowed.
    pub fn any_enabled(&self) -> bool {
        self.contribute_aggregates || self.contribute_feedback || self.contribute_missed_reports
    }
}

/// Configuration for local event retention and expiry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventRetention {
    /// Maximum age in days for local decision traces.
    pub max_age_days: usize,
    /// Maximum age in days for pending aggregate data.
    pub max_pending_aggregate_days: usize,
}

impl Default for EventRetention {
    fn default() -> Self {
        Self {
            max_age_days: DEFAULT_MAX_AGE_DAYS,
            max_pending_aggregate_days: DEFAULT_MAX_PENDING_AGGREGATE_DAYS,
        }
    }
}

impl EventRetention {
    /// Create with default retention periods.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create with custom retention periods.
    pub fn with_max_age(days: usize, pending_days: usize) -> Self {
        Self {
            max_age_days: days,
            max_pending_aggregate_days: pending_days,
        }
    }

    /// Check if a trace with the given age (in days) is expired.
    pub fn is_expired(&self, age_days: usize) -> bool {
        age_days > self.max_age_days
    }

    /// Check if pending aggregate data with the given age (in days) is expired.
    pub fn is_pending_expired(&self, age_days: usize) -> bool {
        age_days > self.max_pending_aggregate_days
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_settings() {
        let settings = PrivacySettings::new();
        assert!(settings.contribute_aggregates);
        assert!(settings.contribute_feedback);
        assert!(settings.contribute_missed_reports);
        assert!(settings.any_enabled());
    }

    #[test]
    fn test_opt_out() {
        let settings = PrivacySettings::opt_out_all();
        assert!(!settings.contribute_aggregates);
        assert!(!settings.contribute_feedback);
        assert!(!settings.contribute_missed_reports);
        assert!(!settings.any_enabled());
    }

    #[test]
    fn test_retention_expiry() {
        let retention = EventRetention::new();
        assert!(!retention.is_expired(10));
        assert!(retention.is_expired(20));
        assert!(!retention.is_pending_expired(5));
        assert!(retention.is_pending_expired(10));
    }

    #[test]
    fn test_custom_retention() {
        let retention = EventRetention::with_max_age(30, 14);
        assert!(!retention.is_expired(25));
        assert!(retention.is_expired(35));
    }
}
