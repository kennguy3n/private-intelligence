//! Privacy budget accountant and system health metrics.
//!
//! Tracks differential privacy budget consumption across aggregation rounds
//! and provides system health metrics for monitoring.

use serde::Serialize;

/// Default privacy budget per week.
const DEFAULT_WEEKLY_EPSILON: f64 = 1.0;
/// Default delta for (ε, δ)-DP.
const DEFAULT_DELTA: f64 = 1e-9;
/// Default max queries per week.
const DEFAULT_MAX_QUERIES: usize = 10;

/// Privacy budget accountant for differential privacy.
///
/// Tracks epsilon consumption across aggregation queries within a week.
/// When the budget is exhausted, no more queries are allowed until reset.
#[derive(Debug, Clone)]
pub struct PrivacyBudget {
    /// Total epsilon available per week.
    total_epsilon: f64,
    /// Epsilon consumed this week.
    consumed_epsilon: f64,
    /// Delta parameter for (ε, δ)-DP.
    delta: f64,
    /// Queries made this week.
    queries_made: usize,
    /// Maximum queries allowed per week.
    max_queries: usize,
    /// Current ISO week bucket.
    current_week: String,
}

impl PrivacyBudget {
    /// Create with default budget.
    pub fn new() -> Self {
        Self {
            total_epsilon: DEFAULT_WEEKLY_EPSILON,
            consumed_epsilon: 0.0,
            delta: DEFAULT_DELTA,
            queries_made: 0,
            max_queries: DEFAULT_MAX_QUERIES,
            current_week: current_week_bucket(),
        }
    }

    /// Create with custom budget.
    pub fn with_epsilon(epsilon: f64, delta: f64, max_queries: usize) -> Self {
        Self {
            total_epsilon: epsilon,
            consumed_epsilon: 0.0,
            delta,
            queries_made: 0,
            max_queries,
            current_week: current_week_bucket(),
        }
    }

    /// Reset weekly budget if the ISO week has changed.
    fn maybe_reset_week(&mut self) {
        let week = current_week_bucket();
        if week != self.current_week {
            self.current_week = week;
            self.consumed_epsilon = 0.0;
            self.queries_made = 0;
        }
    }

    /// Attempt to consume epsilon from the budget.
    ///
    /// Returns `true` if the consumption was allowed, `false` if the
    /// budget is exhausted or the query limit is reached.
    pub fn consume(&mut self, epsilon: f64) -> bool {
        self.maybe_reset_week();
        if epsilon <= 0.0 {
            tracing::warn!(
                requested = epsilon,
                "invalid epsilon (must be positive), consumption rejected"
            );
            return false;
        }
        if self.queries_made >= self.max_queries {
            tracing::warn!(
                queries = self.queries_made,
                max = self.max_queries,
                "privacy budget query limit reached"
            );
            return false;
        }
        if self.consumed_epsilon + epsilon > self.total_epsilon {
            tracing::warn!(
                consumed = self.consumed_epsilon,
                requested = epsilon,
                total = self.total_epsilon,
                "privacy budget exhausted"
            );
            return false;
        }
        self.consumed_epsilon += epsilon;
        self.queries_made += 1;
        true
    }

    /// Remaining epsilon in the budget.
    pub fn remaining(&self) -> f64 {
        (self.total_epsilon - self.consumed_epsilon).max(0.0)
    }

    /// Remaining queries.
    pub fn remaining_queries(&self) -> usize {
        self.max_queries.saturating_sub(self.queries_made)
    }

    /// Epsilon cost per query (evenly divided across max queries).
    pub fn per_query_epsilon(&self) -> f64 {
        if self.max_queries == 0 {
            return self.total_epsilon;
        }
        self.total_epsilon / self.max_queries as f64
    }

    /// Get a snapshot of the budget status.
    pub fn status(&self) -> PrivacyBudgetStatus {
        PrivacyBudgetStatus {
            total_epsilon: self.total_epsilon,
            consumed_epsilon: self.consumed_epsilon,
            remaining_epsilon: self.remaining(),
            delta: self.delta,
            queries_made: self.queries_made,
            max_queries: self.max_queries,
            week: self.current_week.clone(),
        }
    }
}

impl Default for PrivacyBudget {
    fn default() -> Self {
        Self::new()
    }
}

/// Privacy budget status snapshot.
#[derive(Debug, Clone, Serialize)]
pub struct PrivacyBudgetStatus {
    pub total_epsilon: f64,
    pub consumed_epsilon: f64,
    pub remaining_epsilon: f64,
    pub delta: f64,
    pub queries_made: usize,
    pub max_queries: usize,
    pub week: String,
}

/// System health metrics for the scam detection system.
#[derive(Debug, Clone, Default, Serialize)]
pub struct SystemHealth {
    /// Number of times contribution caps were hit.
    pub contribution_caps_hit: usize,
    /// Remaining privacy budget (epsilon).
    pub privacy_budget_remaining: f64,
    /// Number of suppressed cohorts (too few devices).
    pub suppressed_cohorts: usize,
    /// Total aggregation rounds completed.
    pub aggregation_rounds: usize,
    /// Total failed aggregation attempts.
    pub failed_aggregations: usize,
    /// Last successful flush timestamp (ISO week bucket).
    pub last_flush_week: Option<String>,
    /// Total counter cells across all tables.
    pub total_counter_cells: usize,
    /// Total events recorded in counter tables.
    pub total_counter_events: usize,
}

impl SystemHealth {
    /// Create empty system health metrics.
    pub fn new() -> Self {
        Self::default()
    }
}

/// Get the current ISO week bucket (e.g., "2024-W29").
fn current_week_bucket() -> String {
    chrono::Utc::now().format("%Y-W%V").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_privacy_budget_consume() {
        let mut budget = PrivacyBudget::with_epsilon(1.0, 1e-9, 10);
        assert!(budget.consume(0.3));
        assert_eq!(budget.remaining(), 0.7);
        assert!(budget.consume(0.3));
        assert_eq!(budget.remaining(), 0.4);
        assert!(budget.consume(0.4));
        assert_eq!(budget.remaining(), 0.0);
        assert!(!budget.consume(0.1));
    }

    #[test]
    fn test_privacy_budget_query_limit() {
        let mut budget = PrivacyBudget::with_epsilon(10.0, 1e-9, 2);
        assert!(budget.consume(0.1));
        assert!(budget.consume(0.1));
        assert!(!budget.consume(0.1));
    }

    #[test]
    fn test_privacy_budget_status() {
        let mut budget = PrivacyBudget::with_epsilon(1.0, 1e-9, 10);
        budget.consume(0.5);
        let status = budget.status();
        assert_eq!(status.consumed_epsilon, 0.5);
        assert_eq!(status.remaining_epsilon, 0.5);
        assert_eq!(status.queries_made, 1);
    }

    #[test]
    fn test_system_health_default() {
        let health = SystemHealth::new();
        assert_eq!(health.contribution_caps_hit, 0);
        assert_eq!(health.aggregation_rounds, 0);
    }
}
