//! Policy enforcement engine.
//!
//! Checks document sensitivity classification before running any pipeline.
//! Admin-configurable policies can block AI processing on restricted documents.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// A policy rule mapping document sensitivity to allowed/blocked tasks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    /// Document sensitivity level.
    pub sensitivity: String,
    /// Tasks that are blocked for this sensitivity level.
    pub blocked_tasks: HashSet<String>,
}

/// The policy engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyEngine {
    rules: Vec<PolicyRule>,
    /// Whether the policy engine is enabled.
    pub enabled: bool,
}

impl Default for PolicyEngine {
    fn default() -> Self {
        Self {
            rules: vec![
                PolicyRule {
                    sensitivity: "Restricted".to_string(),
                    blocked_tasks: vec![
                        "summarize".to_string(),
                        "translate".to_string(),
                        "semantic_search".to_string(),
                        "qa".to_string(),
                        "generate_doc".to_string(),
                    ].into_iter().collect(),
                },
            ],
            enabled: true,
        }
    }
}

impl PolicyEngine {
    /// Create a new policy engine.
    pub fn new() -> Self {
        Self::default()
    }

    /// Check if a task is allowed for a given sensitivity level.
    pub fn check(&self, sensitivity: &str, task: &str) -> PolicyDecision {
        if !self.enabled {
            return PolicyDecision::Allowed;
        }

        for rule in &self.rules {
            if rule.sensitivity.eq_ignore_ascii_case(sensitivity) {
                if rule.blocked_tasks.contains(task) {
                    return PolicyDecision::Denied(format!(
                        "Task '{}' is blocked for '{}' documents by policy",
                        task, sensitivity,
                    ));
                }
            }
        }

        PolicyDecision::Allowed
    }

    /// Add a custom policy rule.
    pub fn add_rule(&mut self, sensitivity: &str, blocked_tasks: Vec<String>) {
        self.rules.push(PolicyRule {
            sensitivity: sensitivity.to_string(),
            blocked_tasks: blocked_tasks.into_iter().collect(),
        });
    }
}

/// Result of a policy check.
#[derive(Debug, Clone)]
pub enum PolicyDecision {
    /// Task is allowed.
    Allowed,
    /// Task is denied, with reason.
    Denied(String),
}

impl PolicyDecision {
    pub fn is_allowed(&self) -> bool {
        matches!(self, PolicyDecision::Allowed)
    }
}
