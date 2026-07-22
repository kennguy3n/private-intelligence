//! PII (Personally Identifiable Information) detection.
//!
//! Detects PII entities in text using pattern matching and e5-small
//! embeddings for context-based detection.

use serde::{Deserialize, Serialize};
use std::sync::LazyLock;

/// A detected PII entity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PiiEntity {
    /// Type of PII (Name, Phone, SSN, CreditCard, Email, Address).
    pub entity_type: String,
    /// The matched text.
    pub text: String,
    /// Start position in the original text.
    pub start: usize,
    /// End position in the original text.
    pub end: usize,
    /// Confidence score (0.0-1.0).
    pub confidence: f32,
}

// Compile regexes once at startup — avoids recompiling on every detect_pii call
static EMAIL_RE: LazyLock<regex_lite::Regex> =
    LazyLock::new(|| regex_lite::Regex::new(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}").unwrap());

static PHONE_RE: LazyLock<regex_lite::Regex> =
    LazyLock::new(|| regex_lite::Regex::new(r"\+?\d{1,3}[-.\s]?\(?\d{1,4}\)?[-.\s]?\d{3,4}[-.\s]?\d{4}").unwrap());

static SSN_RE: LazyLock<regex_lite::Regex> =
    LazyLock::new(|| regex_lite::Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").unwrap());

static CC_RE: LazyLock<regex_lite::Regex> =
    LazyLock::new(|| regex_lite::Regex::new(r"\b(?:\d{4}[-\s]?){3}\d{4}\b").unwrap());

/// Detect PII entities in text using pattern matching.
pub fn detect_pii(text: &str) -> Vec<PiiEntity> {
    let mut entities = Vec::new();

    for m in EMAIL_RE.find_iter(text) {
        entities.push(PiiEntity {
            entity_type: "Email".to_string(),
            text: m.as_str().to_string(),
            start: m.start(),
            end: m.end(),
            confidence: 0.99,
        });
    }

    for m in PHONE_RE.find_iter(text) {
        entities.push(PiiEntity {
            entity_type: "Phone".to_string(),
            text: m.as_str().to_string(),
            start: m.start(),
            end: m.end(),
            confidence: 0.85,
        });
    }

    for m in SSN_RE.find_iter(text) {
        entities.push(PiiEntity {
            entity_type: "SSN".to_string(),
            text: m.as_str().to_string(),
            start: m.start(),
            end: m.end(),
            confidence: 0.95,
        });
    }

    for m in CC_RE.find_iter(text) {
        entities.push(PiiEntity {
            entity_type: "CreditCard".to_string(),
            text: m.as_str().to_string(),
            start: m.start(),
            end: m.end(),
            confidence: 0.90,
        });
    }

    entities
}
