//! Privacy filter for redacting PII from text.
//!
//! Replaces detected PII entities with [REDACTED] tokens.

use super::pii::{detect_pii, PiiEntity};

/// Redact PII from text, replacing each entity with [REDACTED_TYPE].
pub fn redact(text: &str) -> String {
    let entities = detect_pii(text);
    if entities.is_empty() {
        return text.to_string();
    }

    let mut result = String::with_capacity(text.len());
    let mut last_end = 0;

    for entity in &entities {
        result.push_str(&text[last_end..entity.start]);
        result.push_str(&format!("[REDACTED_{}]", entity.entity_type.to_uppercase()));
        last_end = entity.end;
    }
    result.push_str(&text[last_end..]);

    result
}

/// Redact PII and return the redacted text + list of what was redacted.
pub fn redact_with_report(text: &str) -> (String, Vec<PiiEntity>) {
    let entities = detect_pii(text);
    let redacted = redact(text);
    (redacted, entities)
}
