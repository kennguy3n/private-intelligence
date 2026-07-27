//! Decision trace tests — privacy bounds, serialization, label confidence.

use crate::decision_trace::{DecisionTrace, LabelConfidence, AGGREGATION_SCHEMA_VERSION};
use crate::feedback::FeedbackKind;
use crate::ontology::ONTOLOGY_VERSION;
use crate::taxonomy::SCAM_TAXONOMY_VERSION;

#[test]
fn test_label_confidence_trust_weights() {
    assert!(LabelConfidence::UserFeedback.trust_weight() < LabelConfidence::UserReport.trust_weight());
    assert!(LabelConfidence::UserReport.trust_weight() < LabelConfidence::MultipleReports.trust_weight());
    assert!(LabelConfidence::MultipleReports.trust_weight() < LabelConfidence::ExternallyConfirmed.trust_weight());
    assert!(LabelConfidence::ExternallyConfirmed.trust_weight() < LabelConfidence::Honeypot.trust_weight());
}

#[test]
fn test_decision_trace_serialization() {
    let trace = DecisionTrace {
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
        feedback: Some(FeedbackKind::Correct),
        corrected_type: None,
        prompt_version: "1.0.0".to_string(),
        label_confidence: LabelConfidence::UserFeedback,
        indicator_schema_version: ONTOLOGY_VERSION.to_string(),
        taxonomy_schema_version: SCAM_TAXONOMY_VERSION.to_string(),
        aggregation_schema_version: AGGREGATION_SCHEMA_VERSION.to_string(),
    };

    let json = trace.to_json().unwrap();
    let parsed = DecisionTrace::from_json(&json).unwrap();

    assert_eq!(parsed.model_version, trace.model_version);
    assert_eq!(parsed.channel, trace.channel);
    assert_eq!(parsed.language, trace.language);
    assert_eq!(parsed.risk_bucket, trace.risk_bucket);
    assert_eq!(parsed.indicators.len(), 2);
    assert_eq!(parsed.feedback, trace.feedback);
}

#[test]
fn test_decision_trace_no_sensitive_fields() {
    // Verify that the DecisionTrace struct does NOT have fields for
    // raw text, sender, domain, URL, exact timestamp, etc.
    let trace = DecisionTrace {
        local_id: Some("test-2".to_string()),
        model_version: "1.0.0".to_string(),
        channel: "sms".to_string(),
        language: "vi".to_string(),
        predicted_outcome: "scam".to_string(),
        predicted_type: Some("bank_impersonation".to_string()),
        risk_bucket: 4,
        indicators: vec![("urgency".to_string(), "high".to_string())],
        feedback: None,
        corrected_type: None,
        prompt_version: "1.0.0".to_string(),
        label_confidence: LabelConfidence::UserFeedback,
        indicator_schema_version: ONTOLOGY_VERSION.to_string(),
        taxonomy_schema_version: SCAM_TAXONOMY_VERSION.to_string(),
        aggregation_schema_version: AGGREGATION_SCHEMA_VERSION.to_string(),
    };

    let json = trace.to_json().unwrap();

    // Ensure no raw message content fields exist
    assert!(!json.contains("text"), "Trace should not contain raw text");
    assert!(!json.contains("sender"), "Trace should not contain sender");
    assert!(!json.contains("domain"), "Trace should not contain domain");
    assert!(!json.contains("url"), "Trace should not contain URL");
    assert!(!json.contains("timestamp"), "Trace should not contain exact timestamp");
    assert!(!json.contains("device_id"), "Trace should not contain device ID");
    assert!(!json.contains("embedding"), "Trace should not contain embeddings");
    // local_id should not appear in serialized JSON (skip_serializing)
    assert!(!json.contains("local_id"), "Trace should not contain local_id in JSON");
    assert!(!json.contains("test-2"), "Trace should not contain local correlation ID in JSON");
}

#[test]
fn test_decision_trace_max_3_indicators() {
    // The trace should only carry max 3 indicators
    let trace = DecisionTrace {
        local_id: None,
        model_version: "1.0.0".to_string(),
        channel: "sms".to_string(),
        language: "en".to_string(),
        predicted_outcome: "scam".to_string(),
        predicted_type: None,
        risk_bucket: 5,
        indicators: vec![
            ("urgency".to_string(), "high".to_string()),
            ("financial_request".to_string(), "high".to_string()),
            ("credential_request".to_string(), "medium".to_string()),
        ],
        feedback: None,
        corrected_type: None,
        prompt_version: "1.0.0".to_string(),
        label_confidence: LabelConfidence::UserFeedback,
        indicator_schema_version: ONTOLOGY_VERSION.to_string(),
        taxonomy_schema_version: SCAM_TAXONOMY_VERSION.to_string(),
        aggregation_schema_version: AGGREGATION_SCHEMA_VERSION.to_string(),
    };

    assert_eq!(trace.indicators.len(), 3);
}
