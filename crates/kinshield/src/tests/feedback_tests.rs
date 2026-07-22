//! Feedback system tests — structured feedback kinds, learning targets,
//! and feedback flow.

use crate::feedback::{FeedbackKind, FeedbackRecord, FeedbackFlow, LearningTarget};
use crate::taxonomy::ScamType;

#[test]
fn test_feedback_kind_strings() {
    assert_eq!(FeedbackKind::Correct.as_str(), "correct");
    assert_eq!(FeedbackKind::NotAScam.as_str(), "false_positive");
    assert_eq!(FeedbackKind::WrongType.as_str(), "wrong_type");
    assert_eq!(FeedbackKind::WrongReasons.as_str(), "wrong_reasons");
    assert_eq!(FeedbackKind::Uncertain.as_str(), "uncertain");
}

#[test]
fn test_feedback_kind_predicates() {
    assert!(FeedbackKind::Correct.is_correct());
    assert!(FeedbackKind::NotAScam.is_false_positive());
    assert!(FeedbackKind::WrongType.is_wrong_type());
    assert!(FeedbackKind::WrongReasons.is_wrong_reasons());

    assert!(!FeedbackKind::Correct.is_false_positive());
    assert!(!FeedbackKind::NotAScam.is_correct());
}

#[test]
fn test_learning_target_detection() {
    let record = FeedbackRecord {
        detection_id: "test-1".to_string(),
        feedback: FeedbackKind::Correct,
        corrected_type: None,
        timestamp: chrono::Utc::now(),
        source: crate::feedback::FeedbackSource::User,
    };
    assert_eq!(record.learning_target(), LearningTarget::Detection);

    let record = FeedbackRecord {
        detection_id: "test-2".to_string(),
        feedback: FeedbackKind::NotAScam,
        corrected_type: None,
        timestamp: chrono::Utc::now(),
        source: crate::feedback::FeedbackSource::User,
    };
    assert_eq!(record.learning_target(), LearningTarget::Detection);
}

#[test]
fn test_learning_target_classification() {
    let record = FeedbackRecord {
        detection_id: "test-3".to_string(),
        feedback: FeedbackKind::WrongType,
        corrected_type: Some(ScamType::BankImpersonation),
        timestamp: chrono::Utc::now(),
        source: crate::feedback::FeedbackSource::User,
    };
    assert_eq!(record.learning_target(), LearningTarget::Classification);
}

#[test]
fn test_learning_target_explanation() {
    let record = FeedbackRecord {
        detection_id: "test-4".to_string(),
        feedback: FeedbackKind::WrongReasons,
        corrected_type: None,
        timestamp: chrono::Utc::now(),
        source: crate::feedback::FeedbackSource::User,
    };
    assert_eq!(record.learning_target(), LearningTarget::Explanation);
}

#[test]
fn test_learning_target_uncertain() {
    let record = FeedbackRecord {
        detection_id: "test-5".to_string(),
        feedback: FeedbackKind::Uncertain,
        corrected_type: None,
        timestamp: chrono::Utc::now(),
        source: crate::feedback::FeedbackSource::User,
    };
    assert_eq!(record.learning_target(), LearningTarget::None);
}

#[test]
fn test_thumb_down_options() {
    let options = FeedbackFlow::thumb_down_options();
    assert_eq!(options.len(), 4);
    assert!(options.iter().any(|(_, k)| *k == FeedbackKind::NotAScam));
    assert!(options.iter().any(|(_, k)| *k == FeedbackKind::WrongType));
    assert!(options.iter().any(|(_, k)| *k == FeedbackKind::WrongReasons));
    assert!(options.iter().any(|(_, k)| *k == FeedbackKind::Uncertain));
}

#[test]
fn test_scam_type_options() {
    let options = FeedbackFlow::scam_type_options();
    assert_eq!(options.len(), ScamType::all().len());
}
