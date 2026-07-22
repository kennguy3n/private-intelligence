//! Family construct tests — circles, members, thresholds, guardian alerts.

use crate::family::{FamilyCircle, FamilyMember, MemberRole, SensitivityConfig, EmergencyContact};
use crate::channel::Channel;
use crate::ontology::IndicatorId;
use crate::detection::{DetectionResult, PredictedOutcome};
use crate::taxonomy::ScamType;

fn make_detection(risk: u8, channel: Channel, scam_type: Option<ScamType>) -> DetectionResult {
    DetectionResult {
        id: "test-det".to_string(),
        predicted_outcome: if risk >= 4 { PredictedOutcome::Scam } else if risk >= 3 { PredictedOutcome::Suspicious } else { PredictedOutcome::Benign },
        scam_type,
        risk_bucket: risk,
        indicators: vec![],
        indicator_explanations: vec![],
        channel,
        language_bucket: "vi".to_string(),
        model_version: "1.0.0".to_string(),
        prompt_version: "1.0.0".to_string(),
        duration_ms: 10,
        family_alert: None,
        decision_trace: None,
    }
}

#[test]
fn test_family_circle_creation() {
    let circle = FamilyCircle::new("fam-001");
    assert_eq!(circle.id, "fam-001");
    assert_eq!(circle.members.len(), 0);
    assert!(circle.shared_alerts);
    assert_eq!(circle.alert_threshold, 4);
    assert!(circle.emergency_contacts.is_empty());
}

#[test]
fn test_add_members() {
    let mut circle = FamilyCircle::new("fam-001");
    circle.add_member(FamilyMember::new("m1", "Alice", MemberRole::Adult));
    circle.add_member(FamilyMember::new("m2", "Bob", MemberRole::Child));
    assert_eq!(circle.members.len(), 2);
}

#[test]
fn test_guardians() {
    let mut circle = FamilyCircle::new("fam-001");
    circle.add_member(FamilyMember::new("m1", "Alice", MemberRole::Adult));
    circle.add_member(FamilyMember::new("m2", "Bob", MemberRole::Child));
    circle.add_member(FamilyMember::new("m3", "Carol", MemberRole::Elderly));

    let guardians = circle.guardians();
    assert_eq!(guardians.len(), 1);
    assert_eq!(guardians[0].id, "m1");
}

#[test]
fn test_elderly_threshold_lower_than_adult() {
    let adult = FamilyMember::new("a", "Adult", MemberRole::Adult);
    let elderly = FamilyMember::new("e", "Elderly", MemberRole::Elderly);

    assert!(elderly.sensitivity.risk_threshold <= adult.sensitivity.risk_threshold,
        "Elderly threshold should be lower (more sensitive) than adult");
}

#[test]
fn test_child_threshold_lowest() {
    let child = FamilyMember::new("c", "Child", MemberRole::Child);
    let adult = FamilyMember::new("a", "Adult", MemberRole::Adult);

    assert!(child.sensitivity.risk_threshold <= adult.sensitivity.risk_threshold,
        "Child threshold should be lowest");
}

#[test]
fn test_child_needs_guardian() {
    assert!(MemberRole::Child.needs_guardian());
    assert!(MemberRole::Elderly.needs_guardian());
    assert!(MemberRole::Teen.needs_guardian());
    assert!(!MemberRole::Adult.needs_guardian());
}

#[test]
fn test_alert_triggered_above_threshold() {
    let mut circle = FamilyCircle::new("fam-001");
    circle.alert_threshold = 3;
    circle.add_member(FamilyMember::new("m1", "Alice", MemberRole::Adult));
    circle.add_member(
        FamilyMember::new("m2", "Grandparent", MemberRole::Elderly)
            .with_guardian("m1"),
    );

    let detection = make_detection(5, Channel::Sms, Some(ScamType::BankImpersonation));
    let alert = circle.check_alert("m2", &detection);
    assert!(alert.is_some(), "Should trigger alert for risk 5 with threshold 3");

    let alert = alert.unwrap();
    assert_eq!(alert.member_id, "m2");
    assert_eq!(alert.risk_bucket, 5);
    assert!(alert.alert_targets.contains(&"m1".to_string()));
}

#[test]
fn test_alert_not_triggered_below_threshold() {
    let mut circle = FamilyCircle::new("fam-001");
    circle.alert_threshold = 4;
    circle.add_member(FamilyMember::new("m1", "Alice", MemberRole::Adult));

    let detection = make_detection(2, Channel::Sms, None);
    let alert = circle.check_alert("m1", &detection);
    assert!(alert.is_none(), "Should not trigger alert for risk 2 with threshold 4");
}

#[test]
fn test_channel_override() {
    let config = SensitivityConfig::custom(4)
        .with_channel_override(Channel::Sms, 2);

    assert_eq!(config.risk_threshold, 4);
    assert_eq!(config.channel_overrides.get(&Channel::Sms), Some(&2));
}

#[test]
fn test_blocked_indicators() {
    let config = SensitivityConfig::custom(3)
        .with_blocked_indicator(IndicatorId::Urgency);

    assert!(config.blocked_indicators.contains(&IndicatorId::Urgency));
}

#[test]
fn test_member_with_guardian() {
    let member = FamilyMember::new("m1", "Child", MemberRole::Child)
        .with_guardian("guardian-1");

    assert_eq!(member.guardian_id, Some("guardian-1".to_string()));
    assert!(member.alert_guardian);
}

#[test]
fn test_emergency_contact_creation() {
    let contact = EmergencyContact::new("+84901234567", "Dr. Nguyen", "family doctor")
        .with_channel(Channel::Call);
    assert_eq!(contact.identifier, "+84901234567");
    assert_eq!(contact.name, "Dr. Nguyen");
    assert_eq!(contact.relationship, "family doctor");
    assert_eq!(contact.channel, Some(Channel::Call));
}

#[test]
fn test_emergency_contact_add_and_find() {
    let mut circle = FamilyCircle::new("fam-001");
    circle.add_emergency_contact(
        EmergencyContact::new("school@edu.vn", "School", "school")
    );
    circle.add_emergency_contact(
        EmergencyContact::new("+84901234567", "Dr. Nguyen", "family doctor")
    );

    assert_eq!(circle.emergency_contacts.len(), 2);

    // Case-insensitive match
    let found = circle.find_emergency_contact("SCHOOL@EDU.VN");
    assert!(found.is_some());
    assert_eq!(found.unwrap().name, "School");

    // No match
    assert!(circle.find_emergency_contact("unknown@scam.com").is_none());
}
