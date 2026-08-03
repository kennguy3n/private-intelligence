//! Tests for new emerging scam pattern indicators and heuristic detectors.

use crate::ontology::{IndicatorId, IndicatorStrength, IndicatorHit};
use crate::detection::heuristics;
use crate::detection::keyword;
use crate::channel::Channel;
use crate::detection::scoring;
use crate::taxonomy::ScamType;

#[test]
fn test_qr_code_keyword_detection() {
    let text = "Scan this QR code to pay for your parking now";
    let hits = keyword::detect_keywords(text, Channel::Sms, "en");
    assert!(
        hits.iter().any(|h| h.id == IndicatorId::QRCodeScan),
        "Should detect QRCodeScan indicator for QR code text"
    );
}

#[test]
fn test_qr_code_heuristic_detection() {
    let text = "Scan the QR code below to complete your payment";
    let hits = heuristics::detect_heuristics(text, Channel::Sms);
    assert!(
        hits.iter().any(|h| h.id == IndicatorId::QRCodeScan),
        "QR code heuristic should fire for scan + payment context"
    );

    let hit = hits.iter().find(|h| h.id == IndicatorId::QRCodeScan).unwrap();
    assert_eq!(
        hit.strength,
        IndicatorStrength::High,
        "QR code with payment context should be High strength"
    );
}

#[test]
fn test_qr_code_heuristic_no_payment() {
    let text = "Here is the QR code for the restaurant menu";
    let hits = heuristics::detect_heuristics(text, Channel::Sms);
    let qr_hit = hits.iter().find(|h| h.id == IndicatorId::QRCodeScan);
    assert!(
        qr_hit.is_some(),
        "QR code heuristic should fire even without payment context"
    );
    if let Some(hit) = qr_hit {
        assert_eq!(
            hit.strength,
            IndicatorStrength::Medium,
            "QR code without payment context should be Medium strength"
        );
    }
}

#[test]
fn test_wrong_number_pivot_keyword_detection() {
    let text = "Sorry, wrong number! But you seem nice. Let's be friends";
    let hits = keyword::detect_keywords(text, Channel::Sms, "en");
    assert!(
        hits.iter().any(|h| h.id == IndicatorId::WrongNumberPivot),
        "Should detect WrongNumberPivot indicator"
    );
}

#[test]
fn test_wrong_number_pivot_heuristic_emits_indicator() {
    let text = "Hi, I got your number by mistake. Are you interested in crypto investment?";
    let hits = heuristics::detect_heuristics(text, Channel::Sms);
    assert!(
        hits.iter().any(|h| h.id == IndicatorId::WrongNumberPivot),
        "Wrong number pivot heuristic should emit WrongNumberPivot indicator"
    );
    assert!(
        hits.iter().any(|h| h.id == IndicatorId::PromiseHighReturn),
        "Wrong number pivot with investment should also emit PromiseHighReturn"
    );
}

#[test]
fn test_subscription_trap_keyword_detection() {
    let text = "Your free trial has ended. You will be charged $49.99/month. Cancel anytime.";
    let hits = keyword::detect_keywords(text, Channel::Sms, "en");
    assert!(
        hits.iter().any(|h| h.id == IndicatorId::SubscriptionTrap),
        "Should detect SubscriptionTrap indicator"
    );
}

#[test]
fn test_subscription_trap_heuristic_detection() {
    let text = "Your subscription has been activated. Monthly charges of $29.99 will apply automatically. Cancel by calling our hotline.";
    let hits = heuristics::detect_heuristics(text, Channel::Sms);
    assert!(
        hits.iter().any(|h| h.id == IndicatorId::SubscriptionTrap),
        "Subscription trap heuristic should fire"
    );

    let hit = hits.iter().find(|h| h.id == IndicatorId::SubscriptionTrap).unwrap();
    assert_eq!(
        hit.strength,
        IndicatorStrength::High,
        "Subscription trap with cancel barrier should be High strength"
    );
}

#[test]
fn test_deepfake_impersonation_keyword_detection() {
    let text = "This is a live video call from your boss. Please verify your identity.";
    let hits = keyword::detect_keywords(text, Channel::Sms, "en");
    assert!(
        hits.iter().any(|h| h.id == IndicatorId::DeepfakeImpersonation),
        "Should detect DeepfakeImpersonation indicator"
    );
}

#[test]
fn test_impersonation_heuristic_detection() {
    let text = "Official department notice: Your account will be suspended. Urgent action required within 24 hours.";
    let hits = heuristics::detect_heuristics(text, Channel::Sms);
    assert!(
        hits.iter().any(|h| h.id == IndicatorId::AuthorityClaim),
        "Impersonation heuristic should detect AuthorityClaim"
    );

    let hit = hits.iter().find(|h| h.id == IndicatorId::AuthorityClaim).unwrap();
    assert_eq!(
        hit.strength,
        IndicatorStrength::High,
        "Authority claim with threat + urgency should be High strength"
    );
}

#[test]
fn test_impersonation_heuristic_no_threat() {
    let text = "Official department of transportation announces new regulations.";
    let hits = heuristics::detect_heuristics(text, Channel::Sms);
    assert!(
        !hits.iter().any(|h| h.id == IndicatorId::AuthorityClaim),
        "Impersonation heuristic should not fire without threat or urgency"
    );
}

#[test]
fn test_qr_code_scoring_interaction() {
    let indicators = vec![
        IndicatorHit {
            id: IndicatorId::QRCodeScan,
            strength: IndicatorStrength::High,
            match_count: 2,
        },
        IndicatorHit {
            id: IndicatorId::FinancialRequest,
            strength: IndicatorStrength::Medium,
            match_count: 1,
        },
    ];
    let bucket = scoring::compute_risk_bucket(&indicators, Channel::Sms, "Scan QR to pay");
    assert!(
        bucket >= 3,
        "QR code + financial request should produce bucket >= 3, got {}",
        bucket
    );
}

#[test]
fn test_wrong_number_pivot_scoring_interaction() {
    let indicators = vec![
        IndicatorHit {
            id: IndicatorId::WrongNumberPivot,
            strength: IndicatorStrength::Medium,
            match_count: 1,
        },
        IndicatorHit {
            id: IndicatorId::PromiseHighReturn,
            strength: IndicatorStrength::Medium,
            match_count: 2,
        },
    ];
    let bucket = scoring::compute_risk_bucket(&indicators, Channel::Sms, "wrong number investment");
    assert!(
        bucket >= 3,
        "Wrong number + high return should produce bucket >= 3, got {}",
        bucket
    );
}

#[test]
fn test_subscription_trap_scoring_interaction() {
    let indicators = vec![
        IndicatorHit {
            id: IndicatorId::SubscriptionTrap,
            strength: IndicatorStrength::High,
            match_count: 2,
        },
        IndicatorHit {
            id: IndicatorId::FinancialRequest,
            strength: IndicatorStrength::Medium,
            match_count: 1,
        },
    ];
    let bucket = scoring::compute_risk_bucket(&indicators, Channel::Sms, "free trial charged");
    assert!(
        bucket >= 3,
        "Subscription trap + financial request should produce bucket >= 3, got {}",
        bucket
    );
}

#[test]
fn test_deepfake_impersonation_scoring_interaction() {
    let indicators = vec![
        IndicatorHit {
            id: IndicatorId::DeepfakeImpersonation,
            strength: IndicatorStrength::High,
            match_count: 1,
        },
        IndicatorHit {
            id: IndicatorId::AuthorityClaim,
            strength: IndicatorStrength::Medium,
            match_count: 1,
        },
    ];
    let bucket = scoring::compute_risk_bucket(&indicators, Channel::Sms, "video call from boss");
    assert!(
        bucket >= 4,
        "Deepfake + authority claim should produce bucket >= 4, got {}",
        bucket
    );
}

#[test]
fn test_classify_fake_qr_code_with_indicator() {
    let indicators = vec![
        IndicatorHit {
            id: IndicatorId::QRCodeScan,
            strength: IndicatorStrength::High,
            match_count: 2,
        },
        IndicatorHit {
            id: IndicatorId::LinkSuspicious,
            strength: IndicatorStrength::Medium,
            match_count: 1,
        },
    ];
    let scam_type = scoring::classify_scam_type(&indicators, "Scan this QR code to pay");
    assert_eq!(
        scam_type,
        Some(ScamType::FakeQRCode),
        "QRCodeScan indicator should classify as FakeQRCode"
    );
}

#[test]
fn test_classify_pig_butchering_with_wrong_number() {
    let indicators = vec![
        IndicatorHit {
            id: IndicatorId::WrongNumberPivot,
            strength: IndicatorStrength::Medium,
            match_count: 1,
        },
        IndicatorHit {
            id: IndicatorId::RomanceGrooming,
            strength: IndicatorStrength::Medium,
            match_count: 2,
        },
        IndicatorHit {
            id: IndicatorId::CryptoScheme,
            strength: IndicatorStrength::Medium,
            match_count: 1,
        },
    ];
    let scam_type = scoring::classify_scam_type(&indicators, "wrong number let's be friends crypto");
    assert_eq!(
        scam_type,
        Some(ScamType::PigButchering),
        "WrongNumberPivot + RomanceGrooming + CryptoScheme should classify as PigButchering"
    );
}

#[test]
fn test_classify_subscription_trap_with_indicator() {
    let indicators = vec![
        IndicatorHit {
            id: IndicatorId::SubscriptionTrap,
            strength: IndicatorStrength::High,
            match_count: 2,
        },
        IndicatorHit {
            id: IndicatorId::FreeGift,
            strength: IndicatorStrength::Low,
            match_count: 1,
        },
    ];
    let scam_type = scoring::classify_scam_type(&indicators, "free trial subscription activated monthly charge");
    assert_eq!(
        scam_type,
        Some(ScamType::SubscriptionTrap),
        "SubscriptionTrap indicator should classify as SubscriptionTrap"
    );
}

#[test]
fn test_new_indicator_count() {
    assert_eq!(
        IndicatorId::all().len(),
        33,
        "Should have 33 indicators after adding 4 new ones"
    );
}

#[test]
fn test_new_indicator_ids_unique() {
    let ids: Vec<String> = IndicatorId::all().iter().map(|i| i.as_str().to_string()).collect();
    let unique: std::collections::HashSet<&String> = ids.iter().collect();
    assert_eq!(ids.len(), unique.len(), "All 33 indicator IDs should be unique");
}

#[test]
fn test_new_indicator_labels() {
    assert_eq!(IndicatorId::QRCodeScan.label(), "QR Code Scan");
    assert_eq!(IndicatorId::WrongNumberPivot.label(), "Wrong Number Pivot");
    assert_eq!(IndicatorId::SubscriptionTrap.label(), "Subscription Trap");
    assert_eq!(IndicatorId::DeepfakeImpersonation.label(), "Deepfake Impersonation");
}

#[test]
fn test_new_indicator_explanations() {
    assert!(!IndicatorId::QRCodeScan.explanation().is_empty());
    assert!(!IndicatorId::WrongNumberPivot.explanation().is_empty());
    assert!(!IndicatorId::SubscriptionTrap.explanation().is_empty());
    assert!(!IndicatorId::DeepfakeImpersonation.explanation().is_empty());
}

#[test]
fn test_new_indicator_from_str() {
    assert_eq!(IndicatorId::from_str("qr_code_scan"), Some(IndicatorId::QRCodeScan));
    assert_eq!(IndicatorId::from_str("wrong_number_pivot"), Some(IndicatorId::WrongNumberPivot));
    assert_eq!(IndicatorId::from_str("subscription_trap"), Some(IndicatorId::SubscriptionTrap));
    assert_eq!(IndicatorId::from_str("deepfake_impersonation"), Some(IndicatorId::DeepfakeImpersonation));
}

#[test]
fn test_ontology_version_bumped() {
    assert_eq!(
        crate::ontology::ONTOLOGY_VERSION,
        "1.2.0",
        "Ontology version should be bumped to 1.2.0"
    );
}
