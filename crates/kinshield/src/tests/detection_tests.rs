//! Detection engine tests — keyword detection, URL analysis, risk scoring,
//! and scam type classification.

use crate::channel::Channel;
use crate::ontology::{IndicatorId, IndicatorStrength, IndicatorHit};
use crate::detection::{keyword, url, scoring, PredictedOutcome};
use crate::taxonomy::ScamType;

#[test]
fn test_keyword_detection_vietnamese_bank_scam() {
    let text = "Tai khoan cua ban bi khoa. Vui long xac minh danh tinh ngay lap tuc.";
    let hits = keyword::detect_keywords(text, Channel::Sms, "vi");

    // Should detect urgency and verification_request at minimum
    let has_urgency = hits.iter().any(|h| h.id == IndicatorId::Urgency);
    let has_verification = hits.iter().any(|h| h.id == IndicatorId::VerificationRequest);
    assert!(has_urgency || has_verification, "Should detect urgency or verification in Vietnamese bank scam");
}

#[test]
fn test_keyword_detection_thai_delivery_scam() {
    let text = "พัสดุจัดส่งไม่สำเร็จ กรุณาคลิกที่นี่";
    let hits = keyword::detect_keywords(text, Channel::Messaging, "th");

    let has_delivery = hits.iter().any(|h| h.id == IndicatorId::DeliveryLure);
    assert!(has_delivery, "Should detect delivery lure in Thai");
}

#[test]
fn test_keyword_detection_indonesian_investment() {
    let text = "Keuntungan dijamin 100% tanpa risiko. Investasi crypto sekarang!";
    let hits = keyword::detect_keywords(text, Channel::Email, "id");

    let has_promise = hits.iter().any(|h| h.id == IndicatorId::PromiseHighReturn);
    let has_crypto = hits.iter().any(|h| h.id == IndicatorId::CryptoScheme);
    assert!(has_promise || has_crypto, "Should detect investment fraud indicators in Indonesian");
}

#[test]
fn test_keyword_detection_english_credential_request() {
    let text = "Please enter your password and OTP code to verify your account.";
    let hits = keyword::detect_keywords(text, Channel::Sms, "en");

    let has_credential = hits.iter().any(|h| h.id == IndicatorId::CredentialRequest);
    assert!(has_credential, "Should detect credential request in English");
}

#[test]
fn test_keyword_detection_benign_message() {
    let text = "Thank you for your purchase. Your order will arrive in 3-5 days.";
    let hits = keyword::detect_keywords(text, Channel::Sms, "en");

    // Should have very few or no scam indicators
    let high_risk_count = hits
        .iter()
        .filter(|h| h.strength == IndicatorStrength::High)
        .count();
    assert!(high_risk_count == 0, "Benign message should not have high-strength indicators");
}

#[test]
fn test_url_detection_shortened() {
    let text = "Click here: https://bit.ly/suspicious-link";
    let hit = url::analyze_urls(text);

    assert!(hit.is_some(), "Should detect shortened URL");
    let hit = hit.unwrap();
    assert_eq!(hit.id, IndicatorId::LinkSuspicious);
}

#[test]
fn test_url_detection_ip_address() {
    let text = "Visit http://192.168.1.1/login to verify";
    let hit = url::analyze_urls(text);

    assert!(hit.is_some(), "Should detect IP address in URL");
    let hit = hit.unwrap();
    assert_eq!(hit.strength, IndicatorStrength::High);
}

#[test]
fn test_url_detection_no_url() {
    let text = "Hello, how are you today?";
    let hit = url::analyze_urls(text);
    assert!(hit.is_none(), "Should not detect URLs in plain text");
}

#[test]
fn test_risk_scoring_benign() {
    let indicators = vec![];
    let bucket = scoring::compute_risk_bucket(&indicators, Channel::Sms);
    assert_eq!(bucket, 1, "No indicators should be bucket 1");
}

#[test]
fn test_risk_scoring_high_value_indicator() {
    let indicators = vec![crate::ontology::IndicatorHit {
        id: IndicatorId::CredentialRequest,
        strength: IndicatorStrength::High,
        match_count: 3,
    }];
    let bucket = scoring::compute_risk_bucket(&indicators, Channel::Sms);
    assert!(bucket >= 4, "Credential request High should be min bucket 4, got {}", bucket);
}

#[test]
fn test_risk_scoring_urgency_plus_financial() {
    let indicators = vec![
        crate::ontology::IndicatorHit {
            id: IndicatorId::Urgency,
            strength: IndicatorStrength::High,
            match_count: 2,
        },
        crate::ontology::IndicatorHit {
            id: IndicatorId::FinancialRequest,
            strength: IndicatorStrength::High,
            match_count: 1,
        },
    ];
    let bucket = scoring::compute_risk_bucket(&indicators, Channel::Sms);
    assert!(bucket >= 3, "Urgency + Financial should be min bucket 3, got {}", bucket);
}

#[test]
fn test_risk_scoring_channel_boost() {
    let indicators = vec![crate::ontology::IndicatorHit {
        id: IndicatorId::PrizeLure,
        strength: IndicatorStrength::Medium,
        match_count: 1,
    }];
    let sms_bucket = scoring::compute_risk_bucket(&indicators, Channel::Sms);
    let email_bucket = scoring::compute_risk_bucket(&indicators, Channel::Email);
    assert!(sms_bucket >= email_bucket, "SMS should boost risk over email");
}

#[test]
fn test_predict_outcome() {
    assert_eq!(scoring::predict_outcome(1), PredictedOutcome::Benign);
    assert_eq!(scoring::predict_outcome(2), PredictedOutcome::Benign);
    assert_eq!(scoring::predict_outcome(3), PredictedOutcome::Suspicious);
    assert_eq!(scoring::predict_outcome(4), PredictedOutcome::Scam);
    assert_eq!(scoring::predict_outcome(5), PredictedOutcome::Scam);
}

#[test]
fn test_classify_scam_type_bank_impersonation() {
    let indicators = vec![
        crate::ontology::IndicatorHit {
            id: IndicatorId::AuthorityClaim,
            strength: IndicatorStrength::High,
            match_count: 1,
        },
        crate::ontology::IndicatorHit {
            id: IndicatorId::ThreatAccount,
            strength: IndicatorStrength::High,
            match_count: 1,
        },
        crate::ontology::IndicatorHit {
            id: IndicatorId::VerificationRequest,
            strength: IndicatorStrength::Medium,
            match_count: 1,
        },
    ];
    let scam_type = scoring::classify_scam_type(&indicators);
    assert_eq!(scam_type, Some(ScamType::BankImpersonation));
}

#[test]
fn test_classify_scam_type_investment_fraud() {
    let indicators = vec![
        crate::ontology::IndicatorHit {
            id: IndicatorId::PromiseHighReturn,
            strength: IndicatorStrength::High,
            match_count: 2,
        },
        crate::ontology::IndicatorHit {
            id: IndicatorId::CryptoScheme,
            strength: IndicatorStrength::Medium,
            match_count: 1,
        },
    ];
    let scam_type = scoring::classify_scam_type(&indicators);
    assert_eq!(scam_type, Some(ScamType::InvestmentFraud));
}

#[test]
fn test_classify_scam_type_delivery_scam() {
    let indicators = vec![crate::ontology::IndicatorHit {
        id: IndicatorId::DeliveryLure,
        strength: IndicatorStrength::High,
        match_count: 2,
    }];
    let scam_type = scoring::classify_scam_type(&indicators);
    assert_eq!(scam_type, Some(ScamType::DeliveryScam));
}

#[test]
fn test_classify_scam_type_none_for_benign() {
    let indicators = vec![];
    let scam_type = scoring::classify_scam_type(&indicators);
    assert_eq!(scam_type, None);
}

#[test]
fn test_top_indicators_limits_to_3() {
    let indicators: Vec<crate::ontology::IndicatorHit> = IndicatorId::all()
        .iter()
        .map(|&id| crate::ontology::IndicatorHit {
            id,
            strength: IndicatorStrength::Medium,
            match_count: 1,
        })
        .collect();
    let top = scoring::top_indicators(&indicators, 3);
    assert_eq!(top.len(), 3, "Should limit to top 3 indicators");
}

#[test]
fn test_classify_scam_type_telco_impersonation() {
    // Telco impersonation: sender_anomaly + threat_account WITHOUT authority_claim
    let indicators = vec![
        crate::ontology::IndicatorHit {
            id: IndicatorId::SenderAnomaly,
            strength: IndicatorStrength::High,
            match_count: 1,
        },
        crate::ontology::IndicatorHit {
            id: IndicatorId::ThreatAccount,
            strength: IndicatorStrength::High,
            match_count: 1,
        },
    ];
    let scam_type = scoring::classify_scam_type(&indicators);
    assert_eq!(
        scam_type,
        Some(ScamType::TelcoImpersonation),
        "SenderAnomaly + ThreatAccount without AuthorityClaim should be TelcoImpersonation"
    );
}

#[test]
fn test_call_channel_benign_no_indicators() {
    // A call transcript with no indicators should NOT be forced to bucket 3
    let indicators = vec![];
    let bucket = scoring::compute_risk_bucket(&indicators, Channel::Call);
    assert_eq!(
        bucket, 1,
        "Call channel with no indicators should be bucket 1, got {}", bucket
    );
}

#[test]
fn test_call_channel_with_indicators_boosts() {
    // A call transcript WITH indicators should get the call boost
    let indicators = vec![crate::ontology::IndicatorHit {
        id: IndicatorId::RemoteAccess,
        strength: IndicatorStrength::High,
        match_count: 1,
    }];
    let bucket = scoring::compute_risk_bucket(&indicators, Channel::Call);
    assert!(
        bucket >= 3,
        "Call channel with indicators should be boosted to min bucket 3, got {}",
        bucket
    );
}

#[test]
fn test_link_suspicious_not_triggered_by_plain_http() {
    // "http://" and "https://" alone should not trigger link_suspicious
    // (they were removed from keywords to prevent email false positives)
    let hits = keyword::detect_keywords(
        "Please visit https://example.com for more information.",
        Channel::Email,
        "en",
    );
    let has_link_suspicious = hits.iter().any(|h| h.id == IndicatorId::LinkSuspicious);
    assert!(
        !has_link_suspicious,
        "Plain https:// URL should not trigger link_suspicious keyword"
    );
}

#[test]
fn test_classify_scam_type_parcel_customs() {
    // DeliveryLure + TaxPenalty → ParcelCustoms (not DeliveryScam)
    let indicators = vec![
        IndicatorHit { id: IndicatorId::DeliveryLure, strength: IndicatorStrength::High, match_count: 1 },
        IndicatorHit { id: IndicatorId::TaxPenalty, strength: IndicatorStrength::Medium, match_count: 1 },
    ];
    let scam_type = scoring::classify_scam_type(&indicators);
    assert_eq!(
        scam_type,
        Some(ScamType::ParcelCustoms),
        "DeliveryLure + TaxPenalty should classify as ParcelCustoms, not DeliveryScam"
    );
}

#[test]
fn test_classify_scam_type_delivery_scam_without_tax_penalty() {
    // DeliveryLure alone (without TaxPenalty) → DeliveryScam
    let indicators = vec![
        IndicatorHit { id: IndicatorId::DeliveryLure, strength: IndicatorStrength::High, match_count: 1 },
        IndicatorHit { id: IndicatorId::LinkSuspicious, strength: IndicatorStrength::Medium, match_count: 1 },
    ];
    let scam_type = scoring::classify_scam_type(&indicators);
    assert_eq!(
        scam_type,
        Some(ScamType::DeliveryScam),
        "DeliveryLure without TaxPenalty should classify as DeliveryScam"
    );
}
