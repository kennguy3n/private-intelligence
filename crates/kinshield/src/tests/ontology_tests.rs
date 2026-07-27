//! Ontology tests — indicator properties, keyword sets, and interactions.

use crate::ontology::{IndicatorId, IndicatorStrength, IndicatorCategory};

#[test]
fn test_indicator_count() {
    assert_eq!(IndicatorId::all().len(), 29, "Should have exactly 29 indicators");
}

#[test]
fn test_indicator_ids_unique() {
    let ids: Vec<String> = IndicatorId::all().iter().map(|i| i.as_str().to_string()).collect();
    let unique: std::collections::HashSet<&String> = ids.iter().collect();
    assert_eq!(ids.len(), unique.len(), "All indicator IDs should be unique");
}

#[test]
fn test_indicator_from_str_roundtrip() {
    for &id in IndicatorId::all() {
        let s = id.as_str();
        let parsed = IndicatorId::from_str(s);
        assert_eq!(parsed, Some(id), "Roundtrip failed for {}", s);
    }
}

#[test]
fn test_high_value_indicators() {
    assert!(IndicatorId::CredentialRequest.is_high_value());
    assert!(IndicatorId::RemoteAccess.is_high_value());
    assert!(IndicatorId::BankTransfer.is_high_value());
    assert!(IndicatorId::Sextortion.is_high_value());

    assert!(!IndicatorId::Urgency.is_high_value());
    assert!(!IndicatorId::PrizeLure.is_high_value());
    assert!(!IndicatorId::GiftCard.is_high_value());
}

#[test]
fn test_indicator_strength_weight() {
    assert!(IndicatorStrength::Low.weight() < IndicatorStrength::Medium.weight());
    assert!(IndicatorStrength::Medium.weight() < IndicatorStrength::High.weight());
}

#[test]
fn test_indicator_keywords_all_languages() {
    for &id in IndicatorId::all() {
        let kw = id.keywords();
        // Every indicator should have English keywords
        assert!(!kw.en.is_empty(), "Indicator {} should have English keywords", id);
        // SEA priority indicators should have at least Vietnamese and Thai
        assert!(!kw.vi.is_empty(), "Indicator {} should have Vietnamese keywords", id);
        assert!(!kw.th.is_empty(), "Indicator {} should have Thai keywords", id);
    }
}

#[test]
fn test_indicator_category_assignment() {
    assert_eq!(IndicatorId::Urgency.category(), IndicatorCategory::Psychological);
    assert_eq!(IndicatorId::FinancialRequest.category(), IndicatorCategory::Financial);
    assert_eq!(IndicatorId::CredentialRequest.category(), IndicatorCategory::Credential);
    assert_eq!(IndicatorId::RemoteAccess.category(), IndicatorCategory::Technical);
    assert_eq!(IndicatorId::RomanceGrooming.category(), IndicatorCategory::Social);
}

#[test]
fn test_ontology_version() {
    assert!(!crate::ontology::ONTOLOGY_VERSION.is_empty());
}
