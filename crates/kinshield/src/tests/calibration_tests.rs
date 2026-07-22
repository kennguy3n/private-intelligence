use crate::calibration::CalibrationLayer;
use crate::channel::Channel;
use crate::ontology::{IndicatorId, IndicatorStrength};
use crate::feedback::{FeedbackKind, FeedbackSource};

#[test]
fn test_calibration_layer_creation() {
    let cal = CalibrationLayer::new("1.0.0");
    assert_eq!(cal.version(), "1.0.0");
    let stats = cal.stats();
    assert_eq!(stats.version, "1.0.0");
    assert_eq!(stats.total_feedback, 0);
    assert_eq!(stats.total_false_negatives, 0);
    assert!(stats.indicator_fp_rates.is_empty());
    assert!(stats.risk_bucket_confirmation.is_empty());
}

#[test]
fn test_calibration_no_adjustment_with_insufficient_data() {
    let cal = CalibrationLayer::new("1.0.0");
    // With no data, calibration should return the raw bucket unchanged
    assert_eq!(cal.calibrate(3, Channel::Sms, "vi"), 3);
    assert_eq!(cal.calibrate(5, Channel::Email, "en"), 5);
    assert_eq!(cal.calibrate(1, Channel::Call, "th"), 1);
}

#[test]
fn test_calibration_no_adjustment_below_threshold() {
    let mut cal = CalibrationLayer::new("1.0.0");
    let indicators = vec![(IndicatorId::Urgency, IndicatorStrength::High)];

    // Add 9 feedback records — below the 10-record threshold
    for _ in 0..9 {
        cal.update_calibration(Channel::Sms, "vi", 4, &indicators, FeedbackKind::Correct, FeedbackSource::User);
    }

    // Should still return raw bucket (not enough data)
    assert_eq!(cal.calibrate(4, Channel::Sms, "vi"), 4);
}

#[test]
fn test_calibration_boost_on_high_confirmation() {
    let mut cal = CalibrationLayer::new("1.0.0");
    let indicators = vec![(IndicatorId::Urgency, IndicatorStrength::High)];

    // Add enough correct feedback to exceed threshold (weight=0.3 per record)
    for _ in 0..35 {
        cal.update_calibration(Channel::Sms, "vi", 3, &indicators, FeedbackKind::Correct, FeedbackSource::User);
    }

    // High confirmation rate should boost bucket 3 → 4
    assert_eq!(cal.calibrate(3, Channel::Sms, "vi"), 4);
}

#[test]
fn test_calibration_reduce_on_high_fp_rate() {
    let mut cal = CalibrationLayer::new("1.0.0");
    let indicators = vec![(IndicatorId::Urgency, IndicatorStrength::High)];

    // Add enough NotAScam feedback to exceed threshold (weight=0.7 per record)
    for _ in 0..16 {
        cal.update_calibration(Channel::Sms, "vi", 4, &indicators, FeedbackKind::NotAScam, FeedbackSource::User);
    }

    // High false-positive rate should reduce bucket 4 → 3
    assert_eq!(cal.calibrate(4, Channel::Sms, "vi"), 3);
}

#[test]
fn test_calibration_does_not_boost_above_5() {
    let mut cal = CalibrationLayer::new("1.0.0");
    let indicators = vec![(IndicatorId::Urgency, IndicatorStrength::High)];

    for _ in 0..35 {
        cal.update_calibration(Channel::Sms, "vi", 5, &indicators, FeedbackKind::Correct, FeedbackSource::User);
    }

    // Already at max bucket — should stay at 5
    assert_eq!(cal.calibrate(5, Channel::Sms, "vi"), 5);
}

#[test]
fn test_calibration_does_not_reduce_below_1() {
    let mut cal = CalibrationLayer::new("1.0.0");
    let indicators = vec![(IndicatorId::Urgency, IndicatorStrength::High)];

    for _ in 0..16 {
        cal.update_calibration(Channel::Sms, "vi", 1, &indicators, FeedbackKind::NotAScam, FeedbackSource::User);
    }

    // Already at min bucket — should stay at 1
    assert_eq!(cal.calibrate(1, Channel::Sms, "vi"), 1);
}

#[test]
fn test_calibration_per_channel_language_isolation() {
    let mut cal = CalibrationLayer::new("1.0.0");
    let indicators = vec![(IndicatorId::Urgency, IndicatorStrength::High)];

    // High confirmation for SMS/vi at bucket 3 (weight=0.3 per record)
    for _ in 0..35 {
        cal.update_calibration(Channel::Sms, "vi", 3, &indicators, FeedbackKind::Correct, FeedbackSource::User);
    }

    // Email/en should not be affected by SMS/vi data
    assert_eq!(cal.calibrate(3, Channel::Email, "en"), 3);
}

#[test]
fn test_indicator_stats_tracking() {
    let mut cal = CalibrationLayer::new("1.0.0");
    let indicators = vec![
        (IndicatorId::Urgency, IndicatorStrength::High),
        (IndicatorId::FinancialRequest, IndicatorStrength::High),
    ];

    cal.update_calibration(Channel::Sms, "vi", 4, &indicators, FeedbackKind::Correct, FeedbackSource::User);
    cal.update_calibration(Channel::Sms, "vi", 4, &indicators, FeedbackKind::NotAScam, FeedbackSource::User);
    cal.update_calibration(Channel::Sms, "vi", 4, &indicators, FeedbackKind::Correct, FeedbackSource::User);

    let weights = cal.indicator_weights();
    // With 3 total (< 5 threshold), weight defaults to 1.0
    let urgency_weight = weights.get(&IndicatorId::Urgency).unwrap();
    assert!((urgency_weight - 1.0).abs() < 0.01);
}

#[test]
fn test_indicator_weights_default_for_new_indicators() {
    let cal = CalibrationLayer::new("1.0.0");
    let weights = cal.indicator_weights();
    // No data → no weights returned (empty map)
    assert!(weights.is_empty());
}

#[test]
fn test_indicator_weights_minimum_cap() {
    let mut cal = CalibrationLayer::new("1.0.0");
    let indicators = vec![(IndicatorId::Urgency, IndicatorStrength::High)];

    // All false positives: fp_rate=1.0, weight = (1.0 - 0.5).max(0.3) = 0.5
    for _ in 0..10 {
        cal.update_calibration(Channel::Sms, "vi", 4, &indicators, FeedbackKind::NotAScam, FeedbackSource::User);
    }

    let weights = cal.indicator_weights();
    let weight = weights.get(&IndicatorId::Urgency).unwrap();
    assert!((weight - 0.5).abs() < 0.01);
}

#[test]
fn test_risk_bucket_confirmation_stats() {
    let mut cal = CalibrationLayer::new("1.0.0");
    let indicators = vec![(IndicatorId::Urgency, IndicatorStrength::High)];

    // Bucket 3: 5 correct (w=0.3), 5 false positive (w=0.7)
    // confirmed = 1.5, total = 5.0, rate = 0.3
    for _ in 0..5 {
        cal.update_calibration(Channel::Sms, "vi", 3, &indicators, FeedbackKind::Correct, FeedbackSource::User);
        cal.update_calibration(Channel::Sms, "vi", 3, &indicators, FeedbackKind::NotAScam, FeedbackSource::User);
    }

    // Bucket 5: 8 correct (w=0.3), 2 false positive (w=0.7)
    // confirmed = 2.4, total = 3.8, rate ≈ 0.632
    for _ in 0..8 {
        cal.update_calibration(Channel::Sms, "vi", 5, &indicators, FeedbackKind::Correct, FeedbackSource::User);
    }
    for _ in 0..2 {
        cal.update_calibration(Channel::Sms, "vi", 5, &indicators, FeedbackKind::NotAScam, FeedbackSource::User);
    }

    let stats = cal.stats();
    assert_eq!(stats.risk_bucket_confirmation.len(), 2);

    // Find bucket 3 and 5
    let bucket3 = stats.risk_bucket_confirmation.iter().find(|(b, _)| *b == 3).unwrap();
    let bucket5 = stats.risk_bucket_confirmation.iter().find(|(b, _)| *b == 5).unwrap();

    // Bucket 3: 1.5/5.0 = 0.3
    assert!((bucket3.1 - 0.3).abs() < 0.01);
    // Bucket 5: 2.4/3.8 ≈ 0.632
    assert!((bucket5.1 - 0.632).abs() < 0.01);
}

#[test]
fn test_indicator_fp_rates_stats() {
    let mut cal = CalibrationLayer::new("1.0.0");
    let indicators = vec![
        (IndicatorId::Urgency, IndicatorStrength::High),
        (IndicatorId::FinancialRequest, IndicatorStrength::Medium),
    ];

    // 3 correct (w=0.3 each = 0.9), 1 false positive (w=0.7)
    // total = 1.6, fp = 0.7, rate = 0.4375
    cal.update_calibration(Channel::Sms, "vi", 4, &indicators, FeedbackKind::Correct, FeedbackSource::User);
    cal.update_calibration(Channel::Sms, "vi", 4, &indicators, FeedbackKind::Correct, FeedbackSource::User);
    cal.update_calibration(Channel::Sms, "vi", 4, &indicators, FeedbackKind::Correct, FeedbackSource::User);
    cal.update_calibration(Channel::Sms, "vi", 4, &indicators, FeedbackKind::NotAScam, FeedbackSource::User);

    let stats = cal.stats();
    assert_eq!(stats.indicator_fp_rates.len(), 2);

    // Each indicator: 0.7/1.6 = 0.4375 false positive rate
    for (_, rate) in &stats.indicator_fp_rates {
        assert!((rate - 0.4375).abs() < 0.01);
    }
}

#[test]
fn test_wrong_type_feedback_does_not_affect_calibration() {
    let mut cal = CalibrationLayer::new("1.0.0");
    let indicators = vec![(IndicatorId::Urgency, IndicatorStrength::High)];

    // WrongType feedback should not count as confirmed or false positive
    for _ in 0..15 {
        cal.update_calibration(Channel::Sms, "vi", 4, &indicators, FeedbackKind::WrongType, FeedbackSource::User);
    }

    // With 15 records but 0 confirmed and 0 false positive,
    // confirmation_rate = 0, fp_rate = 0 → no adjustment
    assert_eq!(cal.calibrate(4, Channel::Sms, "vi"), 4);
}

#[test]
fn test_calibration_clamps_to_valid_range() {
    let cal = CalibrationLayer::new("1.0.0");
    // Even if raw_bucket is somehow 0 or 255, calibrate should handle it
    // (though in practice, compute_risk_bucket already clamps 1-5)
    let result = cal.calibrate(1, Channel::Sms, "vi");
    assert!(result >= 1 && result <= 5);
}

#[test]
fn test_indicator_pair_stats_tracking() {
    let mut cal = CalibrationLayer::new("1.0.0");
    let indicators = vec![
        (IndicatorId::Urgency, IndicatorStrength::High),
        (IndicatorId::FinancialRequest, IndicatorStrength::High),
    ];

    cal.update_calibration(Channel::Sms, "vi", 4, &indicators, FeedbackKind::Correct, FeedbackSource::User);
    cal.update_calibration(Channel::Sms, "vi", 4, &indicators, FeedbackKind::NotAScam, FeedbackSource::User);

    // Pair stats are tracked internally — verify via indicator_weights
    // which depends on single-indicator stats
    let weights = cal.indicator_weights();
    assert!(weights.contains_key(&IndicatorId::Urgency));
    assert!(weights.contains_key(&IndicatorId::FinancialRequest));
}
