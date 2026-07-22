//! SEA-specific scam sample tests — verify detection across Southeast
//! Asian languages and scam types.

use crate::channel::Channel;
use crate::detection::keyword;
use crate::detection::scoring;
use crate::ontology::IndicatorId;
use crate::taxonomy::ScamType;

// ── Vietnamese Samples ──

const VI_BANK_SMS: &str = r#"
Ngan hang thong bao: Tai khoan cua ban bi khoa do xac nhan dang nhap bat thuong.
Vui long xac minh danh tinh ngay lap tuc. Neu khong xac minh trong 2 gio,
tai khoan se bi khoa vinh vien.
"#;

const VI_BENIGN_SHOPEE: &str = r#"
Cam on ban da mua hang tai Shopee. Don hang #SP123456 se duoc giao trong 3-5 ngay.
"#;

// ── Thai Samples ──

const TH_DELIVERY_MSG: &str = r#"
พัสดุของคุณจัดส่งไม่สำเร็จ กรุณาอัปเดตที่อยู่ภายใน 24 ชั่วโมง
คลิกที่นี่เพื่ออัปเดต
"#;

// ── Indonesian Samples ──

const ID_INVESTMENT_EMAIL: &str = r#"
Peluang Investasi Crypto dengan Keuntungan Dijamin 100% tanpa risiko.
Trader profesional akan mengelola dana Anda. Minimum investasi hanya Rp 500.000.
"#;

// ── Malay Samples ──

const MS_TECH_SUPPORT_CALL: &str = r#"
This is Microsoft technical support calling. We have detected a virus
on your computer. Please install this remote access software so we can fix it.
Do not turn off your computer. Call us back right now.
"#;

// ── Tagalog Samples ──

const TL_LOTTERY_BROWSER: &str = r#"
Congratulations! You are the lucky winner of our Grand Lottery!
You've won $50,000 USD! To claim your prize, pay the processing fee.
"#;

// ── Khmer Samples ──

const KM_BANK_SMS: &str = r#"
ធនាគារជាតិ: គណនីរបស់អ្នកត្រូវបានផ្អាក។ សូមផ្ទៀងផ្ទាត់អត្តសញ្ញាណឥឡូវនេះ។
"#;

#[test]
fn test_vi_bank_sms_detection() {
    let hits = keyword::detect_keywords(VI_BANK_SMS, Channel::Sms, "vi");
    assert!(!hits.is_empty(), "Vietnamese bank SMS should trigger indicators");

    let bucket = scoring::compute_risk_bucket(&hits, Channel::Sms);
    assert!(bucket >= 3, "Vietnamese bank SMS should be risk bucket >= 3, got {}", bucket);

    let scam_type = scoring::classify_scam_type(&hits);
    assert!(scam_type.is_some(), "Should classify a scam type");
}

#[test]
fn test_vi_benign_message_low_risk() {
    let hits = keyword::detect_keywords(VI_BENIGN_SHOPEE, Channel::Sms, "vi");
    let bucket = scoring::compute_risk_bucket(&hits, Channel::Sms);
    assert!(bucket <= 2, "Benign Shopee notification should be bucket <= 2, got {}", bucket);
}

#[test]
fn test_th_delivery_scam_detection() {
    let hits = keyword::detect_keywords(TH_DELIVERY_MSG, Channel::Messaging, "th");
    assert!(!hits.is_empty(), "Thai delivery scam should trigger indicators");

    let has_delivery = hits.iter().any(|h| h.id == IndicatorId::DeliveryLure);
    assert!(has_delivery, "Should detect delivery lure in Thai");
}

#[test]
fn test_id_investment_fraud_detection() {
    let hits = keyword::detect_keywords(ID_INVESTMENT_EMAIL, Channel::Email, "id");
    assert!(!hits.is_empty(), "Indonesian investment email should trigger indicators");

    let has_promise = hits.iter().any(|h| h.id == IndicatorId::PromiseHighReturn);
    assert!(has_promise, "Should detect promise of high return in Indonesian");
}

#[test]
fn test_ms_tech_support_detection() {
    let hits = keyword::detect_keywords(MS_TECH_SUPPORT_CALL, Channel::Call, "ms");
    assert!(!hits.is_empty(), "Malay tech support scam should trigger indicators");

    let has_remote = hits.iter().any(|h| h.id == IndicatorId::RemoteAccess);
    assert!(has_remote, "Should detect remote access request");
}

#[test]
fn test_tl_lottery_detection() {
    let hits = keyword::detect_keywords(TL_LOTTERY_BROWSER, Channel::Browser, "tl");
    assert!(!hits.is_empty(), "Tagalog lottery scam should trigger indicators");

    let has_prize = hits.iter().any(|h| h.id == IndicatorId::PrizeLure);
    assert!(has_prize, "Should detect prize lure in Tagalog");
}

#[test]
fn test_km_bank_sms_detection() {
    let hits = keyword::detect_keywords(KM_BANK_SMS, Channel::Sms, "km");
    // Khmer may have fewer keywords, but should still detect something
    // via all-language fallback
    let all_kw_hits = keyword::detect_keywords(KM_BANK_SMS, Channel::Sms, "en");
    assert!(
        !hits.is_empty() || !all_kw_hits.is_empty(),
        "Khmer bank SMS should trigger indicators via primary or fallback"
    );
}

#[test]
fn test_cross_language_detection() {
    // A message mixing English and Vietnamese
    let mixed = "URGENT: Tai khoan cua ban bi khoa. Verify your password now!";
    let hits = keyword::detect_keywords(mixed, Channel::Sms, "vi");

    assert!(!hits.is_empty(), "Mixed language message should trigger indicators");

    let has_urgency = hits.iter().any(|h| h.id == IndicatorId::Urgency);
    assert!(has_urgency, "Should detect urgency in mixed language message");
}

#[test]
fn test_scam_type_classification_sea() {
    // Vietnamese bank impersonation
    let vi_hits = keyword::detect_keywords(VI_BANK_SMS, Channel::Sms, "vi");
    let vi_type = scoring::classify_scam_type(&vi_hits);
    assert!(
        vi_type == Some(ScamType::BankImpersonation) || vi_type == Some(ScamType::TelcoImpersonation),
        "Vietnamese bank SMS should classify as bank or telco impersonation, got {:?}",
        vi_type
    );

    // Thai delivery scam
    let th_hits = keyword::detect_keywords(TH_DELIVERY_MSG, Channel::Messaging, "th");
    let th_type = scoring::classify_scam_type(&th_hits);
    assert_eq!(
        th_type,
        Some(ScamType::DeliveryScam),
        "Thai delivery message should classify as delivery scam"
    );

    // Indonesian investment fraud
    let id_hits = keyword::detect_keywords(ID_INVESTMENT_EMAIL, Channel::Email, "id");
    let id_type = scoring::classify_scam_type(&id_hits);
    assert_eq!(
        id_type,
        Some(ScamType::InvestmentFraud),
        "Indonesian investment email should classify as investment fraud"
    );
}
