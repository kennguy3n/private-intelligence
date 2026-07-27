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

// ── Toll/Fine Scam Samples ──

const SG_TOLL_SMS: &str = r#"
LTA: You have an unpaid ERP toll fine of $65.50. Pay now to avoid additional penalties.
Click https://lta-pay.sg-tollsettlenow.com to settle immediately.
"#;

const MY_SUMMONS_SMS: &str = r#"
PDRM: Anda mempunyai saman trafik tertunggak. Bayar kompaun sekarang sebelum tarikh akhir.
Klik https://myeg-pay.com/saman to settle now.
"#;

const ID_TILANG_SMS: &str = r#"
Anda memiliki denda tilang yang belum dibayar. Bayar sekarang sebelum ditindak lanjut.
Klik https://tilang-bayar.com untuk pembayaran.
"#;

// ── Loan Scam Samples ──

const ID_LOAN_SMS: &str = r#"
Pinjaman disetujui! Tanpa agunan, tanpa BI checking. Dapatkan Rp 50.000.000 sekarang.
Bayar biaya administrasi Rp 500.000 untuk pencairan. Hubungi kami segera.
"#;

const TH_LOAN_SMS: &str = r#"
สินเชื่ออนุมัติแล้ว! ไม่ต้องใช้หลักทรัพย์ค้ำประกัน รับเงินทันที 50,000 บาท
โอนเงินเข้าบัญชีทันที ติดต่อเราภายในวันนี้
"#;

// ── Account Takeover Samples ──

const SG_ACCOUNT_PHISHING: &str = r#"
Your account has been deactivated for security reasons. Reactivate now to avoid permanent loss.
Verify your identity at https://secure-verify.account-restored.com within 24 hours.
"#;

const VI_ACCOUNT_PHISHING: &str = r#"
Tai khoan cua ban da bi khoa vi ly do bao mat. Kich hoat lai ngay de tranh mat quyen truy cap.
Xac minh danh tinh tai https://verify-account.vietcombank-secure.com trong 24 gio.
"#;

// ── Sextortion Samples ──

const EN_SEXTORTION_EMAIL: &str = r#"
We have recorded you through your device camera. We have sensitive video footage of you.
Pay $2000 in Bitcoin to prevent us from sharing these videos with your contacts.
You have 48 hours to comply.
"#;

// ── Wrong-Number Pivot Samples ──

const EN_WRONG_NUMBER_INVESTMENT: &str = r#"
Sorry, I think I have the wrong number. But since we're talking, are you interested
in crypto investment? I've been making 20% returns monthly with my trading platform.
Let me know if you want to join our investment group.
"#;

const ID_WRONG_NUMBER_ROMANCE: &str = r#"
Maaf, salah nomor. Tapi senang berkenalan dengan Anda. Apakah kita bisa jadi teman?
Saya mencari seseorang yang tulus untuk menjalin hubungan.
"#;

// ── Parcel/Customs Samples ──

const EN_PARCEL_CUSTOMS: &str = r#"
Your international package is held at customs. Pay the customs duty fee of $35
to release your package. Click https://customs-pay.parcel-hold.com to pay now.
"#;

const TH_PARCEL_CUSTOMS: &str = r#"
พัสดุระหว่างประเทศของคุณถูกกักที่ศุลกากร กรุณาชำระค่าภาษีศุลกากร
เพื่อปล่อยพัสดุ คลิกที่นี่เพื่อชำระเงิน
"#;

// ── Fuzzy Matching Samples ──

const EN_FUZZY_URGENT: &str = r#"
Urgnt: Your accout has been suspendd. Verfy your identity now to restore access.
Click here to confrim your details.
"#;

// ── SMS Slang Samples ──

const EN_SMS_SLANG: &str = r#"
UR account has been locked. Pls verify ur identity ASAP. Send ur OTP to unlock now.
"#;

// ── Benign Samples ──

const SG_BENIGN_BANK: &str = r#"
[DBS] Your transaction of $150.00 to Shopee has been completed successfully.
No action required. If you did not make this transaction, call 1800-111-1111.
"#;

const ID_BENIGN_OTP: &str = r#"
[BCA] Kode OTP Anda: 847291. Jangan berikan kode ini kepada siapapun.
Bank BCA tidak akan pernah meminta kode OTP Anda.
"#;

#[test]
fn test_vi_bank_sms_detection() {
    let hits = keyword::detect_keywords(VI_BANK_SMS, Channel::Sms, "vi");
    assert!(!hits.is_empty(), "Vietnamese bank SMS should trigger indicators");

    let bucket = scoring::compute_risk_bucket(&hits, Channel::Sms, VI_BANK_SMS);
    assert!(bucket >= 3, "Vietnamese bank SMS should be risk bucket >= 3, got {}", bucket);

    let scam_type = scoring::classify_scam_type(&hits, VI_BANK_SMS);
    assert!(scam_type.is_some(), "Should classify a scam type");
}

#[test]
fn test_vi_benign_message_low_risk() {
    let hits = keyword::detect_keywords(VI_BENIGN_SHOPEE, Channel::Sms, "vi");
    let bucket = scoring::compute_risk_bucket(&hits, Channel::Sms, VI_BENIGN_SHOPEE);
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
    let vi_type = scoring::classify_scam_type(&vi_hits, VI_BANK_SMS);
    assert!(
        vi_type == Some(ScamType::BankImpersonation) || vi_type == Some(ScamType::TelcoImpersonation),
        "Vietnamese bank SMS should classify as bank or telco impersonation, got {:?}",
        vi_type
    );

    // Thai delivery scam
    let th_hits = keyword::detect_keywords(TH_DELIVERY_MSG, Channel::Messaging, "th");
    let th_type = scoring::classify_scam_type(&th_hits, TH_DELIVERY_MSG);
    assert_eq!(
        th_type,
        Some(ScamType::DeliveryScam),
        "Thai delivery message should classify as delivery scam"
    );

    // Indonesian investment fraud
    let id_hits = keyword::detect_keywords(ID_INVESTMENT_EMAIL, Channel::Email, "id");
    let id_type = scoring::classify_scam_type(&id_hits, ID_INVESTMENT_EMAIL);
    assert_eq!(
        id_type,
        Some(ScamType::InvestmentFraud),
        "Indonesian investment email should classify as investment fraud"
    );
}

// ── Toll/Fine Scam Tests ──

#[test]
fn test_sg_toll_fine_detection() {
    let hits = keyword::detect_keywords(SG_TOLL_SMS, Channel::Sms, "en");
    assert!(!hits.is_empty(), "SG toll SMS should trigger indicators");

    let has_tax = hits.iter().any(|h| h.id == IndicatorId::TaxPenalty);
    assert!(has_tax, "Should detect tax/penalty indicator in toll SMS");

    let bucket = scoring::compute_risk_bucket(&hits, Channel::Sms, SG_TOLL_SMS);
    assert!(bucket >= 3, "Toll fine SMS should be risk bucket >= 3, got {}", bucket);
}

#[test]
fn test_my_summons_detection() {
    let hits = keyword::detect_keywords(MY_SUMMONS_SMS, Channel::Sms, "ms");
    assert!(!hits.is_empty(), "Malay summons SMS should trigger indicators");

    let has_tax = hits.iter().any(|h| h.id == IndicatorId::TaxPenalty);
    assert!(has_tax, "Should detect tax/penalty in Malay summons SMS");
}

#[test]
fn test_id_tilang_detection() {
    let hits = keyword::detect_keywords(ID_TILANG_SMS, Channel::Sms, "id");
    assert!(!hits.is_empty(), "Indonesian tilang SMS should trigger indicators");

    let has_tax = hits.iter().any(|h| h.id == IndicatorId::TaxPenalty);
    assert!(has_tax, "Should detect tax/penalty in Indonesian tilang SMS");
}

// ── Loan Scam Tests ──

#[test]
fn test_id_loan_scam_detection() {
    let hits = keyword::detect_keywords(ID_LOAN_SMS, Channel::Sms, "id");
    assert!(!hits.is_empty(), "Indonesian loan SMS should trigger indicators");

    let has_financial = hits.iter().any(|h| h.id == IndicatorId::FinancialRequest);
    assert!(has_financial, "Should detect financial request in loan SMS");
}

#[test]
fn test_th_loan_scam_detection() {
    let hits = keyword::detect_keywords(TH_LOAN_SMS, Channel::Sms, "th");
    assert!(!hits.is_empty(), "Thai loan SMS should trigger indicators");

    let has_financial = hits.iter().any(|h| h.id == IndicatorId::FinancialRequest);
    assert!(has_financial, "Should detect financial request in Thai loan SMS");
}

// ── Account Takeover Tests ──

#[test]
fn test_sg_account_takeover_detection() {
    let hits = keyword::detect_keywords(SG_ACCOUNT_PHISHING, Channel::Sms, "en");
    assert!(!hits.is_empty(), "Account phishing SMS should trigger indicators");

    let has_verify = hits.iter().any(|h| h.id == IndicatorId::VerificationRequest);
    assert!(has_verify, "Should detect verification request in account phishing");
}

#[test]
fn test_vi_account_takeover_detection() {
    let hits = keyword::detect_keywords(VI_ACCOUNT_PHISHING, Channel::Sms, "vi");
    assert!(!hits.is_empty(), "Vietnamese account phishing should trigger indicators");
}

// ── Sextortion Tests ──

#[test]
fn test_en_sextortion_detection() {
    let hits = keyword::detect_keywords(EN_SEXTORTION_EMAIL, Channel::Email, "en");
    assert!(!hits.is_empty(), "Sextortion email should trigger indicators");

    let has_sextortion = hits.iter().any(|h| h.id == IndicatorId::Sextortion);
    assert!(has_sextortion, "Should detect sextortion indicator");

    let bucket = scoring::compute_risk_bucket(&hits, Channel::Email, EN_SEXTORTION_EMAIL);
    assert!(bucket >= 4, "Sextortion should be high risk bucket >= 4, got {}", bucket);
}

// ── Wrong-Number Pivot Tests ──

#[test]
fn test_wrong_number_investment_pivot() {
    let hits = crate::detection::heuristics::detect_heuristics(
        EN_WRONG_NUMBER_INVESTMENT,
        Channel::Messaging,
    );
    let has_promise = hits.iter().any(|h| h.id == IndicatorId::PromiseHighReturn);
    assert!(has_promise, "Should detect investment promise in wrong-number pivot");
}

#[test]
fn test_wrong_number_romance_pivot() {
    let hits = crate::detection::heuristics::detect_heuristics(
        ID_WRONG_NUMBER_ROMANCE,
        Channel::Messaging,
    );
    let has_romance = hits.iter().any(|h| h.id == IndicatorId::RomanceGrooming);
    assert!(has_romance, "Should detect romance grooming in Indonesian wrong-number pivot");
}

// ── Parcel/Customs Tests ──

#[test]
fn test_en_parcel_customs_detection() {
    let hits = keyword::detect_keywords(EN_PARCEL_CUSTOMS, Channel::Sms, "en");
    assert!(!hits.is_empty(), "Parcel customs SMS should trigger indicators");

    let has_delivery = hits.iter().any(|h| h.id == IndicatorId::DeliveryLure);
    assert!(has_delivery, "Should detect delivery lure in parcel customs SMS");
}

#[test]
fn test_th_parcel_customs_detection() {
    let hits = keyword::detect_keywords(TH_PARCEL_CUSTOMS, Channel::Messaging, "th");
    assert!(!hits.is_empty(), "Thai parcel customs should trigger indicators");

    let has_delivery = hits.iter().any(|h| h.id == IndicatorId::DeliveryLure);
    assert!(has_delivery, "Should detect delivery lure in Thai parcel customs");
}

// ── Fuzzy Matching Tests ──

#[test]
fn test_fuzzy_matching_misspellings() {
    let hits = keyword::detect_keywords(EN_FUZZY_URGENT, Channel::Sms, "en");
    assert!(!hits.is_empty(), "Fuzzy-misspelled scam SMS should trigger indicators via fuzzy matching");
}

// ── SMS Slang Tests ──

#[test]
fn test_sms_slang_normalization() {
    let hits = keyword::detect_keywords(EN_SMS_SLANG, Channel::Sms, "en");
    assert!(!hits.is_empty(), "SMS slang message should trigger indicators after normalization");

    // After normalization, "ur" → "your", "pls" → "please", "OTP" should trigger credential request
    let has_credential = hits.iter().any(|h| h.id == IndicatorId::CredentialRequest);
    assert!(has_credential, "Should detect credential request (OTP) after SMS slang normalization");
}

// ── Benign Message Tests ──

#[test]
fn test_sg_benign_bank_low_risk() {
    let hits = keyword::detect_keywords(SG_BENIGN_BANK, Channel::Sms, "en");
    let bucket = scoring::compute_risk_bucket(&hits, Channel::Sms, SG_BENIGN_BANK);
    assert!(bucket <= 2, "Benign DBS transaction notification should be bucket <= 2, got {}", bucket);
}

#[test]
fn test_id_benign_otp_low_risk() {
    let hits = keyword::detect_keywords(ID_BENIGN_OTP, Channel::Sms, "id");
    let bucket = scoring::compute_risk_bucket(&hits, Channel::Sms, ID_BENIGN_OTP);
    assert!(bucket <= 2, "Benign BCA OTP message should be bucket <= 2, got {}", bucket);
}

// ── SMS Misspelling Heuristic Tests ──

#[test]
fn test_sms_misspelling_heuristic() {
    let text = "Your accout has been suspendd. Verfy your passwrod now to confrim your identity.";
    let hits = crate::detection::heuristics::detect_heuristics(text, Channel::Sms);
    let has_anomaly = hits.iter().any(|h| h.id == IndicatorId::SenderAnomaly);
    assert!(has_anomaly, "Should detect sender anomaly from multiple misspellings");
}

// ── Pig Butchering Tests ──

const EN_PIG_BUTCHERING: &str = r#"
Sorry, I think I have the wrong number. But you seem really nice! I've fallen in love
with you after just a few days of chatting. You are my soulmate. I'm a crypto trader
making guaranteed high returns with zero risk on my platform. Let me show you how
to invest and we can make money together while we get to know each other.
"#;

#[test]
fn test_pig_butchering_detection() {
    let hits = keyword::detect_keywords(EN_PIG_BUTCHERING, Channel::Messaging, "en");
    assert!(!hits.is_empty(), "Pig butchering message should trigger indicators");

    let has_romance = hits.iter().any(|h| h.id == IndicatorId::RomanceGrooming);
    let has_promise = hits.iter().any(|h| h.id == IndicatorId::PromiseHighReturn);
    assert!(has_romance || has_promise, "Should detect romance or investment indicators");

    let scam_type = scoring::classify_scam_type(&hits, EN_PIG_BUTCHERING);
    assert_eq!(
        scam_type,
        Some(ScamType::PigButchering),
        "Pig butchering should classify as PigButchering, got {:?}",
        scam_type
    );
}

// ── Money Mule Tests ──

const EN_MONEY_MULE: &str = r#"
Work from home opportunity! We need agents to receive payments into their bank accounts
and forward them to our partners. Earn 10% commission on each transfer. No experience
needed, just a bank account. Contact us to start earning today.
"#;

#[test]
fn test_money_mule_detection() {
    let hits = keyword::detect_keywords(EN_MONEY_MULE, Channel::Messaging, "en");
    assert!(!hits.is_empty(), "Money mule message should trigger indicators");

    let has_job = hits.iter().any(|h| h.id == IndicatorId::JobOffer);
    assert!(has_job, "Should detect job offer in money mule message");

    let scam_type = scoring::classify_scam_type(&hits, EN_MONEY_MULE);
    assert_eq!(
        scam_type,
        Some(ScamType::MoneyMule),
        "Money mule should classify as MoneyMule, got {:?}",
        scam_type
    );
}

// ── Customer Service Scam Tests ──

const EN_CUSTOMER_SERVICE: &str = r#"
Hello, this is Shopee customer service. There is an issue with your recent order
and we need to process a refund. Please click https://shopee-refund-verify.com
to verify your identity and receive your refund. Update your information now.
"#;

#[test]
fn test_customer_service_scam_detection() {
    let hits = keyword::detect_keywords(EN_CUSTOMER_SERVICE, Channel::Browser, "en");
    assert!(!hits.is_empty(), "Customer service scam should trigger indicators");

    let scam_type = scoring::classify_scam_type(&hits, EN_CUSTOMER_SERVICE);
    assert_eq!(
        scam_type,
        Some(ScamType::CustomerServiceScam),
        "Customer service scam should classify correctly, got {:?}",
        scam_type
    );
}

// ── Property Rental Scam Tests ──

const SG_PROPERTY_RENTAL: &str = r#"
Beautiful 2-bedroom condo for rent in prime location at below market price.
Move in immediately. Pay one month deposit to secure the unit. Limited availability.
Transfer deposit to reserve. Contact us now.
"#;

#[test]
fn test_property_rental_scam_detection() {
    let hits = keyword::detect_keywords(SG_PROPERTY_RENTAL, Channel::Browser, "en");
    assert!(!hits.is_empty(), "Property rental scam should trigger indicators");

    let has_financial = hits.iter().any(|h| h.id == IndicatorId::FinancialRequest);
    assert!(has_financial, "Should detect financial request in property rental");

    let scam_type = scoring::classify_scam_type(&hits, SG_PROPERTY_RENTAL);
    assert_eq!(
        scam_type,
        Some(ScamType::PropertyRental),
        "Property rental should classify correctly, got {:?}",
        scam_type
    );
}

// ── Utility Impersonation Tests ──

const SG_UTILITY_SCAM: &str = r#"
This is an official notification from SP Group. Your electricity will be disconnected
in 2 hours due to unpaid bills. Your account will be suspended. Pay immediately to
avoid disconnection. Click https://spgroup-pay-settle.com to settle your outstanding
balance now.
"#;

#[test]
fn test_utility_impersonation_detection() {
    let hits = keyword::detect_keywords(SG_UTILITY_SCAM, Channel::Sms, "en");
    assert!(!hits.is_empty(), "Utility impersonation should trigger indicators");

    let scam_type = scoring::classify_scam_type(&hits, SG_UTILITY_SCAM);
    assert_eq!(
        scam_type,
        Some(ScamType::UtilityImpersonation),
        "Utility impersonation should classify correctly, got {:?}",
        scam_type
    );
}

// ── Business Email Compromise Tests ──

const EN_BEC: &str = r#"
Hi, I'm in a meeting and can't talk. I need you to urgently process a payment
of $15,000 to this supplier account. This is confidential and time-sensitive.
Please confirm once the wire transfer is done. Transfer funds to this account
number. Thanks, CEO.
"#;

#[test]
fn test_bec_detection() {
    let hits = keyword::detect_keywords(EN_BEC, Channel::Email, "en");
    assert!(!hits.is_empty(), "BEC email should trigger indicators");

    let scam_type = scoring::classify_scam_type(&hits, EN_BEC);
    assert_eq!(
        scam_type,
        Some(ScamType::BusinessEmailCompromise),
        "BEC should classify correctly, got {:?}",
        scam_type
    );
}

// ── Inheritance Scam Tests ──

const EN_INHERITANCE: &str = r#"
I am a lawyer representing the estate of your late relative who passed away
leaving $5 million. As the next of kin, you are the beneficiary of this
inheritance. Pay the legal fees and transfer charges to claim your funds.
Send money now to process the inheritance claim.
"#;

#[test]
fn test_inheritance_scam_detection() {
    let hits = keyword::detect_keywords(EN_INHERITANCE, Channel::Email, "en");
    assert!(!hits.is_empty(), "Inheritance scam should trigger indicators");

    let scam_type = scoring::classify_scam_type(&hits, EN_INHERITANCE);
    assert_eq!(
        scam_type,
        Some(ScamType::InheritanceScam),
        "Inheritance scam should classify correctly, got {:?}",
        scam_type
    );
}

// ── SIM Swap Fraud Tests ──

const SG_SIM_SWAP: &str = r#"
Your SIM card will be deactivated tonight due to a system upgrade. Your account
will be suspended. To maintain service, reply with your IC number and a one-time
PIN to verify your identity. Your phone number will be transferred to a new SIM
if not verified.
"#;

#[test]
fn test_sim_swap_fraud_detection() {
    let hits = keyword::detect_keywords(SG_SIM_SWAP, Channel::Sms, "en");
    assert!(!hits.is_empty(), "SIM swap fraud should trigger indicators");

    let scam_type = scoring::classify_scam_type(&hits, SG_SIM_SWAP);
    assert_eq!(
        scam_type,
        Some(ScamType::SimSwapFraud),
        "SIM swap fraud should classify correctly, got {:?}",
        scam_type
    );
}

// ── Fake QR Code Tests ──

const SG_FAKE_QR: &str = r#"
Scan this QR code to pay for parking. Official parking payment system.
Pay now via QR code. Enter your card details to complete payment.
https://parking-qr-pay.com
"#;

#[test]
fn test_fake_qr_code_detection() {
    let hits = keyword::detect_keywords(SG_FAKE_QR, Channel::Browser, "en");
    assert!(!hits.is_empty(), "Fake QR code scam should trigger indicators");

    let scam_type = scoring::classify_scam_type(&hits, SG_FAKE_QR);
    assert_eq!(
        scam_type,
        Some(ScamType::FakeQRCode),
        "Fake QR code should classify correctly, got {:?}",
        scam_type
    );
}

// ── Subscription Trap Tests ──

const EN_SUBSCRIPTION_TRAP: &str = r#"
You've activated your free trial of our premium service. After the trial,
you'll be charged $49.99/month automatically. To cancel, call our cancellation
hotline. This is a limited time offer. Pay now to continue your subscription.
"#;

#[test]
fn test_subscription_trap_detection() {
    let hits = keyword::detect_keywords(EN_SUBSCRIPTION_TRAP, Channel::Browser, "en");
    assert!(!hits.is_empty(), "Subscription trap should trigger indicators");

    let scam_type = scoring::classify_scam_type(&hits, EN_SUBSCRIPTION_TRAP);
    assert_eq!(
        scam_type,
        Some(ScamType::SubscriptionTrap),
        "Subscription trap should classify correctly, got {:?}",
        scam_type
    );
}
