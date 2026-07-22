//! Comprehensive multi-region test data for scam detection.
//!
//! Provides realistic scam messages across 4 regions (SEA, Asia, Europe, LatAm)
//! in multiple languages, with expected scam types, indicators, and risk levels.
//! Used for testing, demonstration, and calibration validation.

use crate::taxonomy::ScamType;
use crate::ontology::IndicatorId;
use crate::channel::Channel;

/// A test case for scam detection.
#[derive(Debug, Clone)]
pub struct TestCase {
    /// Unique identifier.
    pub id: &'static str,
    /// Region: "SEA", "Asia", "Europe", "LatAm".
    pub region: &'static str,
    /// Language code.
    pub language: &'static str,
    /// Channel.
    pub channel: Channel,
    /// Message text.
    pub text: &'static str,
    /// Expected scam type (None = benign).
    pub expected_scam_type: Option<ScamType>,
    /// Expected indicators (subset).
    pub expected_indicators: &'static [IndicatorId],
    /// Expected minimum risk bucket (1-5).
    pub expected_min_risk: u8,
    /// Whether this is a benign message (negative test).
    pub is_benign: bool,
    /// Description of the test case.
    pub description: &'static str,
}

/// All test cases across all regions.
pub fn all_test_cases() -> Vec<TestCase> {
    let mut cases = Vec::new();

    // ── Southeast Asia (SEA) ──
    cases.extend(sea_test_cases());
    // ── Asia (East Asia) ──
    cases.extend(asia_test_cases());
    // ── Europe ──
    cases.extend(europe_test_cases());
    // ── Latin America (LatAm) ──
    cases.extend(latam_test_cases());

    cases
}

/// Southeast Asia test cases (Vietnamese, Thai, Indonesian, Malay, Khmer).
pub fn sea_test_cases() -> Vec<TestCase> {
    vec![
        TestCase {
            id: "sea_vn_bank_01",
            region: "SEA",
            language: "vi",
            channel: Channel::Sms,
            text: "Vietcombank: Tai khoan cua ban bi khoa do dang nhap sai nhieu lan. Vui long truy cap https://vcb-khoa-tk.com de mo khoa. Khan cap!",
            expected_scam_type: Some(ScamType::BankImpersonation),
            expected_indicators: &[IndicatorId::Urgency, IndicatorId::CredentialRequest, IndicatorId::LinkSuspicious],
            expected_min_risk: 4,
            is_benign: false,
            description: "Vietcombank phishing SMS with urgent credential request and suspicious URL",
        },
        TestCase {
            id: "sea_vn_bank_02",
            region: "SEA",
            language: "vi",
            channel: Channel::Messaging,
            text: "Techcombank thong bao: Xac thuc OTP tai giao dich 5.000.000 VND. Neu khong phai ban, goi 1900. Khan cap!",
            expected_scam_type: Some(ScamType::BankImpersonation),
            expected_indicators: &[IndicatorId::Urgency, IndicatorId::FinancialRequest],
            expected_min_risk: 3,
            is_benign: false,
            description: "Techcombank OTP phishing via messaging app",
        },
        TestCase {
            id: "sea_th_delivery_01",
            region: "SEA",
            language: "th",
            channel: Channel::Sms,
            text: "มีพัสดุของคุณรอการจัดส่ง กรุณาชำระค่าจัดส่ง 35 บาท ที่ https://th-post-track.co ภายใน 24 ชม.",
            expected_scam_type: Some(ScamType::DeliveryScam),
            expected_indicators: &[IndicatorId::DeliveryLure, IndicatorId::LinkSuspicious, IndicatorId::Urgency],
            expected_min_risk: 4,
            is_benign: false,
            description: "Thai Post delivery scam with fake URL and urgent payment request",
        },
        TestCase {
            id: "sea_th_investment_01",
            region: "SEA",
            language: "th",
            channel: Channel::Messaging,
            text: "ลงทุน 1,000 บาท รับผลตอบแทน 10,000 บาทใน 7 วัน รับรองผลตอบแทน 100% คลิก https://line.me/t/invest-th",
            expected_scam_type: Some(ScamType::InvestmentFraud),
            expected_indicators: &[IndicatorId::PromiseHighReturn, IndicatorId::LinkSuspicious],
            expected_min_risk: 4,
            is_benign: false,
            description: "Thai investment scam with guaranteed returns via LINE",
        },
        TestCase {
            id: "sea_id_parcel_01",
            region: "SEA",
            language: "id",
            channel: Channel::Sms,
            text: "JNE: Paket Anda tertahan. Bayar biaya admin Rp 25.000 di bit.ly/jne-bayar. Segera!",
            expected_scam_type: Some(ScamType::DeliveryScam),
            expected_indicators: &[IndicatorId::DeliveryLure, IndicatorId::LinkSuspicious, IndicatorId::Urgency],
            expected_min_risk: 4,
            is_benign: false,
            description: "Indonesian JNE parcel scam with shortened URL",
        },
        TestCase {
            id: "sea_id_govt_01",
            region: "SEA",
            language: "id",
            channel: Channel::Sms,
            text: "DINAS KEPENDUDUKAN: Data KTP Anda bermasalah. Verifikasi di dikdukcapil-verify.id sebelum 24 jam.",
            expected_scam_type: Some(ScamType::GovernmentImpersonation),
            expected_indicators: &[IndicatorId::AuthorityClaim, IndicatorId::CredentialRequest, IndicatorId::Urgency],
            expected_min_risk: 4,
            is_benign: false,
            description: "Indonesian government impersonation scam",
        },
        TestCase {
            id: "sea_ms_loan_01",
            region: "SEA",
            language: "ms",
            channel: Channel::Sms,
            text: "Tawaran pinjaman tanpa penjamin! RM50,000 diluluskan dalam 5 minit. SMS NAMA GAJI untuk memohon sekarang!",
            expected_scam_type: Some(ScamType::LoanScam),
            expected_indicators: &[IndicatorId::FinancialRequest],
            expected_min_risk: 3,
            is_benign: false,
            description: "Malaysian loan scam with no-guarantor promise",
        },
        TestCase {
            id: "sea_km_kh_01",
            region: "SEA",
            language: "km",
            channel: Channel::Sms,
            text: "ABA Bank: គណនីរបស់អ្នកត្រូវបានចាក់សោ។ សូមចូលតាម aba-secure-kh.com ដើម្បីដោះសោ។ បន្ទាន់!",
            expected_scam_type: Some(ScamType::BankImpersonation),
            expected_indicators: &[IndicatorId::Urgency, IndicatorId::CredentialRequest, IndicatorId::LinkSuspicious],
            expected_min_risk: 4,
            is_benign: false,
            description: "Cambodian ABA Bank phishing SMS",
        },
        TestCase {
            id: "sea_vn_benign_01",
            region: "SEA",
            language: "vi",
            channel: Channel::Sms,
            text: "Cam on ban da mua hang tai Shopee. Don hang #SP2024 se giao trong 3-5 ngay.",
            expected_scam_type: None,
            expected_indicators: &[],
            expected_min_risk: 1,
            is_benign: true,
            description: "Benign Vietnamese Shopee order confirmation",
        },
        TestCase {
            id: "sea_th_benign_01",
            region: "SEA",
            language: "th",
            channel: Channel::Messaging,
            text: "เรียน คุณสมชาย นัดหมายตรวจสุขภาพประจำปี วันที่ 15 มีนาคม 10:00 น. ที่โรงพยาบาลกรุงเทพ",
            expected_scam_type: None,
            expected_indicators: &[],
            expected_min_risk: 1,
            is_benign: true,
            description: "Benign Thai hospital appointment reminder",
        },
    ]
}

/// East Asia test cases (Chinese, Japanese, Korean).
pub fn asia_test_cases() -> Vec<TestCase> {
    vec![
        TestCase {
            id: "asia_cn_police_01",
            region: "Asia",
            language: "zh",
            channel: Channel::Sms,
            text: "公安提醒：您的银行账户涉嫌洗钱，请立即点击 https://police-verify-cn.cn 进行身份验证，否则将冻结账户。",
            expected_scam_type: Some(ScamType::GovernmentImpersonation),
            expected_indicators: &[IndicatorId::AuthorityClaim, IndicatorId::Urgency, IndicatorId::CredentialRequest, IndicatorId::LinkSuspicious],
            expected_min_risk: 5,
            is_benign: false,
            description: "Chinese police impersonation scam with money laundering threat",
        },
        TestCase {
            id: "asia_cn_package_01",
            region: "Asia",
            language: "zh",
            channel: Channel::Messaging,
            text: "您的包裹已被海关扣留，需要缴纳清关费200元。请点击 sf-express-pay.cn 支付。",
            expected_scam_type: Some(ScamType::DeliveryScam),
            expected_indicators: &[IndicatorId::DeliveryLure, IndicatorId::FinancialRequest, IndicatorId::LinkSuspicious],
            expected_min_risk: 4,
            is_benign: false,
            description: "Chinese customs package scam via WeChat",
        },
        TestCase {
            id: "asia_jp_delivery_01",
            region: "Asia",
            language: "ja",
            channel: Channel::Sms,
            text: "【日本郵便】お届け先が不明のため保管しています。24時間以内に確認してください: https://japan-post-track.jp",
            expected_scam_type: Some(ScamType::DeliveryScam),
            expected_indicators: &[IndicatorId::DeliveryLure, IndicatorId::Urgency, IndicatorId::LinkSuspicious],
            expected_min_risk: 4,
            is_benign: false,
            description: "Japanese Post delivery scam with urgent verification request",
        },
        TestCase {
            id: "asia_jp_investment_01",
            region: "Asia",
            language: "ja",
            channel: Channel::Messaging,
            text: "元本保証！月利10%の投資案件。初期投資10万円が1ヶ月で20万円に。今すぐ参加: line.me/t/invest-jp",
            expected_scam_type: Some(ScamType::InvestmentFraud),
            expected_indicators: &[IndicatorId::PromiseHighReturn, IndicatorId::LinkSuspicious],
            expected_min_risk: 4,
            is_benign: false,
            description: "Japanese investment scam with guaranteed monthly returns",
        },
        TestCase {
            id: "asia_kr_delivery_01",
            region: "Asia",
            language: "ko",
            channel: Channel::Sms,
            text: "[우체국] 배송주소 오류로 반송예정입니다. 24시간내 확인: https://korea-post-verify.kr",
            expected_scam_type: Some(ScamType::DeliveryScam),
            expected_indicators: &[IndicatorId::DeliveryLure, IndicatorId::Urgency, IndicatorId::LinkSuspicious],
            expected_min_risk: 4,
            is_benign: false,
            description: "Korean Post delivery scam with address error lure",
        },
        TestCase {
            id: "asia_kr_loan_01",
            region: "Asia",
            language: "ko",
            channel: Channel::Sms,
            text: "무담보 대출 즉시 승인! 최대 5,000만원. 연락처만 입력하면 5분내 승인. 지금 신청: bit.ly/loan-kr",
            expected_scam_type: Some(ScamType::LoanScam),
            expected_indicators: &[IndicatorId::FinancialRequest, IndicatorId::LinkSuspicious],
            expected_min_risk: 3,
            is_benign: false,
            description: "Korean no-collateral loan scam",
        },
        TestCase {
            id: "asia_cn_benign_01",
            region: "Asia",
            language: "zh",
            channel: Channel::Messaging,
            text: "您的快递已签收，签收人：本人。如有疑问请联系客服。",
            expected_scam_type: None,
            expected_indicators: &[],
            expected_min_risk: 1,
            is_benign: true,
            description: "Benign Chinese delivery confirmation",
        },
        TestCase {
            id: "asia_jp_benign_01",
            region: "Asia",
            language: "ja",
            channel: Channel::Sms,
            text: "【銀行】定期預金の満期が近づいております。ご来店ください。",
            expected_scam_type: None,
            expected_indicators: &[],
            expected_min_risk: 1,
            is_benign: true,
            description: "Benign Japanese bank deposit maturity notice",
        },
    ]
}

/// Europe test cases (English, French, German, Spanish).
pub fn europe_test_cases() -> Vec<TestCase> {
    vec![
        TestCase {
            id: "eu_en_bank_01",
            region: "Europe",
            language: "en",
            channel: Channel::Sms,
            text: "BARCLAYS: We detected unusual activity on your account. Verify immediately at barclays-secure-verify.com or your account will be blocked.",
            expected_scam_type: Some(ScamType::BankImpersonation),
            expected_indicators: &[IndicatorId::Urgency, IndicatorId::CredentialRequest, IndicatorId::LinkSuspicious],
            expected_min_risk: 4,
            is_benign: false,
            description: "Barclays bank phishing SMS with urgent verification",
        },
        TestCase {
            id: "eu_en_parcel_01",
            region: "Europe",
            language: "en",
            channel: Channel::Sms,
            text: "Royal Mail: Your parcel is being held. Pay £2.99 processing fee to schedule delivery: royal-mail-pay-fee.com",
            expected_scam_type: Some(ScamType::DeliveryScam),
            expected_indicators: &[IndicatorId::DeliveryLure, IndicatorId::FinancialRequest, IndicatorId::LinkSuspicious],
            expected_min_risk: 4,
            is_benign: false,
            description: "Royal Mail parcel scam with processing fee",
        },
        TestCase {
            id: "eu_fr_bank_01",
            region: "Europe",
            language: "fr",
            channel: Channel::Sms,
            text: "BNP Paribas: Activité suspecte détectée. Vérifiez votre compte immédiatement sur bnp-paribas-verif.fr",
            expected_scam_type: Some(ScamType::BankImpersonation),
            expected_indicators: &[IndicatorId::Urgency, IndicatorId::CredentialRequest, IndicatorId::LinkSuspicious],
            expected_min_risk: 4,
            is_benign: false,
            description: "French BNP Paribas phishing SMS",
        },
        TestCase {
            id: "eu_de_tax_01",
            region: "Europe",
            language: "de",
            channel: Channel::Email,
            text: "Sehr geehrter Steuerzahler, Sie haben eine Steuerrückerstattung von 1.250€ erhalten. Klicken Sie hier um zu beantragen: finanzamt-rueckerstattung.de",
            expected_scam_type: Some(ScamType::GovernmentImpersonation),
            expected_indicators: &[IndicatorId::AuthorityClaim, IndicatorId::FinancialRequest, IndicatorId::LinkSuspicious],
            expected_min_risk: 4,
            is_benign: false,
            description: "German tax refund phishing email",
        },
        TestCase {
            id: "eu_es_investment_01",
            region: "Europe",
            language: "es",
            channel: Channel::Messaging,
            text: "¡Inversión garantizada! Gana 500€ diarios con solo 50€ de inversión. Retiros en 24h. Regístrate: invertir-seguro.es",
            expected_scam_type: Some(ScamType::InvestmentFraud),
            expected_indicators: &[IndicatorId::PromiseHighReturn, IndicatorId::LinkSuspicious],
            expected_min_risk: 4,
            is_benign: false,
            description: "Spanish investment scam with guaranteed daily returns",
        },
        TestCase {
            id: "eu_en_benign_01",
            region: "Europe",
            language: "en",
            channel: Channel::Sms,
            text: "Your appointment at NHS Clinic is confirmed for March 15 at 2:30 PM. Reply C to confirm or R to reschedule.",
            expected_scam_type: None,
            expected_indicators: &[],
            expected_min_risk: 1,
            is_benign: true,
            description: "Benign UK NHS appointment confirmation",
        },
        TestCase {
            id: "eu_fr_benign_01",
            region: "Europe",
            language: "fr",
            channel: Channel::Email,
            text: "Votre commande Amazon a été expédiée. Numéro de suivi: AMZ-2024-7851. Livraison estimée: 3-5 jours.",
            expected_scam_type: None,
            expected_indicators: &[],
            expected_min_risk: 1,
            is_benign: true,
            description: "Benign French Amazon shipping confirmation",
        },
    ]
}

/// Latin America test cases (Spanish, Portuguese).
pub fn latam_test_cases() -> Vec<TestCase> {
    vec![
        TestCase {
            id: "latam_mx_bank_01",
            region: "LatAm",
            language: "es",
            channel: Channel::Sms,
            text: "BBVA: Su cuenta ha sido bloqueada por seguridad. Verifique en bbva-mx-verificar.com o será cancelada en 24h.",
            expected_scam_type: Some(ScamType::BankImpersonation),
            expected_indicators: &[IndicatorId::Urgency, IndicatorId::CredentialRequest, IndicatorId::LinkSuspicious],
            expected_min_risk: 4,
            is_benign: false,
            description: "Mexican BBVA bank phishing SMS",
        },
        TestCase {
            id: "latam_mx_package_01",
            region: "LatAm",
            language: "es",
            channel: Channel::Sms,
            text: "DHL: Su paquete está retenido. Pague $50 MXN de aduana en dhl-mx-pago.com para liberarlo. Urgente!",
            expected_scam_type: Some(ScamType::DeliveryScam),
            expected_indicators: &[IndicatorId::DeliveryLure, IndicatorId::FinancialRequest, IndicatorId::Urgency, IndicatorId::LinkSuspicious],
            expected_min_risk: 4,
            is_benign: false,
            description: "Mexican DHL customs package scam",
        },
        TestCase {
            id: "latam_br_bank_01",
            region: "LatAm",
            language: "pt",
            channel: Channel::Sms,
            text: "Banco do Brasil: Comprovamos uma transação não autorizada de R$ 2.500. Bloqueie agora: bb-seguranca-verificar.com.br",
            expected_scam_type: Some(ScamType::BankImpersonation),
            expected_indicators: &[IndicatorId::Urgency, IndicatorId::FinancialRequest, IndicatorId::LinkSuspicious],
            expected_min_risk: 4,
            is_benign: false,
            description: "Brazilian Banco do Brasil phishing SMS",
        },
        TestCase {
            id: "latam_br_pix_01",
            region: "LatAm",
            language: "pt",
            channel: Channel::Messaging,
            text: "Parabéns! Você ganhou R$ 500 no Pix. Clique para resgatar: pix-resgate-bonus.com.br. Válido por 1 hora!",
            expected_scam_type: Some(ScamType::LotteryPrize),
            expected_indicators: &[IndicatorId::PrizeLure, IndicatorId::Urgency, IndicatorId::LinkSuspicious],
            expected_min_risk: 4,
            is_benign: false,
            description: "Brazilian Pix lottery/prize scam",
        },
        TestCase {
            id: "latam_co_investment_01",
            region: "LatAm",
            language: "es",
            channel: Channel::Messaging,
            text: "Inversión segura en Colombia! Invierte $100.000 COP y recibe $1.000.000 en 7 días. Garantizado. WhatsApp: +57 300 123 4567",
            expected_scam_type: Some(ScamType::InvestmentFraud),
            expected_indicators: &[IndicatorId::PromiseHighReturn, IndicatorId::FinancialRequest],
            expected_min_risk: 4,
            is_benign: false,
            description: "Colombian investment scam via WhatsApp",
        },
        TestCase {
            id: "latam_ar_govt_01",
            region: "LatAm",
            language: "es",
            channel: Channel::Sms,
            text: "AFIP: Tiene un reintegro de impuestos pendiente de $45.000. Confirme sus datos en afip-reintegro-ar.com antes del cierre.",
            expected_scam_type: Some(ScamType::GovernmentImpersonation),
            expected_indicators: &[IndicatorId::AuthorityClaim, IndicatorId::FinancialRequest, IndicatorId::LinkSuspicious],
            expected_min_risk: 4,
            is_benign: false,
            description: "Argentine AFIP tax refund phishing",
        },
        TestCase {
            id: "latam_mx_benign_01",
            region: "LatAm",
            language: "es",
            channel: Channel::Sms,
            text: "MercadoLibre: Tu pedido #ML-2024 ha sido enviado. Llegará en 3-5 días hábiles. Rastrea en mercadolibre.com.mx",
            expected_scam_type: None,
            expected_indicators: &[],
            expected_min_risk: 1,
            is_benign: true,
            description: "Benign Mexican MercadoLibre shipping notification",
        },
        TestCase {
            id: "latam_br_benign_01",
            region: "LatAm",
            language: "pt",
            channel: Channel::Sms,
            text: "Lembrete: Sua consulta odontológica está agendada para amanhã às 14h. Confirme respondendo SIM.",
            expected_scam_type: None,
            expected_indicators: &[],
            expected_min_risk: 1,
            is_benign: true,
            description: "Benign Brazilian dental appointment reminder",
        },
    ]
}

/// Get test cases by region.
pub fn cases_by_region(region: &str) -> Vec<TestCase> {
    all_test_cases()
        .into_iter()
        .filter(|c| c.region == region)
        .collect()
}

/// Get only scam (non-benign) test cases.
pub fn scam_cases() -> Vec<TestCase> {
    all_test_cases()
        .into_iter()
        .filter(|c| !c.is_benign)
        .collect()
}

/// Get only benign test cases.
pub fn benign_cases() -> Vec<TestCase> {
    all_test_cases()
        .into_iter()
        .filter(|c| c.is_benign)
        .collect()
}

/// Count of test cases by region.
pub fn count_by_region() -> Vec<(&'static str, usize)> {
    let regions = ["SEA", "Asia", "Europe", "LatAm"];
    regions
        .iter()
        .map(|&r| (r, cases_by_region(r).len()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_cases_have_unique_ids() {
        let cases = all_test_cases();
        let mut ids: Vec<&str> = cases.iter().map(|c| c.id).collect();
        ids.sort();
        for i in 1..ids.len() {
            assert_ne!(ids[i], ids[i - 1], "duplicate test case ID: {}", ids[i]);
        }
    }

    #[test]
    fn test_all_regions_present() {
        let cases = all_test_cases();
        let regions: Vec<&str> = cases.iter().map(|c| c.region).collect();
        assert!(regions.contains(&"SEA"), "missing SEA region");
        assert!(regions.contains(&"Asia"), "missing Asia region");
        assert!(regions.contains(&"Europe"), "missing Europe region");
        assert!(regions.contains(&"LatAm"), "missing LatAm region");
    }

    #[test]
    fn test_has_benign_and_scam() {
        assert!(!scam_cases().is_empty(), "no scam test cases");
        assert!(!benign_cases().is_empty(), "no benign test cases");
    }

    #[test]
    fn test_min_case_count() {
        let cases = all_test_cases();
        assert!(
            cases.len() >= 30,
            "expected at least 30 test cases, got {}",
            cases.len()
        );
    }

    #[test]
    fn test_scam_cases_have_expected_indicators() {
        for case in scam_cases() {
            assert!(
                !case.expected_indicators.is_empty(),
                "scam case {} should have expected indicators",
                case.id
            );
            assert!(
                case.expected_min_risk >= 3,
                "scam case {} should have min_risk >= 3, got {}",
                case.id,
                case.expected_min_risk
            );
        }
    }

    #[test]
    fn test_benign_cases_have_low_risk() {
        for case in benign_cases() {
            assert_eq!(
                case.expected_min_risk, 1,
                "benign case {} should have min_risk = 1",
                case.id
            );
        }
    }
}
