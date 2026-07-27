//! Risk scoring and bucketing.
//!
//! Combines indicator hits into a risk score, applies monotonic constraints,
//! and quantizes to 5 buckets (1=benign, 5=very likely scam).

use crate::ontology::{IndicatorHit, IndicatorId, IndicatorStrength};
use crate::channel::Channel;
use crate::detection::PredictedOutcome;
use crate::taxonomy::ScamType;
use crate::allowlist;
use crate::detection::url;

/// Compute risk bucket (1-5) from indicator hits.
///
/// Algorithm:
/// 1. Base score from weighted indicator strengths
/// 2. Interaction bonuses (e.g., urgency + financial = +1)
/// 3. Monotonic constraints (e.g., credential_request High → min bucket 4)
/// 4. Legitimacy signal reduction (e.g., "do not share", "no action needed")
/// 5. Channel-specific adjustment
/// 6. Clamp to 1-5
pub fn compute_risk_bucket(
    indicators: &[IndicatorHit],
    channel: Channel,
    text: &str,
) -> u8 {
    if indicators.is_empty() {
        return 1;
    }

    // 1. Base score: sum of indicator weights
    let base_score: f32 = indicators
        .iter()
        .map(|h| h.strength.weight())
        .sum();

    // Convert to initial bucket (1-5)
    // Tuned for better sensitivity: single Medium indicator should reach bucket 2,
    // single High should reach bucket 3, two Mediums should reach bucket 3.
    let mut bucket: u8 = match base_score {
        x if x < 0.4 => 1,
        x if x < 0.8 => 2,
        x if x < 1.5 => 3,
        x if x < 2.5 => 4,
        _ => 5,
    };

    // 2. Interaction bonuses
    let has = |id: IndicatorId| -> Option<&IndicatorHit> {
        indicators.iter().find(|h| h.id == id)
    };

    // urgency + financial_request → strong signal
    if has(IndicatorId::Urgency).is_some() && has(IndicatorId::FinancialRequest).is_some() {
        bucket = bucket.clamp(3, 5);
    }

    // urgency + credential_request → very strong
    if has(IndicatorId::Urgency).is_some() && has(IndicatorId::CredentialRequest).is_some() {
        bucket = bucket.clamp(4, 5);
    }

    // authority_claim + threat_legal → strong impersonation pattern
    if has(IndicatorId::AuthorityClaim).is_some() && has(IndicatorId::ThreatLegal).is_some() {
        bucket = bucket.clamp(3, 5);
    }

    // authority_claim + threat_account → bank impersonation pattern
    if has(IndicatorId::AuthorityClaim).is_some() && has(IndicatorId::ThreatAccount).is_some() {
        bucket = bucket.clamp(3, 5);
    }

    // promise_high_return + crypto_scheme → investment fraud pattern
    if has(IndicatorId::PromiseHighReturn).is_some() && has(IndicatorId::CryptoScheme).is_some() {
        bucket = bucket.clamp(3, 5);
    }

    // delivery_lure + financial_request → delivery fee scam
    if has(IndicatorId::DeliveryLure).is_some() && has(IndicatorId::FinancialRequest).is_some() {
        bucket = bucket.clamp(4, 5);
    }

    // delivery_lure + link_suspicious → delivery scam pattern
    if has(IndicatorId::DeliveryLure).is_some() && has(IndicatorId::LinkSuspicious).is_some() {
        bucket = bucket.clamp(3, 5);
    }

    // romance_grooming + financial_request → romance scam pattern
    if has(IndicatorId::RomanceGrooming).is_some() && has(IndicatorId::FinancialRequest).is_some() {
        bucket = bucket.clamp(3, 5);
    }

    // family_emergency + financial_request → family emergency scam
    if has(IndicatorId::FamilyEmergency).is_some() && has(IndicatorId::FinancialRequest).is_some() {
        bucket = bucket.clamp(4, 5);
    }

    // verification_request + link_suspicious → phishing pattern
    if has(IndicatorId::VerificationRequest).is_some() && has(IndicatorId::LinkSuspicious).is_some() {
        bucket = bucket.clamp(4, 5);
    }

    // threat_account + verification_request → account phishing
    if has(IndicatorId::ThreatAccount).is_some() && has(IndicatorId::VerificationRequest).is_some() {
        bucket = bucket.clamp(4, 5);
    }

    // authority_claim + verification_request → official impersonation phishing
    if has(IndicatorId::AuthorityClaim).is_some() && has(IndicatorId::VerificationRequest).is_some() {
        bucket = bucket.clamp(4, 5);
    }

    // sender_anomaly + verification_request → impersonation phishing
    if has(IndicatorId::SenderAnomaly).is_some() && has(IndicatorId::VerificationRequest).is_some() {
        bucket = bucket.clamp(3, 5);
    }

    // urgency + verification_request → pressure phishing
    if has(IndicatorId::Urgency).is_some() && has(IndicatorId::VerificationRequest).is_some() {
        bucket = bucket.clamp(3, 5);
    }

    // credential_request + urgency → OTP interception
    if has(IndicatorId::CredentialRequest).is_some() && has(IndicatorId::Urgency).is_some() {
        bucket = bucket.clamp(4, 5);
    }

    // sextortion + financial_request → sextortion scam with payment demand
    if has(IndicatorId::Sextortion).is_some() && has(IndicatorId::FinancialRequest).is_some() {
        bucket = bucket.clamp(4, 5);
    }

    // recovery_scam + financial_request → recovery scam asking for fees
    if has(IndicatorId::RecoveryScam).is_some() && has(IndicatorId::FinancialRequest).is_some() {
        bucket = bucket.clamp(3, 5);
    }

    // government_benefit_lure + link_suspicious → phishing for personal info
    if has(IndicatorId::GovernmentBenefitLure).is_some() && has(IndicatorId::LinkSuspicious).is_some() {
        bucket = bucket.clamp(3, 5);
    }

    // fake_marketplace + financial_request → marketplace fraud
    if has(IndicatorId::FakeMarketplace).is_some() && has(IndicatorId::FinancialRequest).is_some() {
        bucket = bucket.clamp(3, 5);
    }

    // tax_penalty + link_suspicious → toll/fine phishing
    if has(IndicatorId::TaxPenalty).is_some() && has(IndicatorId::LinkSuspicious).is_some() {
        bucket = bucket.clamp(3, 5);
    }

    // tax_penalty + financial_request → penalty payment scam
    if has(IndicatorId::TaxPenalty).is_some() && has(IndicatorId::FinancialRequest).is_some() {
        bucket = bucket.clamp(3, 5);
    }

    // authority_claim + tax_penalty → government penalty scam
    if has(IndicatorId::AuthorityClaim).is_some() && has(IndicatorId::TaxPenalty).is_some() {
        bucket = bucket.clamp(3, 5);
    }

    // urgency + tax_penalty → urgent penalty payment
    if has(IndicatorId::Urgency).is_some() && has(IndicatorId::TaxPenalty).is_some() {
        bucket = bucket.clamp(3, 5);
    }

    // financial_request + link_suspicious (without delivery_lure) → payment phishing
    if has(IndicatorId::FinancialRequest).is_some() && has(IndicatorId::LinkSuspicious).is_some()
        && has(IndicatorId::DeliveryLure).is_none()
    {
        bucket = bucket.clamp(3, 5);
    }

    // recovery_scam + urgency → urgent recovery scam
    if has(IndicatorId::RecoveryScam).is_some() && has(IndicatorId::Urgency).is_some() {
        bucket = bucket.clamp(4, 5);
    }

    // job_offer + financial_request → job scam asking for fees
    if has(IndicatorId::JobOffer).is_some() && has(IndicatorId::FinancialRequest).is_some() {
        bucket = bucket.clamp(3, 5);
    }

    // prize_lure + financial_request → lottery fee scam
    if has(IndicatorId::PrizeLure).is_some() && has(IndicatorId::FinancialRequest).is_some() {
        bucket = bucket.clamp(4, 5);
    }

    // gift_card + urgency → gift card scam under pressure
    if has(IndicatorId::GiftCard).is_some() && has(IndicatorId::Urgency).is_some() {
        bucket = bucket.clamp(3, 5);
    }

    // remote_access + authority_claim → tech support impersonation
    if has(IndicatorId::RemoteAccess).is_some() && has(IndicatorId::AuthorityClaim).is_some() {
        bucket = bucket.clamp(4, 5);
    }

    // 3. Monotonic constraints: high-value indicators enforce minimum bucket
    for hit in indicators {
        if hit.id.is_high_value() && hit.strength == IndicatorStrength::High {
            bucket = bucket.max(4);
        }
    }

    // credential_request at High always → min bucket 4
    if let Some(hit) = has(IndicatorId::CredentialRequest) {
        if hit.strength == IndicatorStrength::High {
            bucket = bucket.max(4);
        }
    }

    // 4. Legitimacy signal reduction (enhanced with allowlist)
    // Certain phrases and patterns strongly indicate a legitimate notification
    // rather than a scam. The allowlist module provides richer detection.
    let lower = text.to_lowercase();

    // Check if all URLs are from allowlisted domains
    let has_urls = lower.contains("http://") || lower.contains("https://");
    let all_urls_ok = if has_urls {
        url::all_urls_allowed(text)
    } else {
        false
    };

    let legit = allowlist::analyze_legitimacy(&lower, has_urls, all_urls_ok);

    // Also count legacy legitimacy signals for backward compatibility
    let legacy_legit_hits = count_legitimacy_signals(&lower);
    let total_legit_signals = legit.signal_count + legacy_legit_hits;

    if total_legit_signals > 0 {
        // Stronger reduction: up to 3 levels for multiple signals
        let reduction = total_legit_signals.min(3) as u8;
        bucket = bucket.saturating_sub(reduction).max(1);
    }

    // Security notification override: if this is a security notification
    // (password change, login alert, OTP with "do not share"), cap at bucket 2
    // unless there are high-value indicators at High strength that aren't
    // credential_request (which is expected in security notifications).
    // Skip caps if LinkSuspicious is present — legitimate notifications
    // don't use lookalike/suspicious URLs.
    let has_suspicious_url = has(IndicatorId::LinkSuspicious).is_some();
    if !has_suspicious_url {
    if legit.is_security_notification {
        let has_non_credential_high = indicators.iter().any(|h| {
            h.id.is_high_value() && h.strength == IndicatorStrength::High && h.id != IndicatorId::CredentialRequest
        });
        if !has_non_credential_high {
            bucket = bucket.min(2);
        }
    }

    // Transaction notification: cap at bucket 2 unless there are high-value
    // indicators at High strength (credential_request, remote_access, sextortion).
    if legit.is_transaction_notification {
        let has_high_value = indicators.iter().any(|h| {
            h.id.is_high_value() && h.strength == IndicatorStrength::High
        });
        if !has_high_value {
            bucket = bucket.min(2);
        }
    }

    // Refund notification from known brand: cap at bucket 3
    // BankTransfer and RecoveryScam are expected in refund notifications, so exclude them.
    if legit.is_refund_notification {
        let has_blocking_high = indicators.iter().any(|h| {
            h.id.is_high_value() && h.strength == IndicatorStrength::High
                && h.id != IndicatorId::BankTransfer
                && h.id != IndicatorId::RecoveryScam
        });
        if !has_blocking_high {
            bucket = bucket.min(3);
        }
    }

    // Service expiry notification: cap at bucket 3
    if legit.is_service_notification {
        let has_high_value = indicators.iter().any(|h| {
            h.id.is_high_value() && h.strength == IndicatorStrength::High
        });
        if !has_high_value {
            bucket = bucket.min(3);
        }
    }

    // Legitimate job posting from known employer: cap at bucket 3
    if legit.is_legitimate_job_posting {
        bucket = bucket.min(3);
    }

    // Legitimate charity: cap at bucket 3 (charity appeals use urgency + financial request)
    if legit.is_legitimate_charity {
        let has_blocking_high = indicators.iter().any(|h| {
            h.id.is_high_value() && h.strength == IndicatorStrength::High
                && h.id != IndicatorId::BankTransfer
        });
        if !has_blocking_high {
            bucket = bucket.min(3);
        }
    }

    // Government notification: cap at bucket 3 (gov messages use authority claim)
    if legit.is_government_notification {
        let has_blocking_high = indicators.iter().any(|h| {
            h.id.is_high_value() && h.strength == IndicatorStrength::High
                && h.id != IndicatorId::CredentialRequest
        });
        if !has_blocking_high {
            bucket = bucket.min(3);
        }
    }

    // Bank security alert: cap at bucket 3 (security alerts use credential request + verification)
    if legit.is_bank_security_alert {
        let has_blocking_high = indicators.iter().any(|h| {
            h.id.is_high_value() && h.strength == IndicatorStrength::High
                && h.id != IndicatorId::CredentialRequest
                && h.id != IndicatorId::BankTransfer
                && h.id != IndicatorId::RecoveryScam
        });
        if !has_blocking_high {
            bucket = bucket.min(3);
        }
    }

    // Delivery notification: cap at bucket 3 (delivery customs uses financial request + delivery lure)
    if legit.is_delivery_notification {
        let has_blocking_high = indicators.iter().any(|h| {
            h.id.is_high_value() && h.strength == IndicatorStrength::High
                && h.id != IndicatorId::BankTransfer
        });
        if !has_blocking_high {
            bucket = bucket.min(3);
        }
    }
    } // end if !has_suspicious_url (pre-channel caps)

    // Sender-brand tag reduction: if text contains a recognized brand tag
    // and no suspicious URLs, reduce risk.
    if has(IndicatorId::LinkSuspicious).is_none() && legit.has_sender_brand_tag {
        // Only reduce if there are no high-value indicators (credential, remote access, sextortion)
        if !indicators.iter().any(|h| h.id.is_high_value() && h.strength == IndicatorStrength::High) {
            bucket = bucket.saturating_sub(1).max(1);
        }
    }

    // 5. Channel-specific adjustment
    // SMS and messaging are higher risk channels for scams
    bucket = match channel {
        Channel::Sms | Channel::Messaging => (bucket + 1).min(5),
        // Call channel: only boost if there are indicators present.
        // A benign call transcript with no indicators should stay at bucket 1.
        Channel::Call if !indicators.is_empty() => bucket.clamp(3, 5),
        _ => bucket,
    };

    // 5b. OTP legitimacy override (applied after channel adjustment)
    // An OTP message with "do not share" is almost certainly legitimate,
    // regardless of channel boost.
    if has(IndicatorId::CredentialRequest).is_some() {
        if lower.contains("do not share") || lower.contains("don't share")
            || lower.contains("không chia sẻ") || lower.contains("khong chia se")
            || lower.contains("never ask for this code") || lower.contains("never ask")
            || lower.contains("jangan berikan") || lower.contains("jangan bagikan")
            || lower.contains("jangan sebarkan") || lower.contains("jangan beritahu")
            || lower.contains("tidak akan pernah meminta")
            || lower.contains("tidak pernah minta")
            || lower.contains("jangan beri") || lower.contains("jangan kongsi")
            || lower.contains("ไม่แชร์") || lower.contains("ห้ามแชร์")
            || lower.contains("hindi ibigay") || lower.contains("wag ibigay")
            || lower.contains("hindi i-share") || lower.contains("wag i-share")
            || lower.contains("កានតែមិនដែលសុំ")
        {
            bucket = bucket.min(2);
        }
    }

    // 5c. Re-apply legitimacy caps after channel boost
    // Channel adjustment (+1 for SMS) can push legitimacy-capped messages
    // back above the cap. Re-apply the caps here to ensure they hold.
    // BUT: if LinkSuspicious is present, skip all caps — a legitimate
    // notification would not use a lookalike/suspicious URL.
    if !has_suspicious_url {
    if legit.is_security_notification {
        let has_non_credential_high = indicators.iter().any(|h| {
            h.id.is_high_value() && h.strength == IndicatorStrength::High && h.id != IndicatorId::CredentialRequest
        });
        if !has_non_credential_high {
            bucket = bucket.min(2);
        }
    }
    if legit.is_transaction_notification {
        let has_high_value = indicators.iter().any(|h| {
            h.id.is_high_value() && h.strength == IndicatorStrength::High
        });
        if !has_high_value {
            bucket = bucket.min(2);
        }
    }
    if legit.is_refund_notification {
        let has_blocking_high = indicators.iter().any(|h| {
            h.id.is_high_value() && h.strength == IndicatorStrength::High
                && h.id != IndicatorId::BankTransfer
                && h.id != IndicatorId::RecoveryScam
        });
        if !has_blocking_high {
            bucket = bucket.min(3);
        }
    }
    if legit.is_service_notification {
        let has_high_value = indicators.iter().any(|h| {
            h.id.is_high_value() && h.strength == IndicatorStrength::High
        });
        if !has_high_value {
            bucket = bucket.min(3);
        }
    }
    if legit.is_legitimate_job_posting {
        bucket = bucket.min(3);
    }
    if legit.is_legitimate_charity {
        let has_blocking_high = indicators.iter().any(|h| {
            h.id.is_high_value() && h.strength == IndicatorStrength::High
                && h.id != IndicatorId::BankTransfer
        });
        if !has_blocking_high {
            bucket = bucket.min(3);
        }
    }
    if legit.is_government_notification {
        let has_blocking_high = indicators.iter().any(|h| {
            h.id.is_high_value() && h.strength == IndicatorStrength::High
                && h.id != IndicatorId::CredentialRequest
        });
        if !has_blocking_high {
            bucket = bucket.min(3);
        }
    }
    if legit.is_bank_security_alert {
        let has_blocking_high = indicators.iter().any(|h| {
            h.id.is_high_value() && h.strength == IndicatorStrength::High
                && h.id != IndicatorId::CredentialRequest
                && h.id != IndicatorId::BankTransfer
                && h.id != IndicatorId::RecoveryScam
        });
        if !has_blocking_high {
            bucket = bucket.min(3);
        }
    }
    if legit.is_delivery_notification {
        let has_blocking_high = indicators.iter().any(|h| {
            h.id.is_high_value() && h.strength == IndicatorStrength::High
                && h.id != IndicatorId::BankTransfer
        });
        if !has_blocking_high {
            bucket = bucket.min(3);
        }
    }
    } // end if !has_suspicious_url

    // 6. Clamp
    bucket.clamp(1, 5)
}

/// Count legitimacy signals in text that indicate a genuine notification.
///
/// These are phrases commonly found in legitimate bank/merchant messages
/// that distinguish them from scam messages using similar vocabulary.
fn count_legitimacy_signals(lower: &str) -> usize {
    let mut count = 0;

    // Anti-fraud warnings from institutions
    if lower.contains("never ask") || lower.contains("will never ask")
        || lower.contains("không bao giờ yêu cầu")
        || lower.contains("tidak akan pernah meminta") || lower.contains("tidak pernah minta")
        || lower.contains("tidak akan meminta") || lower.contains("jangan berikan")
        || lower.contains("tidak akan tuntut")
        || lower.contains("จะไม่ขอ") || lower.contains("ไม่เคยขอ")
        || lower.contains("hindi hihingi") || lower.contains("hindi magtatanong")
        || lower.contains("កានតែមិនដែលសុំ")
    {
        count += 1;
    }

    // Official security advice
    if lower.contains("for your security") || lower.contains("for security reasons")
        || lower.contains("to protect your account")
        || lower.contains("vì sự an toàn") || lower.contains("bảo mật tài khoản")
        || lower.contains("untuk keamanan") || lower.contains("demi keselamatan")
        || lower.contains("เพื่อความปลอดภัย") || lower.contains("para sa seguridad")
    {
        count += 1;
    }

    // Scam warning from authorities
    if lower.contains("scam alert") || lower.contains("fraud alert")
        || lower.contains("cảnh báo") || lower.contains("warning: scam")
        || lower.contains("beware of scam") || lower.contains("đề phòng")
        || lower.contains("ingat penipuan") || lower.contains("awas penipuan")
        || lower.contains("awas scam") || lower.contains("hati-hati penipuan")
        || lower.contains("jaga-jaga penipuan")
        || lower.contains("ระวัง scam") || lower.contains("ระวังการหลอกลวง")
        || lower.contains("nagbabala sa scam") || lower.contains("bantay scam")
    {
        count += 1;
    }

    // Transaction confirmation (past tense = notification, not request)
    if lower.contains("has been completed") || lower.contains("has been processed")
        || lower.contains("has been credited") || lower.contains("has been sent")
        || lower.contains("successfully changed") || lower.contains("successfully completed")
        || lower.contains("đã được") || lower.contains("đã chuyển")
        || lower.contains("đã thanh toán") || lower.contains("đã chuyển khoản")
        || lower.contains("thành công") || lower.contains("giao dịch thành công")
        || lower.contains("pembayaran berhasil") || lower.contains("transfer berhasil")
        || lower.contains("transaksi berhasil") || lower.contains("pembayaran telah")
        || lower.contains("pembayaran selesai")
        || lower.contains("telah diterima")
        || lower.contains("ชำระสำเร็จ") || lower.contains("โอนสำเร็จ")
        || lower.contains("transaksyon ay tagumpay") || lower.contains("matagumpay")
    {
        count += 1;
    }

    // "No action needed" variants (SEA languages)
    if lower.contains("no action needed") || lower.contains("no action required")
        || lower.contains("no payment required") || lower.contains("không cần làm gì")
        || lower.contains("không cần thanh toán") || lower.contains("không yêu cầu")
        || lower.contains("tidak perlu tindakan") || lower.contains("tidak perlu bayar")
        || lower.contains("tiada tindakan diperlukan") || lower.contains("tidak perlu pembayaran")
        || lower.contains("ไม่ต้องดำเนินการ") || lower.contains("ไม่ต้องชำระ")
        || lower.contains("walang kailangang gawin") || lower.contains("walang bayad")
    {
        count += 1;
    }

    // "If you did not" variants (SEA languages)
    if (lower.contains("if you did not") || lower.contains("if not you") || lower.contains("nếu không phải")
        || lower.contains("jika bukan anda") || lower.contains("jika anda tidak")
        || lower.contains("jika bukan awak") || lower.contains("ถ้าไม่ใช่คุณ")
        || lower.contains("kung hindi ikaw") || lower.contains("kung hindi mo ginawa"))
        && (lower.contains("call") || lower.contains("contact") || lower.contains("gọi")
            || lower.contains("hubungi") || lower.contains("โทร") || lower.contains("tumawag"))
    {
        count += 1;
    }

    count
}

/// Determine predicted outcome from risk bucket.
pub fn predict_outcome(risk_bucket: u8) -> PredictedOutcome {
    match risk_bucket {
        1 | 2 => PredictedOutcome::Benign,
        3 => PredictedOutcome::Suspicious,
        _ => PredictedOutcome::Scam,
    }
}

/// Classify scam type from indicator hits.
///
/// Uses indicator patterns to determine the most likely scam family.
/// Falls back to None if the pattern doesn't match any known scam type.
pub fn classify_scam_type(indicators: &[IndicatorHit], text: &str) -> Option<ScamType> {
    let has = |id: IndicatorId| -> bool {
        indicators.iter().any(|h| h.id == id)
    };
    let lower = text.to_lowercase();
    let text_contains = |needle: &str| lower.contains(needle);

    // Customer service scam: e-commerce brand + refund/CS keywords + link or verification
    // Checked before BankImpersonation since "your account" triggers SenderAnomaly.
    if (text_contains("customer service") || text_contains("customer support")
            || text_contains("refund") || text_contains("hoàn tiền")
            || text_contains("pengembalian") || text_contains("คืนเงิน"))
        && (text_contains("shopee") || text_contains("lazada")
            || text_contains("tokopedia") || text_contains("bukalapak")
            || text_contains("tiki") || text_contains("sendo")
            || text_contains("grab") || text_contains("gojek")
            || text_contains("carousell") || text_contains("qoo10")
            || text_contains("amazon") || text_contains("ebay"))
        && (has(IndicatorId::LinkSuspicious) || has(IndicatorId::VerificationRequest)
            || has(IndicatorId::CredentialRequest) || has(IndicatorId::FinancialRequest))
    {
        return Some(ScamType::CustomerServiceScam);
    }

    // SIM swap fraud: verification_request + threat_account with SIM/phone keywords
    // Checked before TelcoImpersonation and AccountTakeover since both would shadow it.
    if has(IndicatorId::VerificationRequest) && has(IndicatorId::ThreatAccount)
        && (text_contains("sim card") || text_contains("deactivate sim")
            || text_contains("new sim") || text_contains("port out")
            || text_contains("port-out") || text_contains("number transfer")
            || text_contains("phone number") || text_contains("ic number")
            || text_contains("thẻ sim") || text_contains("kartu sim"))
    {
        return Some(ScamType::SimSwapFraud);
    }

    // Utility impersonation: authority_claim + threat_account with utility keywords
    // Checked before TelcoImpersonation since both use threat_account.
    if has(IndicatorId::AuthorityClaim) && has(IndicatorId::ThreatAccount)
        && (text_contains("electricity") || text_contains("power")
            || text_contains("water bill") || text_contains("gas bill")
            || text_contains("utility") || text_contains("disconnect")
            || text_contains("disconnection") || text_contains("outstanding bill")
            || text_contains("điện") || text_contains("nước")
            || text_contains("listrik") || text_contains("tagihan air")
            || text_contains("pemutusan air")
            || text_contains("ไฟฟ้า") || text_contains("น้ำ"))
    {
        return Some(ScamType::UtilityImpersonation);
    }

    // Telco impersonation: sender_anomaly + threat_account (without authority_claim)
    // Checked before bank impersonation so it's reachable.
    if has(IndicatorId::SenderAnomaly) && has(IndicatorId::ThreatAccount)
        && !has(IndicatorId::AuthorityClaim)
    {
        return Some(ScamType::TelcoImpersonation);
    }

    // Bank impersonation: authority_claim + (threat_account or verification_request)
    // Also matches sender_anomaly + verification_request (bank-branded SMS without authority claim)
    if has(IndicatorId::AuthorityClaim)
        && (has(IndicatorId::ThreatAccount) || has(IndicatorId::VerificationRequest))
    {
        return Some(ScamType::BankImpersonation);
    }

    // Bank-branded SMS with verification request but no authority claim
    if has(IndicatorId::SenderAnomaly) && has(IndicatorId::VerificationRequest)
        && !has(IndicatorId::AuthorityClaim)
    {
        return Some(ScamType::BankImpersonation);
    }

    // Account takeover: verification_request + threat_account + (link_suspicious or credential_request)
    // Checked before government impersonation and social media takeover
    if has(IndicatorId::VerificationRequest) && has(IndicatorId::ThreatAccount)
        && (has(IndicatorId::LinkSuspicious) || has(IndicatorId::CredentialRequest))
    {
        return Some(ScamType::AccountTakeover);
    }

    // Account takeover: authority_claim + threat_account without bank-specific indicators
    if has(IndicatorId::AuthorityClaim) && has(IndicatorId::ThreatAccount)
        && !has(IndicatorId::VerificationRequest)
    {
        return Some(ScamType::AccountTakeover);
    }

    // Government impersonation: authority_claim + threat_legal
    if has(IndicatorId::AuthorityClaim) && has(IndicatorId::ThreatLegal) {
        return Some(ScamType::GovernmentImpersonation);
    }

    // Toll/traffic fine: tax_penalty + (link_suspicious or financial_request) with toll/fine keywords
    if has(IndicatorId::TaxPenalty)
        && (has(IndicatorId::LinkSuspicious) || has(IndicatorId::FinancialRequest))
        && (text_contains("toll") || text_contains("fine") || text_contains("summons")
            || text_contains("compound") || text_contains("erp") || text_contains("traffic")
            || text_contains("denda") || text_contains("saman") || text_contains("tilang")
            || text_contains("phạt") || text_contains("ค่าปรับ") || text_contains("ค่าผ่านทาง"))
    {
        return Some(ScamType::TollFine);
    }

    // Loan scam: financial_request + promise_high_return (without crypto)
    // Checked before InvestmentFraud since InvestmentFraud fires on PromiseHighReturn alone.
    if has(IndicatorId::FinancialRequest) && has(IndicatorId::PromiseHighReturn)
        && !has(IndicatorId::CryptoScheme)
    {
        return Some(ScamType::LoanScam);
    }

    // Pig butchering: romance_grooming + (promise_high_return or crypto_scheme)
    // Checked before InvestmentFraud and RomanceScam since both would shadow it.
    if has(IndicatorId::RomanceGrooming)
        && (has(IndicatorId::PromiseHighReturn) || has(IndicatorId::CryptoScheme))
    {
        return Some(ScamType::PigButchering);
    }

    // Investment fraud: promise_high_return + crypto_scheme
    if has(IndicatorId::PromiseHighReturn) || has(IndicatorId::CryptoScheme) {
        return Some(ScamType::InvestmentFraud);
    }

    // Parcel/customs: delivery_lure + tax_penalty (checked before DeliveryScam
    // since DeliveryScam only requires DeliveryLure and would shadow this)
    if has(IndicatorId::DeliveryLure) && has(IndicatorId::TaxPenalty) {
        return Some(ScamType::ParcelCustoms);
    }

    // Parcel/customs: delivery_lure + financial_request with customs keywords in text
    if has(IndicatorId::DeliveryLure) && has(IndicatorId::FinancialRequest)
        && (text_contains("customs") || text_contains("clearance") || text_contains("duty")
            || text_contains("import") || text_contains("hải quan") || text_contains("bea cukai")
            || text_contains("kastam") || text_contains("ศุลกากร") || text_contains("海关"))
    {
        return Some(ScamType::ParcelCustoms);
    }

    // Delivery scam: delivery_lure + link_suspicious
    if has(IndicatorId::DeliveryLure) {
        return Some(ScamType::DeliveryScam);
    }

    // Sextortion: sextortion indicator
    if has(IndicatorId::Sextortion) {
        return Some(ScamType::Sextortion);
    }

    // Recovery scam: recovery_scam indicator
    if has(IndicatorId::RecoveryScam) {
        return Some(ScamType::RecoveryScam);
    }

    // Government benefit lure: government_benefit_lure
    if has(IndicatorId::GovernmentBenefitLure) {
        return Some(ScamType::GovernmentImpersonation);
    }

    // Fake marketplace: fake_marketplace
    if has(IndicatorId::FakeMarketplace) {
        return Some(ScamType::ECommerceFraud);
    }

    // Romance scam: romance_grooming + financial_request
    if has(IndicatorId::RomanceGrooming) {
        return Some(ScamType::RomanceScam);
    }

    // Money mule: job_offer + (bank_transfer or financial_request) with mule keywords
    // Checked before JobScam since JobScam fires on JobOffer alone.
    if has(IndicatorId::JobOffer)
        && (has(IndicatorId::BankTransfer) || has(IndicatorId::FinancialRequest))
        && (text_contains("receive") || text_contains("forward")
            || text_contains("transfer") || text_contains("agent")
            || text_contains("commission") || text_contains("mule")
            || text_contains("receive payment") || text_contains("forward payment")
            || text_contains("penerima") || text_contains("pindah"))
    {
        return Some(ScamType::MoneyMule);
    }

    // Job scam: job_offer
    if has(IndicatorId::JobOffer) {
        return Some(ScamType::JobScam);
    }

    // Subscription trap: free_gift/limited_time_offer + financial_request with subscription/trial keywords
    // Checked before PrizeLure to avoid being shadowed by it.
    if (has(IndicatorId::FreeGift) || has(IndicatorId::LimitedTimeOffer))
        && has(IndicatorId::FinancialRequest)
        && (text_contains("trial") || text_contains("subscription")
            || text_contains("recurring") || text_contains("auto-renew")
            || text_contains("monthly charge") || text_contains("cancel anytime")
            || text_contains("free trial") || text_contains("membership"))
    {
        return Some(ScamType::SubscriptionTrap);
    }

    // Property rental scam: financial_request with property/rental keywords
    // Checked before PrizeLure since "prime" can fuzzy-match "prize".
    if has(IndicatorId::FinancialRequest)
        && (text_contains("rental") || text_contains("for rent") || text_contains("deposit")
            || text_contains("landlord") || text_contains("property")
            || text_contains("condo") || text_contains("apartment")
            || text_contains("room for rent") || text_contains("house for rent")
            || text_contains("thuê nhà") || text_contains("phòng cho thuê")
            || text_contains("sewa rumah") || text_contains("sewa bilik")
            || text_contains("เช่าบ้าน") || text_contains("เช่าห้อง")
            || text_contains("upaupa") || text_contains("papaupa"))
    {
        return Some(ScamType::PropertyRental);
    }

    // Lottery/prize: prize_lure
    if has(IndicatorId::PrizeLure) {
        return Some(ScamType::LotteryPrize);
    }

    // Tech support: remote_access
    if has(IndicatorId::RemoteAccess) {
        return Some(ScamType::TechSupport);
    }

    // Charity scam: charity_appeal
    if has(IndicatorId::CharityAppeal) {
        return Some(ScamType::CharityScam);
    }

    // Family emergency: family_emergency + financial_request
    if has(IndicatorId::FamilyEmergency) {
        return Some(ScamType::FamilyEmergency);
    }

    // E-commerce fraud: gift_card or bank_transfer + delivery_lure
    if has(IndicatorId::GiftCard) {
        return Some(ScamType::ECommerceFraud);
    }

    // Loan scam: financial_request alone with loan keywords in text
    if has(IndicatorId::FinancialRequest)
        && (text_contains("loan") || text_contains("approved") || text_contains("approval")
            || text_contains("pinjaman") || text_contains("lulus") || text_contains("vay")
            || text_contains("สินเชื่อ") || text_contains("utang"))
    {
        return Some(ScamType::LoanScam);
    }

    // Inheritance scam: financial_request with inheritance/estate keywords
    if has(IndicatorId::FinancialRequest)
        && (text_contains("inheritance") || text_contains("estate of")
            || text_contains("deceased") || text_contains("next of kin")
            || text_contains("beneficiary") || text_contains("last will")
            || text_contains("living will") || text_contains("lawyer")
            || text_contains("solicitor") || text_contains("di sản")
            || text_contains("warisan") || text_contains("มรดก"))
    {
        return Some(ScamType::InheritanceScam);
    }

    // Business email compromise: financial_request/bank_transfer/gift_card with boss/CEO keywords
    // Does not require AuthorityClaim since BEC emails impersonate colleagues, not institutions.
    if (has(IndicatorId::FinancialRequest) || has(IndicatorId::BankTransfer)
            || has(IndicatorId::GiftCard))
        && (text_contains("ceo") || text_contains("boss") || text_contains("manager")
            || text_contains("director") || text_contains("urgent payment")
            || text_contains("process payment") || text_contains("confidential")
            || text_contains("in a meeting") || text_contains("wire transfer")
            || text_contains("supplier") || text_contains("invoice"))
    {
        return Some(ScamType::BusinessEmailCompromise);
    }

    // Fake QR code / quishing: QR code keywords with payment/credential indicators
    // Does not require LinkSuspicious since the QR code itself is the malicious link.
    if (text_contains("qr code") || text_contains("scan qr")
            || text_contains("scan to pay") || text_contains("quishing"))
        && (has(IndicatorId::LinkSuspicious) || has(IndicatorId::FinancialRequest)
            || has(IndicatorId::CredentialRequest) || has(IndicatorId::PersonalInfoRequest))
    {
        return Some(ScamType::FakeQRCode);
    }

    // Credential theft (generic): credential_request
    if has(IndicatorId::CredentialRequest) {
        return Some(ScamType::SocialMediaTakeover);
    }

    // Default: if we have financial indicators, classify as e-commerce
    if has(IndicatorId::FinancialRequest) || has(IndicatorId::BankTransfer) {
        return Some(ScamType::ECommerceFraud);
    }

    // Fallback: indicators are present but no known family matches.
    // Return OtherUnknown so the user sees a scam warning and can
    // provide feedback to help classify new patterns.
    if !indicators.is_empty() {
        return Some(ScamType::OtherUnknown);
    }

    None
}

/// Select top N indicators (max 3) by strength for decision trace.
pub fn top_indicators(indicators: &[IndicatorHit], n: usize) -> Vec<IndicatorHit> {
    let mut sorted: Vec<IndicatorHit> = indicators.to_vec();
    sorted.sort_by(|a, b| {
        b.strength
            .weight()
            .partial_cmp(&a.strength.weight())
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    sorted.truncate(n);
    sorted
}
