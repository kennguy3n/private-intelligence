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

    // Compute legitimacy context early — needed for brand-conditional interactions.
    let lower = text.to_lowercase();
    let has_urls = lower.contains("http://") || lower.contains("https://");
    let all_urls_ok = if has_urls {
        url::all_urls_allowed(text)
    } else {
        false
    };
    let legit = allowlist::analyze_legitimacy(&lower, has_urls, all_urls_ok);
    let has_brand = legit.has_sender_brand_tag || legit.has_known_brand_name;
    let has_suspicious_url = indicators.iter().any(|h| h.id == IndicatorId::LinkSuspicious);

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

    // phone_callback + urgency → urgent callback phishing
    // Common in bank/telco impersonation: "Please call immediately regarding your account"
    if has(IndicatorId::PhoneCallback).is_some() && has(IndicatorId::Urgency).is_some() {
        bucket = bucket.max(3);
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

    // urgency + financial_request (without link_suspicious) → payment pressure scam
    // Catches scam messages demanding urgent payment without a URL (e.g., "pay now via [link]")
    if has(IndicatorId::Urgency).is_some() && has(IndicatorId::FinancialRequest).is_some()
        && has(IndicatorId::LinkSuspicious).is_none()
        && has(IndicatorId::DeliveryLure).is_none()
    {
        bucket = bucket.max(3);
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

    // qr_code_scan + financial_request → QR phishing with payment
    if has(IndicatorId::QRCodeScan).is_some() && has(IndicatorId::FinancialRequest).is_some() {
        bucket = bucket.clamp(3, 5);
    }

    // wrong_number_pivot + promise_high_return → pig butchering pattern
    if has(IndicatorId::WrongNumberPivot).is_some()
        && (has(IndicatorId::PromiseHighReturn).is_some() || has(IndicatorId::CryptoScheme).is_some())
    {
        bucket = bucket.clamp(3, 5);
    }

    // subscription_trap + financial_request → hidden charges scam
    if has(IndicatorId::SubscriptionTrap).is_some() && has(IndicatorId::FinancialRequest).is_some() {
        bucket = bucket.clamp(3, 5);
    }

    // deepfake_impersonation + authority_claim → impersonation scam
    if has(IndicatorId::DeepfakeImpersonation).is_some() && has(IndicatorId::AuthorityClaim).is_some() {
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
    // (legit context, lower, has_urls, all_urls_ok, has_suspicious_url computed earlier)

    // Also count legacy legitimacy signals for backward compatibility
    let legacy_legit_hits = count_legitimacy_signals(&lower);
    let total_legit_signals = legit.signal_count + legacy_legit_hits;

    if total_legit_signals > 0 {
        if has_suspicious_url {
            // Suspicious URL present: limit reduction to 1 level.
            // Brand impersonation is likely — don't over-reduce.
            bucket = bucket.saturating_sub(1).max(1);
        } else {
            // No suspicious URLs: full reduction up to 3 levels.
            let reduction = total_legit_signals.min(3) as u8;
            bucket = bucket.saturating_sub(reduction).max(1);
            // Guard: don't reduce below bucket 2 if high-value indicators
            // at High strength are present — these are strong scam signals
            // that legitimacy phrases alone shouldn't override.
            let has_high_value_high = indicators.iter().any(|h| {
                h.id.is_high_value() && h.strength == IndicatorStrength::High
            });
            if has_high_value_high {
                bucket = bucket.max(2);
            }
            // Guard: don't reduce below bucket 3 when phone_callback + urgency
            // are both present — this is a strong impersonation pattern.
            if has(IndicatorId::PhoneCallback).is_some() && has(IndicatorId::Urgency).is_some() {
                bucket = bucket.max(3);
            }
        }
    }

    // Security notification override: if this is a security notification
    // (password change, login alert, OTP with "do not share"), cap at bucket 2
    // unless there are high-value indicators at High strength that aren't
    // credential_request (which is expected in security notifications).
    // Skip caps if LinkSuspicious is present — legitimate notifications
    // don't use lookalike/suspicious URLs.
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
                && h.id != IndicatorId::ThreatAccount
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
                && h.id != IndicatorId::ThreatAccount
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
    // or known brand name, and no suspicious URLs, reduce risk.
    // (has_brand computed earlier)
    if !has_suspicious_url && has_brand {
        // Only reduce if there are no high-value indicators (credential, remote access, sextortion)
        if !indicators.iter().any(|h| h.id.is_high_value() && h.strength == IndicatorStrength::High) {
            // Don't reduce when phone_callback + urgency are present — strong impersonation signal.
            let has_callback_urgency = has(IndicatorId::PhoneCallback).is_some()
                && has(IndicatorId::Urgency).is_some();
            if !has_callback_urgency {
                // Bracket brand tags are strong legitimacy signals — reduce by 1.
                if legit.has_sender_brand_tag {
                    bucket = bucket.saturating_sub(1).max(1);
                }
                // Known brand name (non-bracket): only reduce when there's at least
                // one other legitimacy signal (notification pattern, allowlisted URL, etc.)
                // to confirm it's a legitimate notification, not a scam mentioning a brand.
                else if legit.has_known_brand_name && legit.signal_count >= 1 {
                    bucket = bucket.saturating_sub(1).max(1);
                }
            }
        }
    }

    // Cross-signal impersonation boost: if message uses authority language
    // but has NO brand tag and HAS a suspicious URL, it's likely impersonation.
    // Boost risk to counteract any legitimacy false positives.
    if has(IndicatorId::AuthorityClaim).is_some()
        && !has_brand
        && has(IndicatorId::LinkSuspicious).is_some()
    {
        bucket = (bucket + 1).min(5);
    }

    // Cross-signal credential phishing boost: if message asks for credentials
    // AND has a suspicious URL but NO brand tag, boost risk.
    if has(IndicatorId::CredentialRequest).is_some()
        && !has_brand
        && has(IndicatorId::LinkSuspicious).is_some()
    {
        bucket = (bucket + 1).min(5);
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
    // BUT: if the message asks to contact someone (email/phone), it's phishing.
    if has(IndicatorId::CredentialRequest).is_some() {
        let has_contact_request = lower.contains("contact us at")
            || lower.contains("contact us immediately")
            || lower.contains("call us at")
            || lower.contains("call immediately")
            || lower.contains("reply to this number");
        if !has_contact_request && (
            lower.contains("do not share") || lower.contains("don't share")
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
        ) {
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
        // Vietnamese — specific transaction patterns only
        || lower.contains("đã được xử lý") || lower.contains("đã được ghi nhận")
        || lower.contains("đã được duyệt") || lower.contains("đã được hoàn thành")
        || lower.contains("đã được chuyển") || lower.contains("đã được kích hoạt")
        || lower.contains("đã chuyển") || lower.contains("đã thanh toán")
        || lower.contains("đã chuyển khoản")
        || lower.contains("giao dịch thành công")
        || (lower.contains("thành công") && (lower.contains("giao dịch")
            || lower.contains("thanh toán") || lower.contains("chuyển khoản")))
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
        || lower.contains("kung hindi ikaw") || lower.contains("kung hindi mo ginawa")
        || lower.contains("បើមិនមែនអ្នក"))
        && (lower.contains("call") || lower.contains("contact") || lower.contains("gọi")
            || lower.contains("hubungi") || lower.contains("โทร") || lower.contains("tumawag")
            || lower.contains("ហៅ"))
    {
        count += 1;
    }

    // Khmer anti-fraud warning
    if lower.contains("ប្រយ័ត្នការបន្លំ") || lower.contains("ការពារការលួច")
        || lower.contains("មិនបានសុំ")
    {
        count += 1;
    }

    // Khmer transaction confirmation
    if lower.contains("បានទទួលជោគជ័យ") || lower.contains("ការប្រាក់បាន")
        || lower.contains("បានផ្ញើរួច")
    {
        count += 1;
    }

    // Khmer "no action needed"
    if lower.contains("មិនត្រូវការផ្តល់") || lower.contains("គ្មានការធ្វើ")
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

/// Classify scam type from indicator hits using scored classification.
///
/// Computes a score for every scam type based on which indicators are present
/// and text keyword boosts, then returns the highest-scoring type.
/// This reduces OtherUnknown classifications by finding the best match
/// even when no single rule fires with full confidence.
pub fn classify_scam_type(indicators: &[IndicatorHit], text: &str) -> Option<ScamType> {
    if indicators.is_empty() {
        return None;
    }

    let has = |id: IndicatorId| -> bool {
        indicators.iter().any(|h| h.id == id)
    };
    let lower = text.to_lowercase();
    let tc = |n: &str| lower.contains(n);

    let mut scores: Vec<(ScamType, f32)> = Vec::new();
    let mut push = |st: ScamType, s: f32| {
        if s > 0.0 {
            scores.push((st, s));
        }
    };

    // --- Customer service scam ---
    {
        let mut s = 0.0;
        if tc("customer service") || tc("customer support") || tc("refund")
            || tc("hoàn tiền") || tc("pengembalian") || tc("คืนเงิน")
        {
            s += 1.0;
        }
        if tc("shopee") || tc("lazada") || tc("tokopedia") || tc("bukalapak")
            || tc("tiki") || tc("sendo") || tc("grab") || tc("gojek")
            || tc("carousell") || tc("qoo10") || tc("amazon") || tc("ebay")
        {
            s += 1.5;
        }
        if has(IndicatorId::LinkSuspicious) { s += 1.0; }
        if has(IndicatorId::VerificationRequest) { s += 1.0; }
        if has(IndicatorId::CredentialRequest) { s += 1.0; }
        if has(IndicatorId::FinancialRequest) { s += 0.5; }
        push(ScamType::CustomerServiceScam, s);
    }

    // --- SIM swap fraud ---
    {
        let mut s = 0.0;
        if has(IndicatorId::VerificationRequest) { s += 1.5; }
        if has(IndicatorId::ThreatAccount) { s += 1.5; }
        if tc("sim card") || tc("deactivate sim") || tc("new sim")
            || tc("port out") || tc("port-out") || tc("number transfer")
            || tc("phone number") || tc("ic number")
            || tc("thẻ sim") || tc("kartu sim")
        {
            s += 2.0;
        }
        push(ScamType::SimSwapFraud, s);
    }

    // --- Utility impersonation ---
    {
        let mut s = 0.0;
        if has(IndicatorId::AuthorityClaim) { s += 1.5; }
        if has(IndicatorId::ThreatAccount) { s += 1.0; }
        if tc("electricity") || tc("power") || tc("water bill")
            || tc("gas bill") || tc("utility") || tc("disconnect")
            || tc("disconnection") || tc("outstanding bill")
            || tc("điện") || tc("nước") || tc("listrik")
            || tc("tagihan air") || tc("pemutusan air")
            || tc("ไฟฟ้า") || tc("น้ำ")
        {
            s += 2.0;
        }
        push(ScamType::UtilityImpersonation, s);
    }

    // --- Telco impersonation ---
    {
        let mut s = 0.0;
        if has(IndicatorId::SenderAnomaly) { s += 1.5; }
        if has(IndicatorId::ThreatAccount) { s += 1.5; }
        if !has(IndicatorId::AuthorityClaim) { s += 0.5; }
        push(ScamType::TelcoImpersonation, s);
    }

    // --- Bank impersonation ---
    {
        let mut s = 0.0;
        if has(IndicatorId::AuthorityClaim) { s += 1.5; }
        if has(IndicatorId::ThreatAccount) { s += 1.5; }
        if has(IndicatorId::VerificationRequest) { s += 1.0; }
        if has(IndicatorId::SenderAnomaly) { s += 1.0; }
        if has(IndicatorId::BankTransfer) { s += 0.5; }
        push(ScamType::BankImpersonation, s);
    }

    // --- Account takeover ---
    {
        let mut s = 0.0;
        if has(IndicatorId::VerificationRequest) { s += 1.5; }
        if has(IndicatorId::ThreatAccount) { s += 1.5; }
        if has(IndicatorId::LinkSuspicious) { s += 1.0; }
        if has(IndicatorId::CredentialRequest) { s += 1.0; }
        if has(IndicatorId::AuthorityClaim) && !has(IndicatorId::VerificationRequest) {
            s += 1.0;
        }
        push(ScamType::AccountTakeover, s);
    }

    // --- Government impersonation ---
    {
        let mut s = 0.0;
        if has(IndicatorId::AuthorityClaim) { s += 1.5; }
        if has(IndicatorId::ThreatLegal) { s += 2.0; }
        if has(IndicatorId::GovernmentBenefitLure) { s += 2.5; }
        if has(IndicatorId::TaxPenalty) { s += 1.0; }
        push(ScamType::GovernmentImpersonation, s);
    }

    // --- Toll/traffic fine ---
    {
        let mut s = 0.0;
        if has(IndicatorId::TaxPenalty) { s += 2.0; }
        if has(IndicatorId::LinkSuspicious) { s += 1.0; }
        if has(IndicatorId::FinancialRequest) { s += 1.0; }
        if tc("toll") || tc("fine") || tc("summons") || tc("compound")
            || tc("erp") || tc("traffic") || tc("denda") || tc("saman")
            || tc("tilang") || tc("phạt") || tc("ค่าปรับ")
            || tc("ค่าผ่านทาง")
        {
            s += 2.0;
        }
        push(ScamType::TollFine, s);
    }

    // --- Loan scam ---
    {
        let mut s = 0.0;
        if has(IndicatorId::FinancialRequest) { s += 1.5; }
        if has(IndicatorId::PromiseHighReturn) { s += 1.0; }
        if !has(IndicatorId::CryptoScheme) { s += 0.5; }
        if tc("loan") || tc("approved") || tc("approval")
            || tc("pinjaman") || tc("lulus") || tc("vay")
            || tc("สินเชื่อ") || tc("utang")
        {
            s += 2.0;
        }
        push(ScamType::LoanScam, s);
    }

    // --- Pig butchering ---
    {
        let mut s = 0.0;
        if has(IndicatorId::RomanceGrooming) { s += 2.0; }
        if has(IndicatorId::WrongNumberPivot) { s += 1.5; }
        if has(IndicatorId::PromiseHighReturn) { s += 1.5; }
        if has(IndicatorId::CryptoScheme) { s += 1.5; }
        push(ScamType::PigButchering, s);
    }

    // --- Investment fraud ---
    {
        let mut s = 0.0;
        if has(IndicatorId::PromiseHighReturn) { s += 2.5; }
        if has(IndicatorId::CryptoScheme) { s += 2.0; }
        if has(IndicatorId::FinancialRequest) { s += 0.5; }
        push(ScamType::InvestmentFraud, s);
    }

    // --- Parcel/customs ---
    {
        let mut s = 0.0;
        if has(IndicatorId::DeliveryLure) { s += 1.5; }
        if has(IndicatorId::TaxPenalty) { s += 1.5; }
        if has(IndicatorId::FinancialRequest) { s += 1.0; }
        if tc("customs") || tc("clearance") || tc("duty") || tc("import")
            || tc("hải quan") || tc("bea cukai") || tc("kastam")
            || tc("ศุลกากร") || tc("海关")
        {
            s += 2.0;
        }
        push(ScamType::ParcelCustoms, s);
    }

    // --- Delivery scam ---
    {
        let mut s = 0.0;
        if has(IndicatorId::DeliveryLure) { s += 2.5; }
        if has(IndicatorId::LinkSuspicious) { s += 1.0; }
        push(ScamType::DeliveryScam, s);
    }

    // --- Sextortion ---
    {
        let mut s = 0.0;
        if has(IndicatorId::Sextortion) { s += 4.0; }
        if has(IndicatorId::FinancialRequest) { s += 0.5; }
        push(ScamType::Sextortion, s);
    }

    // --- Recovery scam ---
    {
        let mut s = 0.0;
        if has(IndicatorId::RecoveryScam) { s += 4.0; }
        if has(IndicatorId::FinancialRequest) { s += 0.5; }
        push(ScamType::RecoveryScam, s);
    }

    // --- Romance scam ---
    {
        let mut s = 0.0;
        if has(IndicatorId::RomanceGrooming) { s += 2.5; }
        if has(IndicatorId::FinancialRequest) { s += 1.0; }
        push(ScamType::RomanceScam, s);
    }

    // --- Money mule ---
    {
        let mut s = 0.0;
        if has(IndicatorId::JobOffer) { s += 1.5; }
        if has(IndicatorId::BankTransfer) { s += 1.0; }
        if has(IndicatorId::FinancialRequest) { s += 1.0; }
        // Use specific mule keywords, not generic "transfer"
        if tc("receive payment") || tc("forward payment")
            || tc("commission") || tc("mule") || tc("agent")
            || tc("receive funds") || tc("forward funds")
            || tc("penerima") || tc("pindah")
        {
            s += 2.0;
        }
        push(ScamType::MoneyMule, s);
    }

    // --- Job scam ---
    {
        let mut s = 0.0;
        if has(IndicatorId::JobOffer) { s += 2.5; }
        if has(IndicatorId::FinancialRequest) { s += 0.5; }
        push(ScamType::JobScam, s);
    }

    // --- Subscription trap ---
    {
        let mut s = 0.0;
        if has(IndicatorId::FreeGift) || has(IndicatorId::LimitedTimeOffer) { s += 1.5; }
        if has(IndicatorId::SubscriptionTrap) { s += 2.5; }
        if has(IndicatorId::FinancialRequest) { s += 1.0; }
        if tc("trial") || tc("subscription") || tc("recurring")
            || tc("auto-renew") || tc("monthly charge") || tc("cancel anytime")
            || tc("free trial") || tc("membership")
        {
            s += 2.0;
        }
        push(ScamType::SubscriptionTrap, s);
    }

    // --- Property rental ---
    {
        let mut s = 0.0;
        if has(IndicatorId::FinancialRequest) { s += 1.5; }
        if tc("rental") || tc("for rent") || tc("deposit") || tc("landlord")
            || tc("property") || tc("condo") || tc("apartment")
            || tc("room for rent") || tc("house for rent")
            || tc("thuê nhà") || tc("phòng cho thuê")
            || tc("sewa rumah") || tc("sewa bilik")
            || tc("เช่าบ้าน") || tc("เช่าห้อง")
            || tc("upaupa") || tc("papaupa")
        {
            s += 2.5;
        }
        push(ScamType::PropertyRental, s);
    }

    // --- Lottery/prize ---
    {
        let mut s = 0.0;
        if has(IndicatorId::PrizeLure) { s += 3.0; }
        if has(IndicatorId::FinancialRequest) { s += 0.5; }
        push(ScamType::LotteryPrize, s);
    }

    // --- Tech support ---
    {
        let mut s = 0.0;
        if has(IndicatorId::RemoteAccess) { s += 3.0; }
        if has(IndicatorId::AuthorityClaim) { s += 1.0; }
        push(ScamType::TechSupport, s);
    }

    // --- Charity scam ---
    {
        let mut s = 0.0;
        if has(IndicatorId::CharityAppeal) { s += 3.0; }
        if has(IndicatorId::FinancialRequest) { s += 0.5; }
        push(ScamType::CharityScam, s);
    }

    // --- Family emergency ---
    {
        let mut s = 0.0;
        if has(IndicatorId::FamilyEmergency) { s += 3.0; }
        if has(IndicatorId::FinancialRequest) { s += 1.0; }
        push(ScamType::FamilyEmergency, s);
    }

    // --- E-commerce fraud ---
    {
        let mut s = 0.0;
        if has(IndicatorId::FakeMarketplace) { s += 2.5; }
        if has(IndicatorId::GiftCard) { s += 2.0; }
        if has(IndicatorId::BankTransfer) { s += 0.5; }
        if has(IndicatorId::FinancialRequest) { s += 0.5; }
        push(ScamType::ECommerceFraud, s);
    }

    // --- Inheritance scam ---
    {
        let mut s = 0.0;
        if has(IndicatorId::FinancialRequest) { s += 1.5; }
        if tc("inheritance") || tc("estate of") || tc("deceased")
            || tc("next of kin") || tc("beneficiary") || tc("last will")
            || tc("living will") || tc("lawyer") || tc("solicitor")
            || tc("di sản") || tc("warisan") || tc("มรดก")
        {
            s += 2.0;
        }
        push(ScamType::InheritanceScam, s);
    }

    // --- Business email compromise ---
    {
        let mut s = 0.0;
        if has(IndicatorId::FinancialRequest) || has(IndicatorId::BankTransfer)
            || has(IndicatorId::GiftCard)
        {
            s += 1.5;
        }
        if tc("ceo") || tc("boss") || tc("manager") || tc("director")
            || tc("urgent payment") || tc("process payment") || tc("confidential")
            || tc("in a meeting") || tc("wire transfer") || tc("supplier")
            || tc("invoice")
        {
            s += 2.5;
        }
        push(ScamType::BusinessEmailCompromise, s);
    }

    // --- Fake QR code ---
    {
        let mut s = 0.0;
        if tc("qr code") || tc("scan qr") || tc("scan to pay") || tc("quishing") {
            s += 2.0;
        }
        if has(IndicatorId::QRCodeScan) { s += 2.5; }
        if has(IndicatorId::LinkSuspicious) || has(IndicatorId::FinancialRequest)
            || has(IndicatorId::CredentialRequest) || has(IndicatorId::PersonalInfoRequest)
        {
            s += 1.5;
        }
        push(ScamType::FakeQRCode, s);
    }

    // --- Social media takeover ---
    {
        let mut s = 0.0;
        if has(IndicatorId::CredentialRequest) { s += 2.5; }
        if has(IndicatorId::LinkSuspicious) { s += 1.0; }
        push(ScamType::SocialMediaTakeover, s);
    }

    // Pick the highest-scoring scam type
    if scores.is_empty() {
        return Some(ScamType::OtherUnknown);
    }

    scores.sort_by(|a, b| {
        b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal)
    });

    Some(scores[0].0)
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
