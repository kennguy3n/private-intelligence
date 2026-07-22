//! Risk scoring and bucketing.
//!
//! Combines indicator hits into a risk score, applies monotonic constraints,
//! and quantizes to 5 buckets (1=benign, 5=very likely scam).

use crate::ontology::{IndicatorHit, IndicatorId, IndicatorStrength};
use crate::channel::Channel;
use crate::detection::PredictedOutcome;
use crate::taxonomy::ScamType;

/// Compute risk bucket (1-5) from indicator hits.
///
/// Algorithm:
/// 1. Base score from weighted indicator strengths
/// 2. Interaction bonuses (e.g., urgency + financial = +1)
/// 3. Monotonic constraints (e.g., credential_request High → min bucket 4)
/// 4. Channel-specific adjustment
/// 5. Clamp to 1-5
pub fn compute_risk_bucket(
    indicators: &[IndicatorHit],
    channel: Channel,
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
    let mut bucket = match base_score {
        x if x < 0.5 => 1,
        x if x < 1.0 => 2,
        x if x < 1.8 => 3,
        x if x < 3.0 => 4,
        _ => 5,
    };

    // 2. Interaction bonuses
    let has = |id: IndicatorId| -> Option<&IndicatorHit> {
        indicators.iter().find(|h| h.id == id)
    };

    // urgency + financial_request → strong signal
    if has(IndicatorId::Urgency).is_some() && has(IndicatorId::FinancialRequest).is_some() {
        bucket = bucket.max(3).min(5);
    }

    // urgency + credential_request → very strong
    if has(IndicatorId::Urgency).is_some() && has(IndicatorId::CredentialRequest).is_some() {
        bucket = bucket.max(4).min(5);
    }

    // authority_claim + threat_legal → strong impersonation pattern
    if has(IndicatorId::AuthorityClaim).is_some() && has(IndicatorId::ThreatLegal).is_some() {
        bucket = bucket.max(3).min(5);
    }

    // authority_claim + threat_account → bank impersonation pattern
    if has(IndicatorId::AuthorityClaim).is_some() && has(IndicatorId::ThreatAccount).is_some() {
        bucket = bucket.max(3).min(5);
    }

    // promise_high_return + crypto_scheme → investment fraud pattern
    if has(IndicatorId::PromiseHighReturn).is_some() && has(IndicatorId::CryptoScheme).is_some() {
        bucket = bucket.max(3).min(5);
    }

    // delivery_lure + link_suspicious → delivery scam pattern
    if has(IndicatorId::DeliveryLure).is_some() && has(IndicatorId::LinkSuspicious).is_some() {
        bucket = bucket.max(3).min(5);
    }

    // romance_grooming + financial_request → romance scam pattern
    if has(IndicatorId::RomanceGrooming).is_some() && has(IndicatorId::FinancialRequest).is_some() {
        bucket = bucket.max(3).min(5);
    }

    // family_emergency + financial_request → family emergency scam
    if has(IndicatorId::FamilyEmergency).is_some() && has(IndicatorId::FinancialRequest).is_some() {
        bucket = bucket.max(4).min(5);
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

    // 4. Channel-specific adjustment
    // SMS and messaging are higher risk channels for scams
    bucket = match channel {
        Channel::Sms | Channel::Messaging => (bucket + 1).min(5),
        // Call channel: only boost if there are indicators present.
        // A benign call transcript with no indicators should stay at bucket 1.
        Channel::Call if !indicators.is_empty() => bucket.max(3).min(5),
        _ => bucket,
    };

    // 5. Clamp
    bucket.clamp(1, 5)
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
pub fn classify_scam_type(indicators: &[IndicatorHit]) -> Option<ScamType> {
    let has = |id: IndicatorId| -> bool {
        indicators.iter().any(|h| h.id == id)
    };

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

    // Government impersonation: authority_claim + threat_legal
    if has(IndicatorId::AuthorityClaim) && has(IndicatorId::ThreatLegal) {
        return Some(ScamType::GovernmentImpersonation);
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

    // Delivery scam: delivery_lure + link_suspicious
    if has(IndicatorId::DeliveryLure) {
        return Some(ScamType::DeliveryScam);
    }

    // Romance scam: romance_grooming + financial_request
    if has(IndicatorId::RomanceGrooming) {
        return Some(ScamType::RomanceScam);
    }

    // Job scam: job_offer
    if has(IndicatorId::JobOffer) {
        return Some(ScamType::JobScam);
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

    // Remove the unreachable telco check that was here (moved above bank check)

    // Loan scam: financial_request + promise_high_return (without crypto)
    if has(IndicatorId::FinancialRequest) && has(IndicatorId::PromiseHighReturn)
        && !has(IndicatorId::CryptoScheme)
    {
        return Some(ScamType::LoanScam);
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
