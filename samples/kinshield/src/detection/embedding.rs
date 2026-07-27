//! Embedding-based semantic indicator detection.
//!
//! Uses zk-ai-core's e5-small model for semantic detection of indicators
//! that are difficult to capture with keywords alone (e.g., romance
//! grooming, authority claim). Uses multi-prototype k-NN with per-indicator
//! thresholds for broad semantic coverage.

use zk_ai_core::AiEngine;
use zk_ai_core::cosine_similarity;
use crate::ontology::{IndicatorId, IndicatorHit, IndicatorStrength};
use crate::channel::Channel;
use std::collections::HashMap;

/// Per-indicator embedding configuration.
struct EmbeddingConfig {
    threshold: f32,
    high_threshold: f32,
    prototypes: &'static [&'static str],
}

fn embedding_config(indicator: IndicatorId) -> Option<EmbeddingConfig> {
    let (threshold, high_threshold, prototypes) = match indicator {
        IndicatorId::RomanceGrooming => (0.88, 0.92, &[
            "I have fallen in love with you after just a few days of chatting. You are my soulmate. I want to visit you but I need money for flights and visa fees. Can you send me money?",
            "We met on the dating app and I feel a deep connection with you. Fate brought us together. I want to meet you in person but I need help with travel expenses. Can you send money for the flight?",
            "You are the most wonderful person I've ever met online. We are meant to be together. I'm working on an oil rig and can't access my bank. Can you help me with some money until I get back?",
            "My darling, I've never felt this way about anyone. I want to come visit you but my funds are frozen. If you could help with the visa fee and flight, I'll pay you back when we meet.",
        ][..]),

        IndicatorId::AuthorityClaim => (0.88, 0.92, &[
            "This is an official call from the police department. I am a government official. We are calling on behalf of the tax authority regarding your outstanding tax payments.",
            "Hello, this is officer Tan from the Singapore Police Force. We are investigating a case involving your bank account. You need to cooperate with our investigation immediately.",
            "This is the immigration department calling. There is an issue with your visa status. You need to transfer funds to a safe account for verification purposes.",
            "I am calling from the anti-money laundering unit. Your identity has been linked to a criminal case. You must follow our instructions to clear your name.",
        ][..]),

        IndicatorId::PromiseHighReturn => (0.89, 0.93, &[
            "Join our investment group for guaranteed high returns. Professional traders will manage your funds with zero risk. You can double your money in just one week. Minimum investment is only $100.",
            "Earn 50% APY on your Bitcoin through our staking platform. Zero risk, guaranteed returns. Join our Telegram group to start earning passive income from crypto today.",
            "Pre-IPO shares available for exclusive allocation. 3x returns expected within 6 months. Pool funds with our investment club for access. Capital protection guaranteed.",
            "Make 20% annual returns with our forex automated trading system. No experience needed. Professional traders manage everything. Withdraw your profits anytime.",
            "Real estate investment opportunity with 15% guaranteed yield. Limited units available. Invest now for passive income. No risk, capital fully protected.",
        ][..]),

        IndicatorId::CharityAppeal => (0.88, 0.92, &[
            "Urgent appeal: victims of the recent disaster urgently need your help. Please donate now to provide food, water, and shelter. Every dollar goes directly to helping the victims.",
            "We are raising funds for orphaned children. Your donation can provide meals and education. Please send money via bank transfer or gift cards to help these children in need.",
        ][..]),

        IndicatorId::FamilyEmergency => (0.89, 0.93, &[
            "Mom, I'm in the hospital. I had an accident and need emergency surgery. Please send money for the medical bills right away. Don't tell dad. This is urgent.",
            "Dad, your son has been in a car accident. He needs surgery immediately. Please send $5000 to this hospital account right now. Don't call back, just send the money.",
            "Grandma, I'm in trouble. I got arrested and need bail money. Please don't tell mom. Send money through Western Union right away. I'm using a friend's phone.",
        ][..]),

        IndicatorId::JobOffer => (0.88, 0.92, &[
            "We saw your LinkedIn profile and would like to offer you a data annotation role. Work from home, flexible hours, $200 per review. No experience needed. Apply now, limited positions available.",
            "Hiring remote product reviewers. Earn $500/day by completing simple tasks. No formal requirements. Commission-based with high salary. Contact us on WhatsApp to start.",
            "Easy work from home job! Earn money by clicking ads and completing surveys. Part-time, no experience needed. Pay a small registration fee to get started. High salary guaranteed.",
        ][..]),

        IndicatorId::DeliveryLure => (0.88, 0.92, &[
            "Your package could not be delivered. Click here to reschedule delivery or update your address. A small redelivery fee applies.",
            "Your parcel is being held at our facility. Please pay the customs clearance fee to release your package for final delivery.",
            "Your international package is held at customs. Pay the customs duty fee to release your package. Click here to pay and arrange delivery.",
            "Your parcel could not be delivered due to incomplete address. Please update your delivery details and pay the redelivery fee. Track your package here.",
        ][..]),

        IndicatorId::PrizeLure => (0.88, 0.92, &[
            "Congratulations! You've won $50,000 in our international lottery. Pay the processing fee to claim your prize. Respond within 24 hours.",
            "You've accumulated enough points to redeem a cashback reward. Claim your reward now at our portal. Limited time offer, expires today.",
            "You have been selected as our lucky winner for this month's draw. Click here to claim your free gift and cashback reward.",
        ][..]),

        IndicatorId::Sextortion => (0.88, 0.93, &[
            "We have recorded you through your device camera. We have sensitive video footage of you. Pay $2000 in Bitcoin to prevent us from sharing these videos with your contacts.",
            "I hacked your camera and have explicit photos of you. I will send these to your family and friends unless you pay. Send money to this Bitcoin wallet within 48 hours.",
            "We installed spyware on your device and captured your screen while you were watching adult content. Pay to delete the footage, otherwise we will publish it online.",
            "We have your private photos and browsing history. Send $1000 in Bitcoin or we will share these with your contacts and family. You have 24 hours to comply.",
        ][..]),

        IndicatorId::RecoveryScam => (0.88, 0.92, &[
            "We are a funds recovery service. We can help you get back the money you lost to a scam. Our recovery team has already traced your stolen funds. Pay a small fee to initiate the recovery process.",
            "Have you been scammed? Our asset recovery team can help you reclaim your lost funds. We have successfully recovered millions for scam victims. Contact us to start the recovery process.",
            "We are from the cybercrime recovery division. Your case has been reviewed and we can help you get your money back. Pay the tracing fee and we will recover your stolen funds within 7 days.",
        ][..]),

        IndicatorId::GovernmentBenefitLure => (0.88, 0.92, &[
            "You qualify for the ComCare assistance scheme. You are eligible for a government payout of $3000. Click here to claim your financial aid before the deadline.",
            "Good news! You are pre-approved for the Enhanced Housing Grant. Claim your government subsidy now. Reply with your details to receive the payout.",
            "You have been selected to receive a government relief fund payment. Claim your cash payout now. This is a cost of living support payment from the government.",
        ][..]),

        IndicatorId::FakeMarketplace => (0.88, 0.92, &[
            "iPhone 15 Pro Max, brand new sealed in box. Retail price $1899, selling for only $500. Limited stock available. Authentic guaranteed. Contact me to buy now.",
            "Brand new Samsung Galaxy S24 Ultra, factory sealed. Below retail price at $400 only. Unopened, original brand. Wholesale price. First come first served, limited stock.",
        ][..]),

        IndicatorId::ThreatLegal => (0.88, 0.92, &[
            "This is a final legal notice. You will be arrested and face criminal charges if you do not respond immediately. A warrant has been issued for your arrest. Contact us now to resolve this matter.",
        ][..]),

        IndicatorId::ThreatAccount => (0.88, 0.92, &[
            "Your account has been suspended due to suspicious activity. Your account will be permanently closed in 24 hours unless you verify your identity immediately. Click here to reactivate.",
        ][..]),

        IndicatorId::VerificationRequest => (0.88, 0.92, &[
            "Verify your identity to secure your account. Your account has been flagged for unusual activity. Confirm your details at our secure portal to prevent permanent suspension.",
            "Your account has been deactivated for security reasons. Reactivate now to avoid permanent loss of access. Click here to verify your identity and restore your account.",
            "We detected unauthorized access to your account. Your account is temporarily locked. Please verify your identity to unlock and restore access to your account.",
        ][..]),

        IndicatorId::TaxPenalty => (0.88, 0.92, &[
            "You have an unpaid toll fine on the expressway. Settle the outstanding amount immediately to avoid additional penalties or legal action. Click here to pay now.",
            "You have an outstanding traffic summons. Pay the compound fine before the deadline to avoid court action. Settle your violation penalty now through our online portal.",
            "Your ERP charges are overdue. Pay the outstanding road toll amount immediately to avoid enforcement action. Click the link to settle your toll fees online.",
        ][..]),

        IndicatorId::FinancialRequest => (0.88, 0.92, &[
            "Your loan has been approved! Get $5,000 instantly with no collateral needed. Just pay the processing fee upfront to release the funds. Low interest, flexible repayment.",
            "Easy loan approval with no credit check. Get cash fast with minimal documentation. Pay the administrative fee to release your loan amount today.",
        ][..]),

        _ => return None,
    };

    Some(EmbeddingConfig { threshold, high_threshold, prototypes })
}

/// All indicators that have embedding prototypes configured.
const EMBEDDING_INDICATORS: &[IndicatorId] = &[
    IndicatorId::RomanceGrooming,
    IndicatorId::AuthorityClaim,
    IndicatorId::PromiseHighReturn,
    IndicatorId::CharityAppeal,
    IndicatorId::FamilyEmergency,
    IndicatorId::JobOffer,
    IndicatorId::DeliveryLure,
    IndicatorId::PrizeLure,
    IndicatorId::Sextortion,
    IndicatorId::RecoveryScam,
    IndicatorId::GovernmentBenefitLure,
    IndicatorId::FakeMarketplace,
    IndicatorId::ThreatLegal,
    IndicatorId::ThreatAccount,
    IndicatorId::VerificationRequest,
    IndicatorId::TaxPenalty,
    IndicatorId::FinancialRequest,
];

/// Pre-compute embedding vectors for all prototype texts across all indicators.
///
/// Should be called once when the embedding model is first loaded.
/// Returns a map from indicator ID to a list of embedding vectors (one per prototype).
pub async fn precompute_prototype_cache(
    engine: &mut AiEngine,
) -> Result<HashMap<IndicatorId, Vec<Vec<f32>>>, zk_ai_core::ZkAiError> {
    let mut cache = HashMap::new();

    for &indicator_id in EMBEDDING_INDICATORS {
        let config = match embedding_config(indicator_id) {
            Some(c) => c,
            None => continue,
        };

        let mut proto_embeddings = Vec::with_capacity(config.prototypes.len());
        for &prototype in config.prototypes {
            let prefixed = format!("query: {}", prototype);
            let emb = engine.run_embedding(&prefixed).await?;
            proto_embeddings.push(emb);
        }
        cache.insert(indicator_id, proto_embeddings);
    }

    Ok(cache)
}

/// Detect indicators using embedding-based semantic similarity.
///
/// Uses multi-prototype matching: takes the max similarity across all
/// pre-computed prototype embeddings for an indicator. Per-indicator
/// thresholds allow broader patterns (AuthorityClaim) to fire at lower
/// thresholds while specific patterns (FamilyEmergency) require higher
/// similarity.
///
/// Only one embedding inference call is made per message (for the input text).
/// Prototype embeddings are pre-computed by `precompute_prototype_cache`.
pub async fn detect_embeddings(
    engine: &mut AiEngine,
    prototype_cache: &HashMap<IndicatorId, Vec<Vec<f32>>>,
    text: &str,
    _channel: Channel,
    _language: &str,
) -> Result<Vec<IndicatorHit>, zk_ai_core::ZkAiError> {
    let prefixed_text = format!("query: {}", text);
    let text_embedding = engine.run_embedding(&prefixed_text).await?;
    let mut hits = Vec::new();

    for &indicator_id in EMBEDDING_INDICATORS {
        let config = match embedding_config(indicator_id) {
            Some(c) => c,
            None => continue,
        };

        let proto_embeddings = match prototype_cache.get(&indicator_id) {
            Some(embs) => embs,
            None => continue,
        };

        let mut best_score = 0.0f32;

        for proto_emb in proto_embeddings {
            let score = cosine_similarity(&text_embedding, proto_emb);
            if score > best_score {
                best_score = score;
            }
        }

        if best_score >= config.threshold {
            let strength = if best_score >= config.high_threshold {
                IndicatorStrength::High
            } else {
                IndicatorStrength::Medium
            };
            hits.push(IndicatorHit {
                id: indicator_id,
                strength,
                match_count: 1,
            });
        }
    }

    hits.sort_by(|a, b| {
        b.strength.weight().partial_cmp(&a.strength.weight()).unwrap_or(std::cmp::Ordering::Equal)
    });

    Ok(hits)
}
