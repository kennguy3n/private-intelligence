//! Embedding-based semantic indicator detection.
//!
//! Uses zk-ai-core's e5-small model for semantic detection of indicators
//! that are difficult to capture with keywords alone (e.g., romance
//! grooming, authority claim). Falls back to embedding k-NN against
//! pre-labeled prototype texts.

use zk_ai_core::AiEngine;
use zk_ai_core::cosine_similarity;
use crate::ontology::{IndicatorId, IndicatorHit, IndicatorStrength};
use crate::channel::Channel;

/// Indicators that benefit from embedding-based detection (semantic, not keyword).
const EMBEDDING_INDICATORS: &[IndicatorId] = &[
    IndicatorId::RomanceGrooming,
    IndicatorId::AuthorityClaim,
    IndicatorId::PromiseHighReturn,
    IndicatorId::CharityAppeal,
    IndicatorId::FamilyEmergency,
];

/// Prototype texts for each embedding-based indicator.
/// These are representative examples that the input text is compared against.
fn prototype_text(indicator: IndicatorId) -> &'static str {
    match indicator {
        IndicatorId::RomanceGrooming => {
            "I have fallen in love with you after just a few days of chatting. \
             You are my soulmate. I want to visit you but I need money for flights \
             and visa fees. Can you send me money?"
        }
        IndicatorId::AuthorityClaim => {
            "This is an official call from the police department. I am a government \
             official. We are calling on behalf of the tax authority regarding your \
             outstanding tax payments."
        }
        IndicatorId::PromiseHighReturn => {
            "Join our investment group for guaranteed high returns. Professional \
             traders will manage your funds with zero risk. You can double your money \
             in just one week. Minimum investment is only $100."
        }
        IndicatorId::CharityAppeal => {
            "Urgent appeal: victims of the recent disaster urgently need your help. \
             Please donate now to provide food, water, and shelter. Every dollar \
             goes directly to helping the victims."
        }
        IndicatorId::FamilyEmergency => {
            "Mom, I'm in the hospital. I had an accident and need emergency surgery. \
             Please send money for the medical bills right away. Don't tell dad. \
             This is urgent."
        }
        _ => "",
    }
}

/// Embedding similarity threshold for indicator detection.
const SIMILARITY_THRESHOLD: f32 = 0.65;
const SIMILARITY_HIGH_THRESHOLD: f32 = 0.78;

/// Detect indicators using embedding-based semantic similarity.
///
/// This requires an AiEngine with the e5-small model loaded.
/// Returns indicator hits for any indicators whose prototype embedding
/// is similar enough to the input text embedding.
pub async fn detect_embeddings(
    engine: &mut AiEngine,
    text: &str,
    _channel: Channel,
    _language: &str,
) -> Result<Vec<IndicatorHit>, zk_ai_core::ZkAiError> {
    let text_embedding = engine.run_embedding(text).await?;
    let mut hits = Vec::new();

    for &indicator_id in EMBEDDING_INDICATORS {
        let prototype = prototype_text(indicator_id);
        if prototype.is_empty() {
            continue;
        }

        let proto_embedding = engine.run_embedding(prototype).await?;
        let score = cosine_similarity(&text_embedding, &proto_embedding);

        if score >= SIMILARITY_THRESHOLD {
            let strength = if score >= SIMILARITY_HIGH_THRESHOLD {
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

    // Sort by strength descending
    hits.sort_by(|a, b| {
        b.strength
            .weight()
            .partial_cmp(&a.strength.weight())
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    Ok(hits)
}
