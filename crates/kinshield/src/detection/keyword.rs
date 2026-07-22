//! Keyword-based indicator detection.
//!
//! Uses zk-ai-core's `keyword_match` and `count_keyword_matches` functions
//! for multi-language keyword matching across all 25 indicators.

use zk_ai_core::{keyword_match, count_keyword_matches};
use crate::ontology::{IndicatorId, IndicatorHit, IndicatorStrength};
use crate::channel::Channel;

/// Detect indicators using keyword matching.
///
/// Scans text against all 25 indicators' keyword sets for the given language.
/// Falls back to all-language keywords if the primary language finds nothing.
///
/// Returns a vector of indicator hits sorted by strength (highest first).
pub fn detect_keywords(text: &str, channel: Channel, language: &str) -> Vec<IndicatorHit> {
    let lower = text.to_lowercase();
    let mut hits = Vec::new();

    for &indicator_id in IndicatorId::all() {
        let keywords = indicator_id.keywords();
        let lang_keywords = keywords.for_language(language);

        // Try primary language first
        let count = count_keyword_matches(&lower, lang_keywords);

        // If no matches in primary language, try all languages
        let (count, used_all) = if count == 0 {
            let all_kw = keywords.all_keywords();
            let all_count = count_keyword_matches(&lower, &all_kw);
            (all_count, true)
        } else {
            (count, false)
        };

        if count == 0 {
            continue;
        }

        // Determine strength based on match count and channel
        let strength = compute_strength(indicator_id, count, channel, used_all);

        hits.push(IndicatorHit {
            id: indicator_id,
            strength,
            match_count: count,
        });
    }

    // Sort by strength weight descending
    hits.sort_by(|a, b| {
        b.strength.weight()
            .partial_cmp(&a.strength.weight())
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    hits
}

/// Compute indicator strength from match count, channel, and language coverage.
fn compute_strength(
    indicator: IndicatorId,
    match_count: usize,
    _channel: Channel,
    used_all_languages: bool,
) -> IndicatorStrength {
    // High-value indicators get boosted
    let base = if indicator.is_high_value() { 1 } else { 0 };

    // Multiple keyword matches → higher strength
    let score = match_count + base;

    // If we only detected via all-language fallback, reduce confidence
    let score = if used_all_languages { score.saturating_sub(1) } else { score };

    match score {
        0 => IndicatorStrength::Low,
        1 => IndicatorStrength::Medium,
        _ => IndicatorStrength::High,
    }
}

/// Check if a specific indicator is present in the text (binary check).
pub fn has_indicator(text: &str, indicator: IndicatorId, language: &str) -> bool {
    let lower = text.to_lowercase();
    let keywords = indicator.keywords();
    let lang_kw = keywords.for_language(language);

    if lang_kw.iter().any(|&k| keyword_match(&lower, k)) {
        return true;
    }

    // Fallback: all languages
    let all_kw = keywords.all_keywords();
    all_kw.iter().any(|&k| keyword_match(&lower, k))
}
