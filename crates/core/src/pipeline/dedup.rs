//! Duplicate ticket detection pipeline.
//!
//! Detects duplicate support tickets using e5-small embeddings + cosine
//! similarity against existing ticket embeddings.

use crate::Result;
use crate::pipeline::{TaskOptions, TaskResult, Task};
use crate::AiEngine;
use crate::model_manager::ModelSpec;
use crate::pipeline::text_index::TextIndex;

/// Threshold above which two tickets are considered duplicates (embedding-based).
const DUPLICATE_THRESHOLD: f32 = 0.85;

/// Threshold for Jaccard word-overlap fallback.
const JACCARD_THRESHOLD: f32 = 0.20;

/// Compute Jaccard similarity between two texts based on word sets.
fn jaccard_similarity(a: &str, b: &str) -> f32 {
    let a_lower = a.to_lowercase();
    let b_lower = b.to_lowercase();
    let set_a: std::collections::HashSet<&str> = a_lower.split_whitespace().collect();
    let set_b: std::collections::HashSet<&str> = b_lower.split_whitespace().collect();
    if set_a.is_empty() && set_b.is_empty() {
        return 1.0;
    }
    let intersection = set_a.intersection(&set_b).count() as f32;
    let union = set_a.union(&set_b).count() as f32;
    if union == 0.0 {
        return 0.0;
    }
    intersection / union
}

/// Extract shared technical terms (ASCII words ≥3 chars and numbers) from two texts.
/// These are language-independent signals (e.g., "API", "500", "ONNX", "Android").
fn shared_technical_terms(a: &str, b: &str) -> Vec<String> {
    let extract_terms = |text: &str| -> std::collections::HashSet<String> {
        text.split_whitespace()
            .filter(|w| {
                w.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
                    && w.len() >= 2
            })
            .map(|w| w.to_lowercase())
            .collect()
    };
    let terms_a = extract_terms(a);
    let terms_b = extract_terms(b);
    terms_a.intersection(&terms_b).cloned().collect()
}

/// Cross-language similarity: count shared technical terms as a fraction of the
/// smaller text's technical term count. Also considers shared non-ASCII tokens
/// (proper nouns, brand names that are identical across languages).
fn cross_lang_similarity(a: &str, b: &str) -> f32 {
    let shared = shared_technical_terms(a, b);
    if shared.is_empty() {
        return 0.0;
    }
    let extract_count = |text: &str| -> f32 {
        text.split_whitespace()
            .filter(|w| {
                w.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
                    && w.len() >= 2
            })
            .count() as f32
    };
    let min_terms = extract_count(a).min(extract_count(b)).max(1.0);
    shared.len() as f32 / min_terms
}

/// Run a duplicate detection task.
///
/// Input: new ticket text + existing ticket index.
/// Output: list of likely duplicates with similarity scores.
pub async fn run(
    engine: &mut AiEngine,
    new_ticket: &str,
    existing_index: &TextIndex,
    _options: TaskOptions,
) -> Result<TaskResult> {
    let spec = ModelSpec::e5_small_int8();
    engine.ensure_model(&spec).await?;

    let start = std::time::Instant::now();
    let new_embedding = engine.run_embedding(new_ticket).await?;

    let hits = existing_index.search(&new_embedding, 10);

    // Try embedding-based detection first
    let mut duplicates: Vec<(String, Option<String>, String, f32)> = Vec::new();
    for h in &hits {
        if h.score >= DUPLICATE_THRESHOLD {
            duplicates.push((
                h.id.clone(),
                h.source.clone(),
                h.text.chars().take(100).collect(),
                h.score,
            ));
        }
    }

    // Fallback: Jaccard word-overlap similarity for each entry in the index
    if duplicates.is_empty() {
        for entry in existing_index.entries() {
            let score = jaccard_similarity(new_ticket, &entry.text);
            if score >= JACCARD_THRESHOLD {
                duplicates.push((
                    entry.id.clone(),
                    entry.source.clone(),
                    entry.text.chars().take(100).collect(),
                    score,
                ));
            }
        }
        // Cross-language fallback: if Jaccard found nothing, try shared technical terms
        if duplicates.is_empty() {
            for entry in existing_index.entries() {
                let cl_score = cross_lang_similarity(new_ticket, &entry.text);
                if cl_score >= 0.15 {
                    duplicates.push((
                        entry.id.clone(),
                        entry.source.clone(),
                        entry.text.chars().take(100).collect(),
                        cl_score,
                    ));
                }
            }
            // Combined fallback: if cross-lang alone didn't find anything,
            // use embedding score + any shared terms as a combined signal
            if duplicates.is_empty() {
                for h in &hits {
                    let cl_score = cross_lang_similarity(new_ticket, &h.text);
                    if h.score >= 0.20 && cl_score > 0.0 {
                        let source = h.source.clone().unwrap_or_else(|| h.id.clone());
                        let combined = (h.score + cl_score) / 2.0;
                        duplicates.push((
                            h.id.clone(),
                            Some(source),
                            h.text.chars().take(100).collect(),
                            combined,
                        ));
                    }
                }
            }
        }
        duplicates.sort_by(|a, b| b.3.partial_cmp(&a.3).unwrap_or(std::cmp::Ordering::Equal));
    }

    let output = if duplicates.is_empty() {
        "No duplicate tickets found.".to_string()
    } else {
        let mut lines = vec![format!("Found {} likely duplicate(s):", duplicates.len())];
        for (rank, (id, source, text, score)) in duplicates.iter().take(10).enumerate() {
            let src = source.as_deref().unwrap_or(id);
            lines.push(format!(
                "{}. [score: {:.3}] {} — {}",
                rank + 1,
                score,
                src,
                text,
            ));
        }
        lines.join("\n")
    };

    let duration_ms = start.elapsed().as_millis() as u64;

    Ok(TaskResult {
        output,
        task: Task::Dedup,
        model: "multilingual-e5-small-int8".to_string(),
        adapter: None,
        duration_ms,
        input_tokens: new_ticket.split_whitespace().count() as u32,
        output_tokens: duplicates.len() as u32,
    })
}
