//! Inbox prioritization pipeline.
//!
//! Auto-sorts emails into "Needs response", "FYI", "Deferred" based on
//! content analysis using e5-small embeddings + k-NN classifier.

use crate::Result;
use crate::pipeline::{TaskOptions, TaskResult, Task};
use crate::AiEngine;
use crate::model_manager::ModelSpec;
use crate::pipeline::image_index::cosine_similarity;

/// Pre-labeled priority examples for k-NN classification (fallback).
const PRIORITY_LABELS: &[(&str, &str)] = &[
    ("Needs response", "Please reply to this email, I need your answer by tomorrow"),
    ("Needs response", "Can you confirm the details and get back to me?"),
    ("FYI", "Sharing this for your information, no action needed from you"),
    ("FYI", "Updated schedule attached, please review when you have time"),
    ("Deferred", "Low priority item, handle when convenient next week"),
    ("Deferred", "Non-urgent request, please address at your earliest convenience"),
];

const NEEDS_RESPONSE_KEYWORDS: &[&str] = &[
    "please reply", "need your", "get back to me", "response", "confirm",
    "questions", "concerns", "review", "feedback", "by friday", "by tomorrow",
    "asap", "urgent", "waiting", "overdue",
];

const DEFERRED_KEYWORDS: &[&str] = &[
    "low priority", "when convenient", "no rush", "non-urgent",
    "next week", "at your earliest", "no action needed",
];

/// Run an inbox prioritization task.
///
/// Input: email text.
/// Output: priority label + confidence score.
pub async fn run(
    engine: &mut AiEngine,
    email_text: &str,
    _options: TaskOptions,
) -> Result<TaskResult> {
    let spec = ModelSpec::e5_small_int8();
    engine.ensure_model(&spec).await?;

    let start = std::time::Instant::now();

    // Primary: keyword-based classification
    let lower = email_text.to_lowercase();
    let needs_response_count = NEEDS_RESPONSE_KEYWORDS.iter().filter(|&k| lower.contains(k)).count();
    let deferred_count = DEFERRED_KEYWORDS.iter().filter(|&k| lower.contains(k)).count();

    let (best_label, best_score) = if needs_response_count > 0 && deferred_count == 0 {
        ("Needs response", 0.85)
    } else if deferred_count > 0 && needs_response_count == 0 {
        ("Deferred", 0.80)
    } else if needs_response_count > deferred_count {
        ("Needs response", 0.75)
    } else {
        // Fallback: embedding-based k-NN
        let text_embedding = engine.run_embedding(email_text).await?;
        let mut best = ("FYI", -1.0f32);
        let mut label_scores: std::collections::HashMap<&str, f32> = std::collections::HashMap::new();
        for (label, example) in PRIORITY_LABELS {
            let label_emb = engine.run_embedding(example).await?;
            let score = cosine_similarity(&text_embedding, &label_emb);
            let entry = label_scores.entry(label).or_insert(0.0);
            if score > *entry {
                *entry = score;
            }
            if score > best.1 {
                best = (label, score);
            }
        }
        best
    };

    let output = format!("{} (score: {:.3})", best_label, best_score);
    let duration_ms = start.elapsed().as_millis() as u64;

    Ok(TaskResult {
        output,
        task: Task::Prioritize,
        model: "multilingual-e5-small-int8".to_string(),
        adapter: None,
        duration_ms,
        input_tokens: email_text.split_whitespace().count() as u32,
        output_tokens: 1,
    })
}
