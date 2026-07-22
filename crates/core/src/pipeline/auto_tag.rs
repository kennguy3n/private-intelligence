//! Auto-tagging pipeline.
//!
//! Automatically tags documents with topics using e5-small embeddings
//! + k-NN against topic label embeddings. No new model required.

use crate::Result;
use crate::pipeline::{TaskOptions, TaskResult, Task};
use crate::AiEngine;
use crate::model_manager::ModelSpec;
use crate::pipeline::image_index::cosine_similarity;

/// Topic labels for auto-tagging.
const TOPIC_LABELS: &[(&str, &str)] = &[
    ("finance", "financial report revenue profit loss budget quarterly earnings"),
    ("legal", "contract agreement terms conditions legal obligation clause"),
    ("personal", "personal notes diary family vacation health appointment"),
    ("travel", "travel itinerary flight hotel booking vacation trip destination"),
    ("technology", "software code technical architecture API database deployment"),
    ("marketing", "marketing campaign brand strategy audience engagement content"),
    ("hr", "human resources employee onboarding policy handbook benefits"),
    ("meeting", "meeting notes agenda minutes action items decisions discussion"),
];

/// Run an auto-tagging task.
///
/// Input: document text.
/// Output: top-3 topic tags with confidence scores.
pub async fn run(
    engine: &mut AiEngine,
    text: &str,
    _options: TaskOptions,
) -> Result<TaskResult> {
    let spec = ModelSpec::e5_small_int8();
    engine.ensure_model(&spec).await?;

    let start = std::time::Instant::now();
    let text_embedding = engine.run_embedding(text).await?;

    let mut scores = Vec::new();
    for (label, example) in TOPIC_LABELS {
        let label_emb = engine.run_embedding(example).await?;
        let score = cosine_similarity(&text_embedding, &label_emb);
        scores.push((label, score));
    }

    scores.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

    let tags: Vec<String> = scores.iter()
        .take(3)
        .map(|(label, score)| format!("{} ({:.3})", label, score))
        .collect();

    let output = tags.join(", ");
    let duration_ms = start.elapsed().as_millis() as u64;

    Ok(TaskResult {
        output,
        task: Task::AutoTag,
        model: "multilingual-e5-small-int8".to_string(),
        adapter: None,
        duration_ms,
        input_tokens: text.split_whitespace().count() as u32,
        output_tokens: 3,
    })
}
