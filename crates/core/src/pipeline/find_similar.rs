//! Find similar documents pipeline.
//!
//! Finds documents similar to a selected document using e5-small embeddings
//! and cosine similarity against a TextIndex. No new model required.

use crate::Result;
use crate::pipeline::{TaskOptions, TaskResult, Task};
use crate::AiEngine;
use crate::model_manager::ModelSpec;
use crate::pipeline::text_index::TextIndex;

/// Run a find-similar task.
///
/// Input: document text + TextIndex of other documents.
/// Output: top-k similar documents with similarity scores.
pub async fn run(
    engine: &mut AiEngine,
    text: &str,
    index: &TextIndex,
    top_k: usize,
    _options: TaskOptions,
) -> Result<TaskResult> {
    let spec = ModelSpec::e5_small_int8();
    engine.ensure_model(&spec).await?;

    let start = std::time::Instant::now();
    let text_embedding = engine.run_embedding(text).await?;
    let hits = index.search(&text_embedding, top_k);

    let output = if hits.is_empty() {
        "No similar documents found.".to_string()
    } else {
        hits.iter()
            .enumerate()
            .map(|(rank, hit)| {
                let source = hit.source.as_deref().unwrap_or("unknown");
                format!("{}. [score: {:.3}] {} — {}", rank + 1, hit.score, source, hit.text.chars().take(100).collect::<String>())
            })
            .collect::<Vec<_>>()
            .join("\n")
    };

    let duration_ms = start.elapsed().as_millis() as u64;

    Ok(TaskResult {
        output,
        task: Task::FindSimilar,
        model: "multilingual-e5-small-int8".to_string(),
        adapter: None,
        duration_ms,
        input_tokens: text.split_whitespace().count() as u32,
        output_tokens: hits.len() as u32,
    })
}
