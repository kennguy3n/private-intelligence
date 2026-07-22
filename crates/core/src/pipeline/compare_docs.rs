//! Document comparison pipeline.
//!
//! Compares two documents by computing chunk-level similarity matrix
//! with e5-small, then generating a difference summary with mT5-small.

use crate::Result;
use crate::pipeline::{TaskOptions, TaskResult, Task, validate_language, build_prompt};
use crate::AiEngine;
use crate::model_manager::ModelSpec;
use crate::pipeline::image_index::cosine_similarity;

/// Run a document comparison task.
///
/// Input: two document texts.
/// Output: summary of key differences.
pub async fn run(
    engine: &mut AiEngine,
    doc_a: &str,
    doc_b: &str,
    language: &str,
    _options: TaskOptions,
) -> Result<TaskResult> {
    validate_language(language)?;

    // Step 1: Embed both docs with e5-small
    let spec = ModelSpec::e5_small_int8();
    engine.ensure_model(&spec).await?;

    let start = std::time::Instant::now();

    let chunks_a = chunk_text(doc_a, 500);
    let chunks_b = chunk_text(doc_b, 500);

    // Pre-compute all embeddings once to avoid O(n²) inference calls
    let mut embeddings_a = Vec::with_capacity(chunks_a.len());
    for chunk in &chunks_a {
        embeddings_a.push(engine.run_embedding(chunk).await?);
    }
    let mut embeddings_b = Vec::with_capacity(chunks_b.len());
    for chunk in &chunks_b {
        embeddings_b.push(engine.run_embedding(chunk).await?);
    }

    // Compute chunk-level similarity using pre-computed embeddings
    let mut differences = Vec::new();
    for (i, emb_a) in embeddings_a.iter().enumerate() {
        let mut best_sim = 0.0f32;
        let mut best_j = 0;
        for (j, emb_b) in embeddings_b.iter().enumerate() {
            let sim = cosine_similarity(emb_a, emb_b);
            if sim > best_sim {
                best_sim = sim;
                best_j = j;
            }
        }
        if best_sim < 0.7 {
            differences.push(format!(
                "Section {} of doc A differs from section {} of doc B (similarity: {:.2})",
                i + 1, best_j + 1, best_sim,
            ));
        }
    }

    // Step 2: Generate difference summary with mT5-small
    let spec = ModelSpec::mt5_small_int8();
    engine.ensure_model(&spec).await?;

    let diff_text = if differences.is_empty() {
        "The documents are highly similar with no significant differences found.".to_string()
    } else {
        differences.join("\n")
    };

    let prompt = build_prompt(
        "Summarize the key differences between the two documents based on the following analysis",
        language,
        &diff_text,
    );

    let infer_output = engine.run_inference(&prompt, None).await?;
    let duration_ms = start.elapsed().as_millis() as u64;

    Ok(TaskResult {
        output: infer_output.text,
        task: Task::CompareDocs,
        model: "multilingual-e5-small-int8+mt5-small-int8".to_string(),
        adapter: None,
        duration_ms,
        input_tokens: infer_output.input_tokens,
        output_tokens: infer_output.output_tokens,
    })
}

fn chunk_text(text: &str, target_len: usize) -> Vec<String> {
    if text.len() <= target_len {
        return vec![text.to_string()];
    }
    let mut chunks = Vec::new();
    let mut start = 0;
    while start < text.len() {
        let mut end = (start + target_len).min(text.len());
        while end < text.len() && !text.is_char_boundary(end) {
            end -= 1;
        }
        if end == start {
            end = text.len();
        }
        chunks.push(text[start..end].to_string());
        start = end;
    }
    chunks
}
