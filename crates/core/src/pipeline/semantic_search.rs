//! Semantic search pipeline using e5-small embeddings.
//!
//! Encodes a text query into an e5-small embedding, then compares against
//! a pre-computed vector index of text passage embeddings to find the most
//! semantically relevant passages.

use crate::Result;
use crate::pipeline::{TaskOptions, TaskResult, Task};
use crate::AiEngine;
use crate::model_manager::ModelSpec;
use crate::pipeline::text_index::{TextIndex, TextSearchHit};

/// Default number of results to return.
const DEFAULT_TOP_K: usize = 5;

/// Run a semantic search task.
///
/// Encodes the text query into an e5-small embedding vector, then searches
/// the provided text index for the most semantically similar passages using
/// cosine similarity. If no index is provided (empty), falls back to text-based
/// inference.
pub async fn run(
    engine: &mut AiEngine,
    query: &str,
    options: TaskOptions,
) -> Result<TaskResult> {
    let spec = ModelSpec::e5_small_int8();
    engine.ensure_model(&spec).await?;

    let start = std::time::Instant::now();

    // Extract the e5-small text embedding for the query
    let query_embedding = engine.run_embedding(query).await?;

    // Try to load a text index from the cache directory
    let index_path = engine.resolve_adapter_path("text_index.json");
    let index = if index_path.exists() {
        match std::fs::read_to_string(&index_path) {
            Ok(json) => TextIndex::from_json(&json).unwrap_or_default(),
            Err(_) => TextIndex::new(),
        }
    } else {
        TextIndex::new()
    };

    let top_k = options
        .extra
        .get("top_k")
        .and_then(|v| v.as_u64())
        .map(|v| v as usize)
        .unwrap_or(DEFAULT_TOP_K);

    let (output_text, output_tokens, input_tokens) = if index.is_empty() {
        // No index available — fall back to text inference
        let infer_output = engine.run_inference(query, None).await?;
        (infer_output.text, infer_output.output_tokens, infer_output.input_tokens)
    } else {
        let hits = index.search(&query_embedding, top_k);
        let formatted = format_hits(&hits);
        (formatted, hits.len() as u32, 0u32)
    };

    let duration_ms = start.elapsed().as_millis() as u64;

    Ok(TaskResult {
        output: output_text,
        task: Task::SemanticSearch,
        model: "multilingual-e5-small-int8".to_string(),
        adapter: None,
        duration_ms,
        input_tokens,
        output_tokens,
    })
}

/// Format search hits as a human-readable string.
fn format_hits(hits: &[TextSearchHit]) -> String {
    if hits.is_empty() {
        return "No matching passages found.".to_string();
    }

    let mut lines = Vec::with_capacity(hits.len());
    for (rank, hit) in hits.iter().enumerate() {
        let source_str = hit
            .source
            .as_ref()
            .map(|s| format!(" — {s}"))
            .unwrap_or_default();
        lines.push(format!(
            "{}. [score: {:.3}] {}{}",
            rank + 1,
            hit.score,
            hit.text,
            source_str
        ));
    }
    lines.join("\n")
}
