//! Image search pipeline using CLIP embeddings.
//!
//! Encodes a text query into a CLIP embedding, then compares against
//! a pre-computed vector index of image embeddings to find the most
//! relevant images for a slide.

use crate::Result;
use crate::pipeline::{TaskOptions, TaskResult, Task};
use crate::AiEngine;
use crate::model_manager::ModelSpec;
use crate::pipeline::image_index::{ImageIndex, ImageSearchHit};

/// Default number of results to return.
const DEFAULT_TOP_K: usize = 5;

/// Run an image search task.
///
/// Encodes the text query into a CLIP embedding vector, then searches
/// the provided image index for the most similar images using cosine similarity.
/// If no index is provided (empty), falls back to text-based inference.
pub async fn run(
    engine: &mut AiEngine,
    query: &str,
    options: TaskOptions,
) -> Result<TaskResult> {
    let spec = ModelSpec::clip_int8();
    engine.ensure_model(&spec).await?;

    let start = std::time::Instant::now();

    // Extract the CLIP text embedding for the query
    let query_embedding = engine.run_embedding(query).await?;

    // Try to load an image index from the cache directory
    let index_path = engine.resolve_adapter_path("image_index.json");
    let index = if index_path.exists() {
        match std::fs::read_to_string(&index_path) {
            Ok(json) => ImageIndex::from_json(&json).unwrap_or_default(),
            Err(_) => ImageIndex::new(),
        }
    } else {
        ImageIndex::new()
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
        task: Task::ImageSearch,
        model: "clip-vit-base-patch32-int8".to_string(),
        adapter: None,
        duration_ms,
        input_tokens,
        output_tokens,
    })
}

/// Format search hits as a human-readable string.
fn format_hits(hits: &[ImageSearchHit]) -> String {
    if hits.is_empty() {
        return "No matching images found.".to_string();
    }

    let mut lines = Vec::with_capacity(hits.len());
    for (rank, hit) in hits.iter().enumerate() {
        lines.push(format!(
            "{}. {} (score: {:.3}) — {}",
            rank + 1,
            hit.id,
            hit.score,
            hit.caption
        ));
    }
    lines.join("\n")
}
