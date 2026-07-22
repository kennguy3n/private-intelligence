//! Search result reranking pipeline.
//!
//! Reranks semantic search results using a cross-encoder approach with
//! e5-small. Re-scores top-N results with query-document interaction.

use crate::Result;
use crate::pipeline::{TaskOptions, TaskResult, Task};
use crate::AiEngine;
use crate::model_manager::ModelSpec;
use crate::pipeline::text_index::TextSearchHit;
use crate::pipeline::image_index::cosine_similarity;

/// Run a reranking task.
///
/// Input: query + initial search hits.
/// Output: reranked hits with improved precision.
pub async fn run(
    engine: &mut AiEngine,
    query: &str,
    hits: &[TextSearchHit],
    _options: TaskOptions,
) -> Result<TaskResult> {
    let spec = ModelSpec::e5_small_int8();
    engine.ensure_model(&spec).await?;

    let start = std::time::Instant::now();

    // Re-score each hit by embedding query+document together
    let mut reranked: Vec<(TextSearchHit, f32)> = Vec::new();

    for hit in hits {
        let combined = format!("{} {}", query, hit.text);
        let combined_emb = engine.run_embedding(&combined).await?;
        let query_emb = engine.run_embedding(query).await?;
        let doc_emb = engine.run_embedding(&hit.text).await?;

        // Cross-encoder style: similarity of (query+doc) embedding to query embedding
        let cross_score = cosine_similarity(&combined_emb, &query_emb);
        let doc_score = cosine_similarity(&query_emb, &doc_emb);

        // Blend original score with cross-encoder score
        let reranked_score = 0.5 * hit.score + 0.3 * cross_score + 0.2 * doc_score;

        reranked.push((hit.clone(), reranked_score));
    }

    reranked.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

    let output = reranked.iter()
        .enumerate()
        .map(|(rank, (hit, score))| {
            let source = hit.source.as_deref().unwrap_or(&hit.id);
            format!("{}. [reranked: {:.3}] {} — {}", rank + 1, score, source, hit.text.chars().take(100).collect::<String>())
        })
        .collect::<Vec<_>>()
        .join("\n");

    let duration_ms = start.elapsed().as_millis() as u64;

    Ok(TaskResult {
        output,
        task: Task::Rerank,
        model: "multilingual-e5-small-int8".to_string(),
        adapter: None,
        duration_ms,
        input_tokens: query.split_whitespace().count() as u32,
        output_tokens: reranked.len() as u32,
    })
}
