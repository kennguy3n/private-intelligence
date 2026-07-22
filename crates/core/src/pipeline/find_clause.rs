//! Clause search pipeline.
//!
//! Finds relevant clauses in legal documents using semantic search (e5-small).
//! No generation needed — returns matching sections with context.

use crate::Result;
use crate::pipeline::{TaskOptions, TaskResult, Task};
use crate::AiEngine;
use crate::model_manager::ModelSpec;
use crate::pipeline::text_index::TextIndex;

/// Run a clause search task.
///
/// Input: contract text + search query (e.g., "termination clause").
/// Output: relevant sections with context.
pub async fn run(
    engine: &mut AiEngine,
    contract_text: &str,
    query: &str,
    _options: TaskOptions,
) -> Result<TaskResult> {
    let spec = ModelSpec::e5_small_int8();
    engine.ensure_model(&spec).await?;

    let start = std::time::Instant::now();

    // Chunk the contract
    let chunks = chunk_text(contract_text, 500);
    let mut index = TextIndex::new();

    for (i, chunk) in chunks.iter().enumerate() {
        let emb = engine.run_embedding(chunk).await?;
        index.add_text(&format!("section_{}", i + 1), chunk, emb, Some("contract"));
    }

    // Search for relevant clauses
    let query_emb = engine.run_embedding(query).await?;
    let hits = index.search(&query_emb, 5);

    let output = if hits.is_empty() {
        "No relevant clauses found.".to_string()
    } else {
        hits.iter()
            .enumerate()
            .map(|(rank, hit)| {
                format!("{}. [score: {:.3}] {}\n", rank + 1, hit.score, hit.text)
            })
            .collect::<Vec<_>>()
            .join("\n")
    };

    let duration_ms = start.elapsed().as_millis() as u64;

    Ok(TaskResult {
        output,
        task: Task::FindClause,
        model: "multilingual-e5-small-int8".to_string(),
        adapter: None,
        duration_ms,
        input_tokens: contract_text.split_whitespace().count() as u32,
        output_tokens: hits.len() as u32,
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
