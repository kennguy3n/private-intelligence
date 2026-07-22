//! Expert finder pipeline.
//!
//! Finds colleagues who authored or frequently reference a topic using
//! semantic search (e5-small) + author metadata aggregation.

use crate::Result;
use crate::pipeline::{TaskOptions, TaskResult, Task};
use crate::AiEngine;
use crate::model_manager::ModelSpec;
use crate::pipeline::text_index::TextIndex;

/// Run an expert finder task.
///
/// Input: topic query + TextIndex with source metadata (author names).
/// Output: list of colleagues ranked by topic relevance.
pub async fn run(
    engine: &mut AiEngine,
    topic: &str,
    index: &TextIndex,
    top_k: usize,
    _options: TaskOptions,
) -> Result<TaskResult> {
    let spec = ModelSpec::e5_small_int8();
    engine.ensure_model(&spec).await?;

    let start = std::time::Instant::now();
    let query_emb = engine.run_embedding(topic).await?;
    let hits = index.search(&query_emb, top_k * 3);

    // Aggregate by source (author)
    let mut author_scores: std::collections::HashMap<String, (usize, f32)> = std::collections::HashMap::new();
    for hit in &hits {
        if let Some(source) = &hit.source {
            let entry = author_scores.entry(source.clone()).or_insert((0, 0.0));
            entry.0 += 1;
            entry.1 = entry.1.max(hit.score);
        }
    }

    // Fallback: always run keyword matching as secondary signal
    {
        let topic_lower = topic.to_lowercase();
        let topic_words: std::collections::HashSet<&str> = topic_lower
            .split_whitespace()
            .filter(|w| w.len() > 2)
            .collect();

        for entry in index.entries() {
            if let Some(source) = &entry.source {
                let text_lower = entry.text.to_lowercase();
                let text_words: std::collections::HashSet<&str> = text_lower
                    .split_whitespace()
                    .filter(|w| w.len() > 2)
                    .collect();
                let overlap = topic_words.intersection(&text_words).count() as f32;
                let score = overlap / topic_words.len().max(1) as f32;
                if score > 0.1 {
                    let entry_ref = author_scores.entry(source.clone()).or_insert((0, 0.0));
                    // Only boost score with keyword overlap - don't increment count
                    // (embedding search already handles document count)
                    entry_ref.1 = entry_ref.1.max(score);
                }
            }
        }
    }

    let mut ranked: Vec<(String, usize, f32)> = author_scores
        .into_iter()
        .map(|(author, (count, best_score))| (author, count, best_score))
        .collect();
    ranked.sort_by(|a, b| {
        b.2.partial_cmp(&a.2).unwrap_or(std::cmp::Ordering::Equal)
            .then(b.1.cmp(&a.1))
    });

    let output = if ranked.is_empty() {
        "No experts found for this topic.".to_string()
    } else {
        ranked.iter()
            .take(top_k)
            .enumerate()
            .map(|(rank, (author, count, score))| {
                format!("{}. {} — {} document(s), best score: {:.3}", rank + 1, author, count, score)
            })
            .collect::<Vec<_>>()
            .join("\n")
    };

    let duration_ms = start.elapsed().as_millis() as u64;

    Ok(TaskResult {
        output,
        task: Task::FindExpert,
        model: "multilingual-e5-small-int8".to_string(),
        adapter: None,
        duration_ms,
        input_tokens: topic.split_whitespace().count() as u32,
        output_tokens: ranked.len().min(top_k) as u32,
    })
}
