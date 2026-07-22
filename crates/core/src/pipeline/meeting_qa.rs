//! Meeting Q&A pipeline.
//!
//! Composes semantic search (e5-small) over transcript chunks with
//! summarization (mT5-small) for answer synthesis. No new model —
//! reuses existing pipelines in sequence.

use crate::Result;
use crate::pipeline::{TaskOptions, TaskResult, Task, validate_language, build_prompt};
use crate::AiEngine;
use crate::model_manager::ModelSpec;
use crate::inference::LoRAAdapter;
use crate::pipeline::text_index::TextIndex;
use super::summarize::collect_stream_result;

/// Run a meeting Q&A task.
///
/// Input: meeting transcript + user question.
/// Output: answer synthesized from relevant transcript sections.
pub async fn run(
    engine: &mut AiEngine,
    transcript: &str,
    question: &str,
    language: &str,
    options: TaskOptions,
) -> Result<TaskResult> {
    validate_language(language)?;

    // Step 1: Chunk the transcript and embed with e5-small
    let spec = ModelSpec::e5_small_int8();
    engine.ensure_model(&spec).await?;

    let chunks = chunk_text(transcript, 500);
    let mut index = TextIndex::new();

    for (i, chunk) in chunks.iter().enumerate() {
        let emb = engine.run_embedding(chunk).await?;
        index.add_text(&format!("chunk_{}", i), chunk, emb, Some("transcript"));
    }

    // Step 2: Semantic search for relevant chunks
    let query_emb = engine.run_embedding(question).await?;
    let hits = index.search(&query_emb, 3);

    // Step 3: Synthesize answer with mT5-small
    let spec = ModelSpec::mt5_small_int8();
    engine.ensure_model(&spec).await?;

    let adapter_path = engine.resolve_adapter_path(
        &format!("adapters/rag_qa.{}.bin", language)
    );
    let adapter = LoRAAdapter::new("rag_qa", language, &adapter_path, 8);
    let adapter_id = adapter.id();

    let context = hits.iter()
        .map(|h| h.text.as_str())
        .collect::<Vec<_>>()
        .join("\n\n");

    let content = format!("Question: {}\nContext:\n{}", question, context);
    let prompt = build_prompt(
        "Answer the question based on the following meeting context",
        language,
        &content,
    );

    let start = std::time::Instant::now();

    if options.stream {
        let rx = engine.run_inference_stream(&prompt, Some(adapter)).await?;
        return collect_stream_result(rx, Task::MeetingQa, "mt5-small-int8", Some(adapter_id), start).await;
    }

    let infer_output = engine.run_inference(&prompt, Some(adapter)).await?;
    let duration_ms = start.elapsed().as_millis() as u64;

    Ok(TaskResult {
        output: infer_output.text,
        task: Task::MeetingQa,
        model: "multilingual-e5-small-int8+mt5-small-int8".to_string(),
        adapter: Some(adapter_id),
        duration_ms,
        input_tokens: infer_output.input_tokens,
        output_tokens: infer_output.output_tokens,
    })
}

/// Split text into overlapping chunks of approximately `target_len` characters.
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
        // Try to break at a sentence boundary
        let mut break_point = end;
        if break_point < text.len() {
            let half = start + target_len / 2;
            let half = text.char_indices().take_while(|(i, _)| *i < half).last().map(|(i, _)| i).unwrap_or(start);
            for (i, _) in text[half..end].char_indices().rev() {
                let abs_i = half + i;
                if text.as_bytes().get(abs_i) == Some(&b'.') || text.as_bytes().get(abs_i) == Some(&b'\n') {
                    break_point = abs_i + 1;
                    break;
                }
            }
        }
        chunks.push(text[start..break_point].to_string());
        start = break_point;
    }

    chunks
}
