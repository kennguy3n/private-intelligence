//! Lightweight RAG Q&A pipeline.
//!
//! Composes semantic search (e5-small) with answer synthesis (mT5-small
//! + rag_qa LoRA) to answer questions about local documents.

use crate::Result;
use crate::pipeline::{TaskOptions, TaskResult, Task, validate_language, build_prompt};
use crate::AiEngine;
use crate::model_manager::ModelSpec;
use crate::inference::LoRAAdapter;
use crate::pipeline::text_index::TextIndex;
use super::summarize::collect_stream_result;

/// Run a Q&A task over a local document index.
///
/// Input: question + pre-built TextIndex.
/// Output: answer synthesized from relevant document chunks.
pub async fn run(
    engine: &mut AiEngine,
    question: &str,
    index: &TextIndex,
    language: &str,
    options: TaskOptions,
) -> Result<TaskResult> {
    validate_language(language)?;

    if index.is_empty() {
        return Ok(TaskResult {
            output: "No documents indexed. Please index some documents first.".to_string(),
            task: Task::Qa,
            model: "none".to_string(),
            adapter: None,
            duration_ms: 0,
            input_tokens: 0,
            output_tokens: 0,
        });
    }

    // Step 1: Semantic search for relevant chunks
    let spec = ModelSpec::e5_small_int8();
    engine.ensure_model(&spec).await?;

    let query_emb = engine.run_embedding(question).await?;
    let hits = index.search(&query_emb, 5);

    // Step 2: Synthesize answer with mT5-small
    let spec = ModelSpec::mt5_small_int8();
    engine.ensure_model(&spec).await?;

    let adapter_path = engine.resolve_adapter_path(
        &format!("adapters/rag_qa.{}.bin", language)
    );
    let adapter = LoRAAdapter::new("rag_qa", language, &adapter_path, 8);
    let adapter_id = adapter.id();

    let context = hits.iter()
        .map(|h| {
            let source = h.source.as_deref().unwrap_or("unknown");
            format!("[Source: {}]\n{}", source, h.text)
        })
        .collect::<Vec<_>>()
        .join("\n\n");

    let content = format!("Question: {}\n\nRelevant context:\n{}", question, context);
    let prompt = build_prompt(
        "Answer the question based on the following context. Cite sources.",
        language,
        &content,
    );

    let start = std::time::Instant::now();

    if options.stream {
        let rx = engine.run_inference_stream(&prompt, Some(adapter)).await?;
        return collect_stream_result(rx, Task::Qa, "mt5-small-int8", Some(adapter_id), start).await;
    }

    let infer_output = engine.run_inference(&prompt, Some(adapter)).await?;
    let duration_ms = start.elapsed().as_millis() as u64;

    Ok(TaskResult {
        output: infer_output.text,
        task: Task::Qa,
        model: "multilingual-e5-small-int8+mt5-small-int8".to_string(),
        adapter: Some(adapter_id),
        duration_ms,
        input_tokens: infer_output.input_tokens,
        output_tokens: infer_output.output_tokens,
    })
}
