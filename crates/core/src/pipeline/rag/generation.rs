//! RAG answer generation.
//!
//! Generates answers from retrieved context using mT5-small + rag_qa LoRA.

use crate::Result;
use crate::pipeline::{TaskOptions, TaskResult, Task, validate_language, build_prompt};
use crate::AiEngine;
use crate::model_manager::ModelSpec;
use crate::inference::LoRAAdapter;
use crate::pipeline::text_index::TextSearchHit;
use crate::pipeline::summarize::collect_stream_result;

/// Generate an answer from retrieved context.
pub async fn generate(
    engine: &mut AiEngine,
    question: &str,
    hits: &[TextSearchHit],
    language: &str,
    options: TaskOptions,
) -> Result<TaskResult> {
    validate_language(language)?;

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

    let content = format!("Question: {}\n\nContext:\n{}", question, context);
    let prompt = build_prompt(
        "Answer the question based on the following context. Include source citations.",
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
        model: "mt5-small-int8".to_string(),
        adapter: Some(adapter_id),
        duration_ms,
        input_tokens: infer_output.input_tokens,
        output_tokens: infer_output.output_tokens,
    })
}

/// Multi-document synthesis: answer questions requiring info from multiple docs.
pub async fn generate_multi_doc(
    engine: &mut AiEngine,
    question: &str,
    hits: &[TextSearchHit],
    language: &str,
    options: TaskOptions,
) -> Result<TaskResult> {
    // Group hits by source for multi-doc synthesis
    let mut by_source: std::collections::HashMap<String, Vec<&TextSearchHit>> = std::collections::HashMap::new();
    for hit in hits {
        let source = hit.source.clone().unwrap_or("unknown".to_string());
        by_source.entry(source).or_default().push(hit);
    }

    let mut context_parts = Vec::new();
    for (source, source_hits) in &by_source {
        let texts: Vec<&str> = source_hits.iter().map(|h| h.text.as_str()).collect();
        context_parts.push(format!("[From: {}]\n{}", source, texts.join("\n")));
    }

    let context = context_parts.join("\n\n");

    let spec = ModelSpec::mt5_small_int8();
    engine.ensure_model(&spec).await?;

    let adapter_path = engine.resolve_adapter_path(
        &format!("adapters/rag_qa.{}.bin", language)
    );
    let adapter = LoRAAdapter::new("rag_qa", language, &adapter_path, 8);
    let adapter_id = adapter.id();

    let content = format!("Question: {}\n\nMulti-document context:\n{}", question, context);
    let prompt = build_prompt(
        "Synthesize an answer from multiple documents. Compare and contrast information from different sources.",
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
        model: "mt5-small-int8".to_string(),
        adapter: Some(adapter_id),
        duration_ms,
        input_tokens: infer_output.input_tokens,
        output_tokens: infer_output.output_tokens,
    })
}
