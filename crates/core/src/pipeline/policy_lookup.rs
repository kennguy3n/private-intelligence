//! Policy lookup pipeline.
//!
//! Finds and summarizes company policy sections using semantic search
//! (e5-small) + summarization (mT5-small + policy LoRA).

use crate::Result;
use crate::pipeline::{TaskOptions, TaskResult, Task, validate_language, build_prompt};
use crate::AiEngine;
use crate::model_manager::ModelSpec;
use crate::inference::LoRAAdapter;
use crate::pipeline::text_index::TextIndex;
use super::summarize::collect_stream_result;

/// Run a policy lookup task.
pub async fn run(
    engine: &mut AiEngine,
    query: &str,
    index: &TextIndex,
    language: &str,
    options: TaskOptions,
) -> Result<TaskResult> {
    validate_language(language)?;

    if index.is_empty() {
        return Ok(TaskResult {
            output: "No policy documents indexed.".to_string(),
            task: Task::PolicyLookup,
            model: "none".to_string(),
            adapter: None,
            duration_ms: 0,
            input_tokens: 0,
            output_tokens: 0,
        });
    }

    // Semantic search
    let spec = ModelSpec::e5_small_int8();
    engine.ensure_model(&spec).await?;
    let query_emb = engine.run_embedding(query).await?;
    let hits = index.search(&query_emb, 3);

    // Summarize policy section
    let spec = ModelSpec::mt5_small_int8();
    engine.ensure_model(&spec).await?;

    let adapter_path = engine.resolve_adapter_path(
        &format!("adapters/policy.{}.bin", language)
    );
    let adapter = LoRAAdapter::new("policy", language, &adapter_path, 8);
    let adapter_id = adapter.id();

    let context = hits.iter()
        .map(|h| {
            let source = h.source.as_deref().unwrap_or("policy doc");
            format!("[Source: {}]\n{}", source, h.text)
        })
        .collect::<Vec<_>>()
        .join("\n\n");

    let content = format!("Policy question: {}\nRelevant policy sections:\n{}", query, context);
    let prompt = build_prompt(
        "Answer the policy question by citing the relevant policy sections",
        language,
        &content,
    );

    let start = std::time::Instant::now();

    if options.stream {
        let rx = engine.run_inference_stream(&prompt, Some(adapter)).await?;
        return collect_stream_result(rx, Task::PolicyLookup, "mt5-small-int8", Some(adapter_id), start).await;
    }

    let infer_output = engine.run_inference(&prompt, Some(adapter)).await?;
    let duration_ms = start.elapsed().as_millis() as u64;

    Ok(TaskResult {
        output: infer_output.text,
        task: Task::PolicyLookup,
        model: "multilingual-e5-small-int8+mt5-small-int8".to_string(),
        adapter: Some(adapter_id),
        duration_ms,
        input_tokens: infer_output.input_tokens,
        output_tokens: infer_output.output_tokens,
    })
}
