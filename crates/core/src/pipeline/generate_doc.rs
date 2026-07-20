//! Document generation pipeline.

use crate::Result;
use crate::pipeline::{TaskOptions, TaskResult, Task, validate_language, build_prompt};
use crate::AiEngine;
use crate::model_manager::ModelSpec;
use crate::inference::LoRAAdapter;
use super::summarize::collect_stream_result;

/// Run a document generation task.
pub async fn run(
    engine: &mut AiEngine,
    topic: &str,
    outline: &str,
    language: &str,
    options: TaskOptions,
) -> Result<TaskResult> {
    validate_language(language)?;

    let spec = ModelSpec::mt5_small_int8();
    engine.ensure_model(&spec).await?;

    let adapter_path = engine.resolve_adapter_path(
        &format!("adapters/gendoc.{}.bin", language)
    );
    let adapter = LoRAAdapter::new("gendoc", language, &adapter_path, 8);
    let adapter_id = adapter.id();

    let content = format!("Topic: {}\nOutline: {}", topic, outline);
    let prompt = build_prompt("Generate a document based on the following topic and outline", language, &content);
    let start = std::time::Instant::now();

    if options.stream {
        let rx = engine.run_inference_stream(&prompt, Some(adapter)).await?;
        return collect_stream_result(rx, Task::GenerateDoc, "mt5-small-int8", Some(adapter_id), start).await;
    }

    let infer_output = engine.run_inference(&prompt, Some(adapter)).await?;

    let duration_ms = start.elapsed().as_millis() as u64;

    Ok(TaskResult {
        output: infer_output.text,
        task: Task::GenerateDoc,
        model: "mt5-small-int8".to_string(),
        adapter: Some(adapter_id),
        duration_ms,
        input_tokens: infer_output.input_tokens,
        output_tokens: infer_output.output_tokens,
    })
}
