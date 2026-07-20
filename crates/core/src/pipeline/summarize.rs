//! Summarization pipeline.

use crate::Result;
use crate::pipeline::{TaskOptions, TaskResult, Task, validate_language, build_prompt};
use crate::AiEngine;
use crate::model_manager::ModelSpec;
use crate::inference::LoRAAdapter;

/// Run a summarization task.
pub async fn run(
    engine: &mut AiEngine,
    text: &str,
    language: &str,
    options: TaskOptions,
) -> Result<TaskResult> {
    validate_language(language)?;

    let spec = ModelSpec::mt5_small_int8();
    engine.ensure_model(&spec).await?;

    let adapter_path = engine.resolve_adapter_path(
        &format!("adapters/summarize.{}.bin", language)
    );
    let adapter = LoRAAdapter::new("summarize", language, &adapter_path, 8);
    let adapter_id = adapter.id();

    let prompt = build_prompt("Summarize the following text concisely", language, text);
    let start = std::time::Instant::now();

    if options.stream {
        let rx = engine.run_inference_stream(&prompt, Some(adapter)).await?;
        return collect_stream_result(rx, Task::Summarize, "mt5-small-int8", Some(adapter_id), start).await;
    }

    let infer_output = engine.run_inference(&prompt, Some(adapter)).await?;
    let duration_ms = start.elapsed().as_millis() as u64;

    Ok(TaskResult {
        output: infer_output.text,
        task: Task::Summarize,
        model: "mt5-small-int8".to_string(),
        adapter: Some(adapter_id),
        duration_ms,
        input_tokens: infer_output.input_tokens,
        output_tokens: infer_output.output_tokens,
    })
}

/// Collect a streaming result into a single TaskResult.
pub(crate) async fn collect_stream_result(
    mut rx: tokio::sync::mpsc::Receiver<String>,
    task: Task,
    model: &str,
    adapter: Option<String>,
    start: std::time::Instant,
) -> Result<TaskResult> {
    let mut output = String::new();
    let mut output_tokens: u32 = 0;
    while let Some(chunk) = rx.recv().await {
        output.push_str(&chunk);
        output_tokens += 1;
    }
    let duration_ms = start.elapsed().as_millis() as u64;
    Ok(TaskResult {
        output,
        task,
        model: model.to_string(),
        adapter,
        duration_ms,
        input_tokens: 0,
        output_tokens,
    })
}

