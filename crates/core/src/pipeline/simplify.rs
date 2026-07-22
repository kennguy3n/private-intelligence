//! Text simplification pipeline.
//!
//! Simplifies complex text to a plain-language version at ~8th grade
//! reading level using mT5-small with a simplify-specific LoRA adapter.

use crate::Result;
use crate::pipeline::{TaskOptions, TaskResult, Task, validate_language, build_prompt};
use crate::AiEngine;
use crate::model_manager::ModelSpec;
use crate::inference::LoRAAdapter;
use super::summarize::collect_stream_result;

/// Run a text simplification task.
///
/// Input: complex text.
/// Output: simplified version at ~8th grade reading level.
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
        &format!("adapters/simplify.{}.bin", language)
    );
    let adapter = LoRAAdapter::new("simplify", language, &adapter_path, 8);
    let adapter_id = adapter.id();

    let prompt = build_prompt(
        "Simplify the following text to be easy to understand for a general audience",
        language,
        text,
    );
    let start = std::time::Instant::now();

    if options.stream {
        let rx = engine.run_inference_stream(&prompt, Some(adapter)).await?;
        return collect_stream_result(rx, Task::Simplify, "mt5-small-int8", Some(adapter_id), start).await;
    }

    let infer_output = engine.run_inference(&prompt, Some(adapter)).await?;
    let duration_ms = start.elapsed().as_millis() as u64;

    Ok(TaskResult {
        output: infer_output.text,
        task: Task::Simplify,
        model: "mt5-small-int8".to_string(),
        adapter: Some(adapter_id),
        duration_ms,
        input_tokens: infer_output.input_tokens,
        output_tokens: infer_output.output_tokens,
    })
}
