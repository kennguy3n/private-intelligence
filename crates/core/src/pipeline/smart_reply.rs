//! Smart reply pipeline.
//!
//! Generates 3 quick reply suggestions (<10 words each) for a message,
//! similar to Gmail Smart Reply but fully on-device.

use crate::Result;
use crate::pipeline::{TaskOptions, TaskResult, Task, validate_language, build_prompt};
use crate::AiEngine;
use crate::model_manager::ModelSpec;
use crate::inference::LoRAAdapter;
use super::summarize::collect_stream_result;

/// Run a smart reply task.
///
/// Input: last 2-3 messages in a conversation.
/// Output: 3 short reply options (<10 words each).
pub async fn run(
    engine: &mut AiEngine,
    messages: &str,
    language: &str,
    options: TaskOptions,
) -> Result<TaskResult> {
    validate_language(language)?;

    let spec = ModelSpec::mt5_small_int8();
    engine.ensure_model(&spec).await?;

    let adapter_path = engine.resolve_adapter_path(
        &format!("adapters/smartreply.{}.bin", language)
    );
    let adapter = LoRAAdapter::new("smartreply", language, &adapter_path, 8);
    let adapter_id = adapter.id();

    let prompt = build_prompt(
        "Generate 3 short reply options (under 10 words each) for the following messages",
        language,
        messages,
    );
    let start = std::time::Instant::now();

    if options.stream {
        let rx = engine.run_inference_stream(&prompt, Some(adapter)).await?;
        return collect_stream_result(rx, Task::SmartReply, "mt5-small-int8", Some(adapter_id), start).await;
    }

    let infer_output = engine.run_inference(&prompt, Some(adapter)).await?;
    let duration_ms = start.elapsed().as_millis() as u64;

    Ok(TaskResult {
        output: infer_output.text,
        task: Task::SmartReply,
        model: "mt5-small-int8".to_string(),
        adapter: Some(adapter_id),
        duration_ms,
        input_tokens: infer_output.input_tokens,
        output_tokens: infer_output.output_tokens,
    })
}
