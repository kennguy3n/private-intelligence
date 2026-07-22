//! Draft reply pipeline.
//!
//! Generates a contextually appropriate reply to an email based on the
//! original message and the user's intent (agree, decline, ask for details).

use crate::Result;
use crate::pipeline::{TaskOptions, TaskResult, Task, validate_language, build_prompt};
use crate::AiEngine;
use crate::model_manager::ModelSpec;
use crate::inference::LoRAAdapter;
use super::summarize::collect_stream_result;

/// Run a draft reply task.
///
/// Input: original email text + user intent (e.g., "agree", "decline").
/// Output: 2-3 sentence reply in the user's preferred language.
pub async fn run(
    engine: &mut AiEngine,
    original_email: &str,
    intent: &str,
    language: &str,
    options: TaskOptions,
) -> Result<TaskResult> {
    validate_language(language)?;

    let spec = ModelSpec::mt5_small_int8();
    engine.ensure_model(&spec).await?;

    let adapter_path = engine.resolve_adapter_path(
        &format!("adapters/draftreply.{}.bin", language)
    );
    let adapter = LoRAAdapter::new("draftreply", language, &adapter_path, 8);
    let adapter_id = adapter.id();

    let content = format!("Intent: {}\nOriginal email:\n{}", intent, original_email);
    let prompt = build_prompt(
        "Draft a reply to the following email based on the given intent",
        language,
        &content,
    );
    let start = std::time::Instant::now();

    if options.stream {
        let rx = engine.run_inference_stream(&prompt, Some(adapter)).await?;
        return collect_stream_result(rx, Task::DraftReply, "mt5-small-int8", Some(adapter_id), start).await;
    }

    let infer_output = engine.run_inference(&prompt, Some(adapter)).await?;
    let duration_ms = start.elapsed().as_millis() as u64;

    Ok(TaskResult {
        output: infer_output.text,
        task: Task::DraftReply,
        model: "mt5-small-int8".to_string(),
        adapter: Some(adapter_id),
        duration_ms,
        input_tokens: infer_output.input_tokens,
        output_tokens: infer_output.output_tokens,
    })
}
