//! Support ticket reply drafting pipeline.
//!
//! Drafts a response to a support ticket using mT5-small with a
//! ticket-reply-specific LoRA adapter.

use crate::Result;
use crate::pipeline::{TaskOptions, TaskResult, Task, validate_language, build_prompt};
use crate::AiEngine;
use crate::model_manager::ModelSpec;
use crate::inference::LoRAAdapter;
use super::summarize::collect_stream_result;

/// Run a ticket reply drafting task.
pub async fn run(
    engine: &mut AiEngine,
    ticket_text: &str,
    language: &str,
    options: TaskOptions,
) -> Result<TaskResult> {
    validate_language(language)?;

    let spec = ModelSpec::mt5_small_int8();
    engine.ensure_model(&spec).await?;

    let adapter_path = engine.resolve_adapter_path(
        &format!("adapters/ticket_reply.{}.bin", language)
    );
    let adapter = LoRAAdapter::new("ticket_reply", language, &adapter_path, 8);
    let adapter_id = adapter.id();

    let prompt = build_prompt(
        "Draft a helpful response to the following support ticket based on the issue and troubleshooting history",
        language,
        ticket_text,
    );
    let start = std::time::Instant::now();

    if options.stream {
        let rx = engine.run_inference_stream(&prompt, Some(adapter)).await?;
        return collect_stream_result(rx, Task::TicketReply, "mt5-small-int8", Some(adapter_id), start).await;
    }

    let infer_output = engine.run_inference(&prompt, Some(adapter)).await?;
    let duration_ms = start.elapsed().as_millis() as u64;

    Ok(TaskResult {
        output: infer_output.text,
        task: Task::TicketReply,
        model: "mt5-small-int8".to_string(),
        adapter: Some(adapter_id),
        duration_ms,
        input_tokens: infer_output.input_tokens,
        output_tokens: infer_output.output_tokens,
    })
}
