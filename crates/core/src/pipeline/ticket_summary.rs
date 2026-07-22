//! Support ticket summarization pipeline.
//!
//! Summarizes support ticket threads using mT5-small with a ticket-specific
//! LoRA adapter. Fine-tuned on support ticket structure (issue, steps tried,
//! current status).

use crate::Result;
use crate::pipeline::{TaskOptions, TaskResult, Task, validate_language, build_prompt};
use crate::AiEngine;
use crate::model_manager::ModelSpec;
use crate::inference::LoRAAdapter;
use super::summarize::collect_stream_result;

/// Run a ticket summarization task.
///
/// Input: ticket thread text.
/// Output: summary of issue + troubleshooting steps + current status.
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
        &format!("adapters/ticket_summary.{}.bin", language)
    );
    let adapter = LoRAAdapter::new("ticket_summary", language, &adapter_path, 8);
    let adapter_id = adapter.id();

    let prompt = build_prompt(
        "Summarize the following support ticket: issue description, troubleshooting steps tried, and current status",
        language,
        ticket_text,
    );
    let start = std::time::Instant::now();

    if options.stream {
        let rx = engine.run_inference_stream(&prompt, Some(adapter)).await?;
        return collect_stream_result(rx, Task::TicketSummary, "mt5-small-int8", Some(adapter_id), start).await;
    }

    let infer_output = engine.run_inference(&prompt, Some(adapter)).await?;
    let duration_ms = start.elapsed().as_millis() as u64;

    Ok(TaskResult {
        output: infer_output.text,
        task: Task::TicketSummary,
        model: "mt5-small-int8".to_string(),
        adapter: Some(adapter_id),
        duration_ms,
        input_tokens: infer_output.input_tokens,
        output_tokens: infer_output.output_tokens,
    })
}
