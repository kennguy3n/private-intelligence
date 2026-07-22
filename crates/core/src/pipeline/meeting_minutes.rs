//! Meeting minutes generation pipeline.
//!
//! Generates formatted meeting minutes (attendees, agenda, discussions,
//! decisions, action items) by orchestrating multiple sub-pipelines.

use crate::Result;
use crate::pipeline::{TaskOptions, TaskResult, Task, validate_language, build_prompt};
use crate::AiEngine;
use crate::model_manager::ModelSpec;
use crate::inference::LoRAAdapter;
use super::summarize::collect_stream_result;

/// Run a meeting minutes generation task.
///
/// Input: meeting transcript.
/// Output: formatted minutes (attendees, agenda, discussions, decisions, action items).
pub async fn run(
    engine: &mut AiEngine,
    transcript: &str,
    language: &str,
    options: TaskOptions,
) -> Result<TaskResult> {
    validate_language(language)?;

    let start = std::time::Instant::now();

    // Run sub-pipelines
    let summary = super::meeting_summary::run(engine, transcript, language, options.clone()).await?;
    let actions = super::action_items::run(engine, transcript, language, options.clone()).await?;
    let decisions = super::extract_decisions::run(engine, transcript, language, options.clone()).await?;

    // Compose into minutes
    let spec = ModelSpec::mt5_small_int8();
    engine.ensure_model(&spec).await?;

    let adapter_path = engine.resolve_adapter_path(
        &format!("adapters/meeting.{}.bin", language)
    );
    let adapter = LoRAAdapter::new("meeting", language, &adapter_path, 8);
    let adapter_id = adapter.id();

    let content = format!(
        "Summary: {}\n\nDecisions: {}\n\nAction Items: {}",
        summary.output, decisions.output, actions.output,
    );

    let prompt = build_prompt(
        "Format the following meeting information into formal meeting minutes with sections: Attendees, Agenda, Discussion Summary, Decisions, Action Items",
        language,
        &content,
    );

    if options.stream {
        let rx = engine.run_inference_stream(&prompt, Some(adapter)).await?;
        return collect_stream_result(rx, Task::MeetingMinutes, "mt5-small-int8", Some(adapter_id), start).await;
    }

    let infer_output = engine.run_inference(&prompt, Some(adapter)).await?;
    let duration_ms = start.elapsed().as_millis() as u64;

    Ok(TaskResult {
        output: infer_output.text,
        task: Task::MeetingMinutes,
        model: "mt5-small-int8".to_string(),
        adapter: Some(adapter_id),
        duration_ms,
        input_tokens: infer_output.input_tokens,
        output_tokens: infer_output.output_tokens,
    })
}
