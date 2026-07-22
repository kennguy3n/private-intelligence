//! Follow-up reminder pipeline.
//!
//! Generates follow-up messages for overdue action items by composing
//! action_items extraction + draft_reply generation.

use crate::Result;
use crate::pipeline::{TaskOptions, TaskResult, Task, validate_language};
use crate::AiEngine;

/// Run a follow-up reminder task.
///
/// Input: action items text + overdue items.
/// Output: follow-up messages for each overdue item.
pub async fn run(
    engine: &mut AiEngine,
    action_items: &str,
    language: &str,
    options: TaskOptions,
) -> Result<TaskResult> {
    validate_language(language)?;

    let start = std::time::Instant::now();

    // Generate follow-up message using draft_reply
    let result = super::draft_reply::run(
        engine,
        action_items,
        "Send a polite follow-up reminder about overdue action items",
        language,
        options,
    ).await?;

    let duration_ms = start.elapsed().as_millis() as u64;

    Ok(TaskResult {
        output: result.output,
        task: Task::FollowUp,
        model: "mt5-small-int8".to_string(),
        adapter: result.adapter,
        duration_ms,
        input_tokens: result.input_tokens,
        output_tokens: result.output_tokens,
    })
}
