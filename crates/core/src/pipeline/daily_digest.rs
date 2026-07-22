//! Daily digest pipeline.
//!
//! Orchestrates multiple pipelines (email_summary, meeting_summary,
//! action_items, notif_summary) to produce an end-of-day digest.
//! All use mT5-small with different LoRA adapters, hot-swapped in sequence.

use crate::Result;
use crate::pipeline::{TaskOptions, TaskResult, Task};
use crate::AiEngine;

/// Input data for the daily digest.
pub struct DailyDigestInput {
    /// Email threads (one per line, or multiple threads).
    pub emails: String,
    /// Meeting transcripts.
    pub meetings: String,
    /// Notifications received.
    pub notifications: String,
}

/// Run a daily digest task.
///
/// Composes email_summary + meeting_summary + action_items + notif_summary
/// into a unified end-of-day digest.
pub async fn run(
    engine: &mut AiEngine,
    input: &DailyDigestInput,
    language: &str,
    options: TaskOptions,
) -> Result<TaskResult> {
    let start = std::time::Instant::now();
    let mut sections = Vec::new();

    // Email summaries
    if !input.emails.is_empty() {
        let result = super::email_summary::run(engine, &input.emails, language, options.clone()).await?;
        sections.push(format!("📧 Email Summary:\n{}", result.output));
    }

    // Meeting summary
    if !input.meetings.is_empty() {
        let result = super::meeting_summary::run(engine, &input.meetings, language, options.clone()).await?;
        sections.push(format!("📅 Meeting Summary:\n{}", result.output));

        // Action items from meetings
        let actions = super::action_items::run(engine, &input.meetings, language, options.clone()).await?;
        sections.push(format!("✅ Action Items:\n{}", actions.output));
    }

    // Notification digest
    if !input.notifications.is_empty() {
        let result = super::notif_summary::run(engine, &input.notifications, language, options.clone()).await?;
        sections.push(format!("🔔 Notifications:\n{}", result.output));
    }

    let output = if sections.is_empty() {
        "No data to summarize for today.".to_string()
    } else {
        format!("Daily Digest\n============\n\n{}", sections.join("\n\n"))
    };

    let duration_ms = start.elapsed().as_millis() as u64;

    Ok(TaskResult {
        output,
        task: Task::DailyDigest,
        model: "mt5-small-int8".to_string(),
        adapter: None,
        duration_ms,
        input_tokens: 0,
        output_tokens: sections.len() as u32,
    })
}
