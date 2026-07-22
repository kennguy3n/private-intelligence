//! Pre-send check pipeline.
//!
//! Orchestrates grammar_check + classify_tone + rewrite_tone to check
//! writing before sending. All use mT5-small/e5-small with different
//! LoRA adapters/heads.

use crate::Result;
use crate::pipeline::{TaskOptions, TaskResult, Task};
use crate::AiEngine;

/// Run a pre-send check task.
///
/// Input: text to check before sending.
/// Output: grammar corrections + tone analysis + suggested improvements.
pub async fn run(
    engine: &mut AiEngine,
    text: &str,
    language: &str,
    options: TaskOptions,
) -> Result<TaskResult> {
    let start = std::time::Instant::now();
    let mut sections = Vec::new();

    // Grammar check
    let grammar = super::grammar_check::run(engine, text, language, options.clone()).await?;
    sections.push(format!("📝 Grammar:\n{}", grammar.output));

    // Tone detection
    let tone = super::classify_tone::run(engine, text, options.clone()).await?;
    sections.push(format!("🎭 Tone:\n{}", tone.output));

    // If tone is "Concerned" or "Urgent", suggest a professional rewrite
    if tone.output.starts_with("Concerned") || tone.output.starts_with("Urgent") {
        let rewrite = super::rewrite_tone::run(engine, text, "professional", language, options.clone()).await?;
        sections.push(format!("💡 Suggested rewrite:\n{}", rewrite.output));
    }

    let output = sections.join("\n\n");
    let duration_ms = start.elapsed().as_millis() as u64;

    Ok(TaskResult {
        output,
        task: Task::PreSendCheck,
        model: "mt5-small-int8+multilingual-e5-small-int8".to_string(),
        adapter: None,
        duration_ms,
        input_tokens: text.split_whitespace().count() as u32,
        output_tokens: sections.len() as u32,
    })
}
