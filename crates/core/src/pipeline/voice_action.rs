//! Voice-to-action pipeline.
//!
//! Composes speech-to-text (Whisper-tiny) with intent classification
//! (e5-small k-NN) to extract voice commands like "Remind me to follow up
//! with John about the proposal."

use crate::Result;
use crate::pipeline::{TaskOptions, TaskResult, Task};
use crate::AiEngine;
use crate::model_manager::ModelSpec;
use crate::profiler::DeviceTier;
use crate::pipeline::image_index::cosine_similarity;

/// Intent templates for k-NN classification.
const INTENT_TEMPLATES: &[(&str, &str)] = &[
    ("reminder", "Remind me to follow up with someone about something"),
    ("reminder", "Set a reminder to call or email someone"),
    ("schedule", "Schedule a meeting with someone for tomorrow"),
    ("schedule", "Add an event to my calendar for next week"),
    ("search", "Find documents about a specific topic"),
    ("search", "Search my files for information about something"),
    ("email", "Send an email to someone about a topic"),
    ("email", "Draft a message to someone regarding something"),
    ("note", "Take a note about something important"),
    ("note", "Write down that I need to remember something"),
];

/// Run a voice-to-action task.
///
/// Input: audio data (16kHz, 16-bit PCM mono).
/// Output: extracted intent + structured action.
///
/// Tier gating: MidRange+ only (requires Whisper-tiny).
pub async fn run(
    engine: &mut AiEngine,
    audio_data: &[f32],
    options: TaskOptions,
) -> Result<TaskResult> {
    let tier = engine.profile().tier;
    if matches!(tier, DeviceTier::LowEnd | DeviceTier::Throttled) {
        return Err(crate::ZkAiError::UnsupportedTask(
            "Voice actions require a mid-tier or higher device".to_string(),
        ));
    }

    // Step 1: Transcribe audio to text
    let transcribe_result = super::transcribe::run(engine, audio_data, options).await?;
    let transcribed_text = &transcribe_result.output;

    // Step 2: Classify intent using e5-small
    let spec = ModelSpec::e5_small_int8();
    engine.ensure_model(&spec).await?;

    let start = std::time::Instant::now();
    let text_embedding = engine.run_embedding(transcribed_text).await?;

    let mut best_intent = "unknown";
    let mut best_score = -1.0f32;

    for (intent, template) in INTENT_TEMPLATES {
        let template_emb = engine.run_embedding(template).await?;
        let score = cosine_similarity(&text_embedding, &template_emb);
        if score > best_score {
            best_score = score;
            best_intent = intent;
        }
    }

    let output = format!(
        "Intent: {} (confidence: {:.3})\nTranscribed: {}",
        best_intent, best_score, transcribed_text,
    );
    let duration_ms = start.elapsed().as_millis() as u64;

    Ok(TaskResult {
        output,
        task: Task::VoiceAction,
        model: "whisper-tiny-int8+multilingual-e5-small-int8".to_string(),
        adapter: None,
        duration_ms,
        input_tokens: transcribed_text.split_whitespace().count() as u32,
        output_tokens: 2,
    })
}
