//! Dictate-and-format pipeline.
//!
//! Composes speech-to-text (Whisper-tiny) with document generation
//! (mT5-small) to transcribe voice and format into structured notes.
//! MidRange+ only (requires Whisper).

use crate::Result;
use crate::pipeline::{TaskOptions, TaskResult, Task, validate_language, build_prompt};
use crate::AiEngine;
use crate::model_manager::ModelSpec;
use crate::inference::LoRAAdapter;
use crate::profiler::DeviceTier;
use super::summarize::collect_stream_result;

/// Run a dictate-and-format task.
///
/// Input: audio data (16kHz, f32 samples).
/// Output: formatted structured notes from transcribed speech.
///
/// Tier gating: MidRange+ only.
pub async fn run(
    engine: &mut AiEngine,
    audio_data: &[f32],
    language: &str,
    options: TaskOptions,
) -> Result<TaskResult> {
    validate_language(language)?;

    let tier = engine.profile().tier;
    if matches!(tier, DeviceTier::LowEnd | DeviceTier::Throttled) {
        return Err(crate::ZkAiError::UnsupportedTask(
            "Dictate-and-format requires a mid-tier or higher device".to_string(),
        ));
    }

    let start = std::time::Instant::now();

    // Step 1: Transcribe
    let transcribe_result = super::transcribe::run(engine, audio_data, options.clone()).await?;
    let transcribed = &transcribe_result.output;

    // Step 2: Format into structured notes
    let spec = ModelSpec::mt5_small_int8();
    engine.ensure_model(&spec).await?;

    let adapter_path = engine.resolve_adapter_path(
        &format!("adapters/gendoc.{}.bin", language)
    );
    let adapter = LoRAAdapter::new("gendoc", language, &adapter_path, 8);
    let adapter_id = adapter.id();

    let prompt = build_prompt(
        "Format the following transcribed notes into a well-structured document",
        language,
        transcribed,
    );

    if options.stream {
        let rx = engine.run_inference_stream(&prompt, Some(adapter)).await?;
        return collect_stream_result(rx, Task::DictateFormat, "whisper-tiny-int8+mt5-small-int8", Some(adapter_id), start).await;
    }

    let infer_output = engine.run_inference(&prompt, Some(adapter)).await?;
    let duration_ms = start.elapsed().as_millis() as u64;

    Ok(TaskResult {
        output: infer_output.text,
        task: Task::DictateFormat,
        model: "whisper-tiny-int8+mt5-small-int8".to_string(),
        adapter: Some(adapter_id),
        duration_ms,
        input_tokens: infer_output.input_tokens,
        output_tokens: infer_output.output_tokens,
    })
}
