//! Speech-to-text transcription pipeline.
//!
//! Uses Whisper-tiny int8 (~30MB) for on-device speech-to-text.
//! On-demand download, MidRange+ tier only. LowEnd falls back to an error.
//!
//! Audio pipeline: raw PCM (16kHz f32) → log-mel spectrogram (80×3000)
//! → Whisper ONNX encoder → decoder → text.

use crate::Result;
use crate::pipeline::{TaskOptions, TaskResult, Task};
use crate::AiEngine;
use crate::model_manager::ModelSpec;
use crate::profiler::DeviceTier;
use super::audio;

/// Run a speech-to-text transcription task.
///
/// Input: audio data (16kHz, f32 samples in [-1, 1], mono).
/// Output: transcribed text.
///
/// Tier gating: MidRange+ only. LowEnd/Throttled devices get an error.
pub async fn run(
    engine: &mut AiEngine,
    audio_data: &[f32],
    _options: TaskOptions,
) -> Result<TaskResult> {
    let tier = engine.profile().tier;
    if matches!(tier, DeviceTier::LowEnd | DeviceTier::Throttled) {
        return Err(crate::ZkAiError::UnsupportedTask(
            "Voice transcription requires a mid-tier or higher device".to_string(),
        ));
    }

    if audio_data.is_empty() {
        return Ok(TaskResult {
            output: String::new(),
            task: Task::Transcribe,
            model: "whisper-tiny-int8".to_string(),
            adapter: None,
            duration_ms: 0,
            input_tokens: 0,
            output_tokens: 0,
        });
    }

    let spec = ModelSpec::whisper_tiny_int8();
    engine.ensure_model(&spec).await?;

    let start = std::time::Instant::now();

    // Compute log-mel spectrogram from raw audio
    let mel = audio::compute_log_mel_spectrogram(audio_data);

    // Run Whisper inference with mel spectrogram as direct ONNX input.
    // This feeds the [1, 80, 3000] mel tensor directly into the Whisper
    // encoder-decoder, bypassing the text-based prompt interface.
    let infer_output = engine.run_whisper(&mel).await?;

    let duration_ms = start.elapsed().as_millis() as u64;

    Ok(TaskResult {
        output: infer_output.text,
        task: Task::Transcribe,
        model: "whisper-tiny-int8".to_string(),
        adapter: None,
        duration_ms,
        input_tokens: 0,
        output_tokens: infer_output.output_tokens,
    })
}
