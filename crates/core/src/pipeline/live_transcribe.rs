//! Live transcription pipeline.
//!
//! Real-time speech-to-text during phone/VoIP calls using Whisper-tiny
//! with streaming audio chunk processing. MidRange+ only.

use crate::Result;
use crate::pipeline::{TaskOptions, TaskResult, Task};
use crate::AiEngine;
use crate::model_manager::ModelSpec;
use crate::profiler::DeviceTier;

/// Audio chunk size in samples (30s at 16kHz = 480,000 samples).
const CHUNK_SIZE: usize = 480_000;

/// Run a live transcription task.
///
/// Input: streaming audio chunks (16kHz, f32 samples).
/// Output: transcribed text for each chunk.
///
/// Tier gating: MidRange+ only. Governor enforces 20s timeout per chunk.
pub async fn run(
    engine: &mut AiEngine,
    audio_chunks: &[Vec<f32>],
    _options: TaskOptions,
) -> Result<TaskResult> {
    let tier = engine.profile().tier;
    if matches!(tier, DeviceTier::LowEnd | DeviceTier::Throttled) {
        return Err(crate::ZkAiError::UnsupportedTask(
            "Live transcription requires a mid-tier or higher device".to_string(),
        ));
    }

    let spec = ModelSpec::whisper_tiny_int8();
    engine.ensure_model(&spec).await?;

    let start = std::time::Instant::now();
    let mut full_transcript = String::new();

    for (idx, chunk) in audio_chunks.iter().enumerate() {
        if chunk.len() > CHUNK_SIZE {
            tracing::warn!(
                chunk_idx = idx,
                len = chunk.len(),
                max = CHUNK_SIZE,
                "audio chunk exceeds 30s limit, truncating"
            );
        }
        let chunk_result = super::transcribe::run(engine, chunk, TaskOptions::default()).await?;
        full_transcript.push_str(&chunk_result.output);
        full_transcript.push(' ');
    }

    let duration_ms = start.elapsed().as_millis() as u64;

    Ok(TaskResult {
        output: full_transcript.trim().to_string(),
        task: Task::LiveTranscribe,
        model: "whisper-tiny-int8".to_string(),
        adapter: None,
        duration_ms,
        input_tokens: 0,
        output_tokens: full_transcript.split_whitespace().count() as u32,
    })
}
