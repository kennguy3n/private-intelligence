//! Slide content generation pipeline.
//!
//! Produces structured slide text with bullet points and an
//! IMAGE_QUERY tag for each slide that the image_search pipeline
//! can use to find relevant images.

use crate::Result;
use crate::pipeline::{TaskOptions, TaskResult, Task, validate_language, build_prompt};
use crate::AiEngine;
use crate::model_manager::ModelSpec;
use crate::inference::LoRAAdapter;
use super::summarize::collect_stream_result;

/// Run a slide content generation task.
pub async fn run(
    engine: &mut AiEngine,
    topic: &str,
    source_content: &str,
    language: &str,
    options: TaskOptions,
) -> Result<TaskResult> {
    validate_language(language)?;

    let spec = ModelSpec::mt5_small_int8();
    engine.ensure_model(&spec).await?;

    let adapter_path = engine.resolve_adapter_path(
        &format!("adapters/slides.{}.bin", language)
    );
    let adapter = LoRAAdapter::new("slides", language, &adapter_path, 8);
    let adapter_id = adapter.id();

    let content = format!("Topic: {}\nSource content: {}", topic, source_content);
    let instruction = "Generate slide content with the following format for each slide:\n\
        SLIDE N\n\
        Title: <slide title>\n\
        • <bullet point 1>\n\
        • <bullet point 2>\n\
        • <bullet point 3>\n\
        IMAGE_QUERY: <search terms for a relevant image>";
    let prompt = build_prompt(instruction, language, &content);
    let start = std::time::Instant::now();

    if options.stream {
        let rx = engine.run_inference_stream(&prompt, Some(adapter)).await?;
        return collect_stream_result(rx, Task::GenerateSlides, "mt5-small-int8", Some(adapter_id), start).await;
    }

    let infer_output = engine.run_inference(&prompt, Some(adapter)).await?;

    let duration_ms = start.elapsed().as_millis() as u64;

    Ok(TaskResult {
        output: infer_output.text,
        task: Task::GenerateSlides,
        model: "mt5-small-int8".to_string(),
        adapter: Some(adapter_id),
        duration_ms,
        input_tokens: infer_output.input_tokens,
        output_tokens: infer_output.output_tokens,
    })
}
