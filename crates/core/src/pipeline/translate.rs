//! Translation pipeline.

use crate::Result;
use crate::pipeline::{TaskOptions, TaskResult, Task, validate_language};
use crate::AiEngine;
use crate::model_manager::ModelSpec;
use crate::inference::LoRAAdapter;
use super::summarize::collect_stream_result;

/// Run a translation task.
pub async fn run(
    engine: &mut AiEngine,
    text: &str,
    source_lang: &str,
    target_lang: &str,
    options: TaskOptions,
) -> Result<TaskResult> {
    validate_language(source_lang)?;
    validate_language(target_lang)?;

    let spec = ModelSpec::mt5_small_int8();
    engine.ensure_model(&spec).await?;

    let adapter_path = engine.resolve_adapter_path(
        &format!("adapters/translate.{}_{}.bin", source_lang, target_lang)
    );
    let adapter = LoRAAdapter::new("translate", &format!("{}_{}", source_lang, target_lang), &adapter_path, 8);
    let adapter_id = adapter.id();

    let prompt = format!(
        "Translate the following text from {} to {}:\n{}",
        source_lang, target_lang, text
    );
    let start = std::time::Instant::now();

    if options.stream {
        let rx = engine.run_inference_stream(&prompt, Some(adapter)).await?;
        return collect_stream_result(rx, Task::Translate, "mt5-small-int8", Some(adapter_id), start).await;
    }

    let infer_output = engine.run_inference(&prompt, Some(adapter)).await?;
    let duration_ms = start.elapsed().as_millis() as u64;

    Ok(TaskResult {
        output: infer_output.text,
        task: Task::Translate,
        model: "mt5-small-int8".to_string(),
        adapter: Some(adapter_id),
        duration_ms,
        input_tokens: infer_output.input_tokens,
        output_tokens: infer_output.output_tokens,
    })
}
