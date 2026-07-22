//! Multi-turn document chat pipeline.
//!
//! Composes semantic search (e5-small) with conversational response
//! generation (mT5-small + chat LoRA) for multi-turn Q&A over documents.

use crate::Result;
use crate::pipeline::{TaskOptions, TaskResult, Task, validate_language, build_prompt};
use crate::AiEngine;
use crate::model_manager::ModelSpec;
use crate::inference::LoRAAdapter;
use crate::pipeline::text_index::TextIndex;
use super::summarize::collect_stream_result;

/// Run a document chat task.
///
/// Input: user message + conversation history + TextIndex.
/// Output: conversational response grounded in document context.
pub async fn run(
    engine: &mut AiEngine,
    message: &str,
    history: &[(String, String)],
    index: &TextIndex,
    language: &str,
    options: TaskOptions,
) -> Result<TaskResult> {
    validate_language(language)?;

    // Step 1: Semantic search for relevant context
    let spec = ModelSpec::e5_small_int8();
    engine.ensure_model(&spec).await?;

    let query_emb = engine.run_embedding(message).await?;
    let hits = index.search(&query_emb, 3);

    let context = hits.iter()
        .map(|h| h.text.as_str())
        .collect::<Vec<_>>()
        .join("\n\n");

    // Step 2: Build conversation prompt with context
    let spec = ModelSpec::mt5_small_int8();
    engine.ensure_model(&spec).await?;

    let adapter_path = engine.resolve_adapter_path(
        &format!("adapters/chat.{}.bin", language)
    );
    let adapter = LoRAAdapter::new("chat", language, &adapter_path, 8);
    let adapter_id = adapter.id();

    let mut conversation = String::new();
    for (user_msg, ai_reply) in history {
        conversation.push_str(&format!("User: {}\nAssistant: {}\n", user_msg, ai_reply));
    }
    conversation.push_str(&format!("User: {}", message));

    let content = format!("Document context:\n{}\n\nConversation:\n{}", context, conversation);
    let prompt = build_prompt(
        "Answer the user's message based on the document context and conversation history",
        language,
        &content,
    );

    let start = std::time::Instant::now();

    if options.stream {
        let rx = engine.run_inference_stream(&prompt, Some(adapter)).await?;
        return collect_stream_result(rx, Task::DocChat, "mt5-small-int8", Some(adapter_id), start).await;
    }

    let infer_output = engine.run_inference(&prompt, Some(adapter)).await?;
    let duration_ms = start.elapsed().as_millis() as u64;

    Ok(TaskResult {
        output: infer_output.text,
        task: Task::DocChat,
        model: "multilingual-e5-small-int8+mt5-small-int8".to_string(),
        adapter: Some(adapter_id),
        duration_ms,
        input_tokens: infer_output.input_tokens,
        output_tokens: infer_output.output_tokens,
    })
}
