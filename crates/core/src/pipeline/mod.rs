//! Task pipelines: summarization, translation, key-point extraction,
//! document generation, slide content generation, and image search.
//!
//! Each pipeline is a thin layer over the inference engine that:
//! 1. Constructs the appropriate prompt for the task + language
//! 2. Selects the right LoRA adapter
//! 3. Calls the inference session
//! 4. Post-processes the output into a structured result

use serde::{Deserialize, Serialize};
use crate::profiler::DeviceTier;

pub mod summarize;
pub mod translate;
pub mod key_points;
pub mod generate_doc;
pub mod generate_slides;
pub mod image_search;
pub mod image_index;
pub mod semantic_search;
pub mod text_index;

/// Supported AI tasks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Task {
    Summarize,
    Translate,
    KeyPoints,
    GenerateDoc,
    GenerateSlides,
    ImageSearch,
    SemanticSearch,
}

impl std::fmt::Display for Task {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Task::Summarize => write!(f, "summarize"),
            Task::Translate => write!(f, "translate"),
            Task::KeyPoints => write!(f, "key_points"),
            Task::GenerateDoc => write!(f, "generate_doc"),
            Task::GenerateSlides => write!(f, "generate_slides"),
            Task::ImageSearch => write!(f, "image_search"),
            Task::SemanticSearch => write!(f, "semantic_search"),
        }
    }
}

/// Options for an inference task.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskOptions {
    /// Maximum output length in tokens (0 = use tier default).
    pub max_tokens: u32,
    /// Whether to stream output token by token.
    pub stream: bool,
    /// Additional task-specific parameters.
    pub extra: serde_json::Value,
}

impl Default for TaskOptions {
    fn default() -> Self {
        Self {
            max_tokens: 0,
            stream: false,
            extra: serde_json::Value::Null,
        }
    }
}

/// Result of an inference task.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskResult {
    /// The primary output text.
    pub output: String,
    /// The task that produced this result.
    pub task: Task,
    /// The model used.
    pub model: String,
    /// The LoRA adapter used (if any).
    pub adapter: Option<String>,
    /// Inference duration in milliseconds.
    pub duration_ms: u64,
    /// Number of input tokens.
    pub input_tokens: u32,
    /// Number of output tokens.
    pub output_tokens: u32,
}

/// Supported languages for AI tasks.
///
/// mT5-small was pre-trained on 101 languages; we ship LoRA adapters for
/// the 22 listed below covering major language families:
/// - **Germanic**: English (en), German (de)
/// - **Romance**: Spanish (es), French (fr), Portuguese (pt)
/// - **East Asian**: Chinese (zh), Japanese (ja), Korean (ko)
/// - **Southeast Asian**: Vietnamese (vi), Thai (th), Indonesian (id),
///   Malay (ms), Tagalog (tl), Khmer (km)
/// - **South Asian**: Hindi (hi), Bengali (bn), Nepali (ne), Urdu (ur)
/// - **Middle East / Central Asia**: Arabic (ar), Persian (fa), Turkish (tr)
/// - **Slavic**: Russian (ru)
pub const SUPPORTED_LANGUAGES: &[&str] = &[
    "en", "vi", "th", "ar", "zh", "es",
    "fr", "de", "ja", "ko", "id", "ms",
    "tl", "pt", "ru", "hi", "tr", "fa",
    "ur", "bn", "ne", "km",
];

/// Validate that a language code is supported.
pub fn validate_language(lang: &str) -> crate::Result<()> {
    if SUPPORTED_LANGUAGES.contains(&lang) {
        Ok(())
    } else {
        Err(crate::ZkAiError::UnsupportedLanguage(lang.to_string()))
    }
}

/// Construct a task prompt with the appropriate language instruction.
pub fn build_prompt(task: &str, language: &str, content: &str) -> String {
    let lang_instruction = match language {
        "vi" => "Trả lời bằng tiếng Việt.",
        "th" => "ตอบเป็นภาษาไทย",
        "ar" => "أجب باللغة العربية.",
        "zh" => "请用中文回答。",
        "es" => "Responde en español.",
        "fr" => "Répondez en français.",
        "de" => "Antworten Sie auf Deutsch.",
        "ja" => "日本語で答えてください。",
        "ko" => "한국어로 답변하세요.",
        "id" => "Jawab dalam bahasa Indonesia.",
        "ms" => "Jawab dalam bahasa Melayu.",
        "tl" => "Sumagot sa Tagalog.",
        "pt" => "Responda em português.",
        "ru" => "Ответьте на русском языке.",
        "hi" => "हिंदी में उत्तर दें।",
        "tr" => "Türkçe cevap verin.",
        "fa" => "به فارسی پاسخ دهید.",
        "ur" => "اردو میں جواب دیں۔",
        "bn" => "বাংলায় উত্তর দিন।",
        "ne" => "नेपालीमा उत्तर दिनुहोस्।",
        "km" => "ឆ្លើយជាភាសាខ្មែរ។",
        _ => "Answer in English.",
    };

    format!("{}: {}\n{}", task, content, lang_instruction)
}
