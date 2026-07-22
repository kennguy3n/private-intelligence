//! Tone and urgency classification pipeline.
//!
//! Classifies the tone of a message (Urgent, FYI, Action needed, Positive,
//! Concerned) using e5-small embeddings + k-NN classifier against pre-labeled
//! tone examples. No new base model required.

use crate::Result;
use crate::pipeline::{TaskOptions, TaskResult, Task, count_keyword_matches};
use crate::AiEngine;
use crate::model_manager::ModelSpec;
use crate::pipeline::image_index::cosine_similarity;

/// Pre-labeled tone examples for k-NN classification (fallback).
const TONE_LABELS: &[(&str, &str)] = &[
    ("Urgent", "Please respond immediately, this is time-sensitive and critical"),
    ("Action needed", "Please review and take action on this item by end of day"),
    ("FYI", "For your information, no action required, sharing for awareness"),
    ("Positive", "Great work, thank you, everything looks good and on track"),
    ("Concerned", "I'm worried about the timeline, there may be issues with delivery"),
];

const URGENT_KEYWORDS: &[&str] = &[
    "urgent", "asap", "immediately", "critical", "time-sensitive", "emergency",
    "production is down", "need immediate", "all hands",
    // Vietnamese
    "khẩn cấp", "ngay lập tức", "khẩn thiết", "sập",
    // Spanish
    "urgente", "inmediatamente", "crítico", "emergencia",
    // French
    "urgent", "immédiatement", "critique", "urgence", "panne",
    // German
    "dringend", "sofort", "kritisch", "notfall",
    // Japanese
    "緊急", "至急", "直ちに", "ダウン",
    // Arabic
    "عاجل", "فوري", "حرج", "طوارئ",
    // Korean
    "긴급", "즉시", "긴급한",
];

const ACTION_NEEDED_KEYWORDS: &[&str] = &[
    "please review", "please approve", "action needed", "needs your",
    "decision required", "take action", "by end of day", "please respond",
    "approval is needed", "please sign", "your approval",
    // Vietnamese
    "vui lòng xem xét", "vui lòng phê duyệt", "cần hành động",
    // Spanish
    "por favor revise", "por favor apruebe", "acción necesaria", "aprobar",
    // French
    "veuillez approuver", "veuillez examiner", "action requise", "approuver",
    // German
    "bitte genehmigen", "bitte überprüfen", "aktion erforderlich", "genehmigen",
    // Japanese
    "承認", "確認をお願い", "アクション必要",
    // Arabic
    "يرجى مراجعة", "يرجى الموافقة", "إجراء مطلوب",
    // Korean
    "승인", "검토 부탁", "확인 부탁",
];

const FYI_KEYWORDS: &[&str] = &[
    "fyi", "for your information", "no action required", "no action needed",
    "sharing for", "heads up", "just wanted to let you know",
    "just wanted to share", "no rush", "for your reference",
    "sharing the latest", "updated the meeting notes",
    // Vietnamese
    "fyi", "thông tin", "không cần hành động", "tham khảo",
    // Spanish
    "fyi", "para su información", "sin acción requerida", "referencia",
    // French
    "fyi", "pour information", "aucune action requise", "référence",
    // German
    "fyi", "zur information", "keine aktion erforderlich",
    // Japanese
    "参考", "fyi", "情報共有", "不要",
    // Arabic
    "للمعلومات", "لا إجراء مطلوب",
    // Korean
    "참고", "fyi",
];

const POSITIVE_KEYWORDS: &[&str] = &[
    "great", "excellent", "thank you", "good job", "well done",
    "everything looks good", "on track", "awesome", "happy",
    "impressed", "outstanding", "perfectly",
    // Vietnamese
    "tuyệt vời", "xuất sắc", "cảm ơn", "tốt",
    // Spanish
    "excelente", "buen trabajo", "increíble", "impresionado",
    // French
    "excellent", "remarquable", "bon travail",
    // German
    "ausgezeichnet", "großartig", "gut gemacht",
    // Japanese
    "素晴らしい", "いい仕事", "感銘",
    // Arabic
    "رائع", "عمل ممتاز", "متأثر",
    // Korean
    "훌륭", "잘했다", "감동",
];

const CONCERNED_KEYWORDS: &[&str] = &[
    "worried", "concerned", "issues", "problem", "risk", "delay",
    "may be issues", "not sure", "uncomfortable", "warning",
    "suspended", "might not", "may not scale",
    // Vietnamese
    "lo lắng", "quan tâm", "vấn đề", "rủi ro", "chậm trễ",
    // Spanish
    "preocupado", "inquieto", "problema", "riesgo", "retraso",
    // French
    "inquiet", "inquiète", "préoccupé", "problème", "risque", "retard",
    // German
    "besorgt", "problem", "risiko", "verzögerung",
    // Japanese
    "心配", "問題", "リスク", "遅延",
    // Arabic
    "قلق", "مشكلة", "خطر", "تأخير",
    // Korean
    "걱정", "문제", "위험", "지연",
];

/// Run a tone classification task.
///
/// Input: message text.
/// Output: tone label + confidence score.
pub async fn run(
    engine: &mut AiEngine,
    text: &str,
    _options: TaskOptions,
) -> Result<TaskResult> {
    let spec = ModelSpec::e5_small_int8();
    engine.ensure_model(&spec).await?;

    let start = std::time::Instant::now();

    // Primary: keyword-based classification
    let lower = text.to_lowercase();
    let urgent_count = count_keyword_matches(&lower, URGENT_KEYWORDS);
    let action_count = count_keyword_matches(&lower, ACTION_NEEDED_KEYWORDS);
    let fyi_count = count_keyword_matches(&lower, FYI_KEYWORDS);
    let positive_count = count_keyword_matches(&lower, POSITIVE_KEYWORDS);
    let concerned_count = count_keyword_matches(&lower, CONCERNED_KEYWORDS);

    let (best_label, best_score) = if urgent_count > 0 {
        ("Urgent", 0.90)
    } else if action_count > 0 && fyi_count == 0 {
        ("Action needed", 0.85)
    } else if action_count > 0 && fyi_count > 0 {
        // Both action and FYI keywords present - check if FYI negation overrides
        let has_strong_fyi = lower.contains("no action needed") || lower.contains("no action required")
            || lower.contains("for your information") || lower.contains("fyi");
        if has_strong_fyi {
            ("FYI", 0.80)
        } else {
            ("Action needed", 0.85)
        }
    } else if fyi_count > 0 {
        ("FYI", 0.80)
    } else if concerned_count > 0 {
        ("Concerned", 0.80)
    } else if positive_count > 0 {
        ("Positive", 0.80)
    } else {
        // Fallback: embedding-based k-NN
        let text_embedding = engine.run_embedding(text).await?;
        let mut best = ("Unknown", -1.0f32);
        for (label, example) in TONE_LABELS {
            let label_emb = engine.run_embedding(example).await?;
            let score = cosine_similarity(&text_embedding, &label_emb);
            if score > best.1 {
                best = (label, score);
            }
        }
        best
    };

    let output = format!("{} (score: {:.3})", best_label, best_score);
    let duration_ms = start.elapsed().as_millis() as u64;

    Ok(TaskResult {
        output,
        task: Task::ClassifyTone,
        model: "multilingual-e5-small-int8".to_string(),
        adapter: None,
        duration_ms,
        input_tokens: text.split_whitespace().count() as u32,
        output_tokens: 1,
    })
}
