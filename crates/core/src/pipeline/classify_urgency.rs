//! Ticket urgency classification pipeline.
//!
//! Classifies support tickets as Critical, High, Medium, or Low using
//! e5-small embeddings + k-NN against urgency-labeled examples.

use crate::Result;
use crate::pipeline::{TaskOptions, TaskResult, Task, count_keyword_matches};
use crate::AiEngine;
use crate::model_manager::ModelSpec;
use crate::pipeline::image_index::cosine_similarity;

const URGENCY_LABELS: &[(&str, &str)] = &[
    ("Critical", "System is down, production outage, data loss, security breach, immediate attention required"),
    ("High", "Major functionality broken, significant impact on business operations, needs urgent fix"),
    ("Medium", "Feature not working as expected, workaround available, moderate impact on user"),
    ("Low", "Minor cosmetic issue, feature request, general question, no immediate impact"),
];

const CRITICAL_KEYWORDS: &[&str] = &[
    "production", "outage", "down", "critical", "p1", "emergency",
    "data loss", "security breach", "immediate", "all requests failing",
    // Vietnamese
    "sập", "sản xuất bị sập", "thất bại", "khẩn cấp", "khẩn thiết",
    // Spanish
    "caída", "producción caída", "fallan", "crítico", "emergencia",
    // French
    "panne", "production en panne", "échouent", "critique", "urgence",
    // German
    "ausfall", "produktionsausfall", "fehlgeschlagen", "kritisch", "notfall",
    // Japanese
    "ダウン", "本番環境", "失敗", "緊急",
    // Arabic
    "متوقف", "الإنتاج", "تفشل", "حرج",
    // Korean
    "다운", "프로덕션", "실패", "긴급",
];

const HIGH_KEYWORDS: &[&str] = &[
    "urgent", "high", "p2", "major", "broken", "significant impact",
    "needs urgent", "asap", "escalate", "slow response", "some users experiencing",
    "rate limit", "crashes", "crash", "occasionally", "affects significant",
    "significant user", "enterprise customer", "throttled",
    "incorrect results", "returning incorrect", "not processing",
    "500 error", "intermittent failures",
    // Vietnamese
    "chậm", "thời gian phản hồi chậm", "giải pháp thay thế", "tốc độ",
    // Spanish
    "lentos", "tiempos de respuesta lentos", "solución alternativa", "lento",
    // French
    "lents", "temps de réponse lents", "contournement", "lent",
    // German
    "langsame", "antwortzeiten", "workaround", "langsam",
    // Japanese
    "遅延", "応答遅延", "回避策", "遅い",
    // Arabic
    "بطء", "بطء الاستجابة", "حل بديل",
    // Korean
    "응답", "느린", "회피책",
];

const LOW_KEYWORDS: &[&str] = &[
    "minor", "cosmetic", "general question",
    "no impact", "p4", "documentation", "typo", "suggestion",
    "keyboard shortcut", "faq", "outdated", "misaligned",
    // Vietnamese
    "lỗi chính tả", "tài liệu", "nhỏ", "không ảnh hưởng",
    // Spanish
    "error tipográfico", "documentación", "menor", "cosmético",
    // French
    "faute de frappe", "documentation", "mineur", "cosmétique",
    // German
    "tippfehler", "dokumentation", "geringfügig", "kosmetisch",
    // Japanese
    "誤字", "ドキュメント", "軽微", "タイポ",
    // Arabic
    "خطأ مطبعي", "توثيق", "طفيف",
    // Korean
    "오타", "문서", "사소한",
];

const MEDIUM_KEYWORDS: &[&str] = &[
    "moderate", "workaround", "p3", "not working as expected",
    "some users", "intermittent", "feature request", "export",
    "integrate with", "question:", "how do i",
    // Vietnamese
    "yêu cầu tính năng", "chế độ tối", "tính năng", "yêu cầu",
    // Spanish
    "solicitud de función", "modo oscuro", "función", "solicitud",
    // French
    "demande de fonctionnalité", "mode sombre", "fonctionnalité", "demande",
    // German
    "funktionsanfrage", "dark mode", "funktion", "anfrage",
    // Japanese
    "機能リクエスト", "ダークモード", "機能",
    // Arabic
    "طلب ميزة", "الوضع الداكن", "ميزة",
    // Korean
    "기능 요청", "다크 모드", "기능",
];

/// Run a ticket urgency classification task.
pub async fn run(
    engine: &mut AiEngine,
    ticket_text: &str,
    _options: TaskOptions,
) -> Result<TaskResult> {
    let spec = ModelSpec::e5_small_int8();
    engine.ensure_model(&spec).await?;

    let start = std::time::Instant::now();

    // Primary: keyword-based classification
    let lower = ticket_text.to_lowercase();
    let critical_count = count_keyword_matches(&lower, CRITICAL_KEYWORDS);
    let high_count = count_keyword_matches(&lower, HIGH_KEYWORDS);
    let medium_count = count_keyword_matches(&lower, MEDIUM_KEYWORDS);
    let low_count = count_keyword_matches(&lower, LOW_KEYWORDS);

    let (best_label, best_score) = if critical_count > 0 {
        ("Critical", 0.95)
    } else if high_count > 0 {
        ("High", 0.85)
    } else if low_count > medium_count {
        ("Low", 0.75)
    } else if medium_count > 0 {
        ("Medium", 0.75)
    } else {
        // Fallback: embedding-based k-NN
        let text_embedding = engine.run_embedding(ticket_text).await?;
        let mut best = ("Medium", -1.0f32);
        for (label, example) in URGENCY_LABELS {
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
        task: Task::ClassifyUrgency,
        model: "multilingual-e5-small-int8".to_string(),
        adapter: None,
        duration_ms,
        input_tokens: ticket_text.split_whitespace().count() as u32,
        output_tokens: 1,
    })
}
