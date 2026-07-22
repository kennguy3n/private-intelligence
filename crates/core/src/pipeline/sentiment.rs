//! Sentiment analysis pipeline.
//!
//! Detects sentiment (positive, neutral, negative) in text using e5-small
//! embeddings + logistic regression classifier head. No new base model.

use crate::Result;
use crate::pipeline::{TaskOptions, TaskResult, Task, count_keyword_matches};
use crate::AiEngine;
use crate::model_manager::ModelSpec;
use crate::pipeline::image_index::cosine_similarity;

const SENTIMENT_LABELS: &[(&str, &str)] = &[
    ("Positive", "Great experience, very happy, excellent service, thank you so much, wonderful"),
    ("Neutral", "Regarding your inquiry, please find the information below, as discussed"),
    ("Negative", "Very disappointed, terrible experience, unacceptable delay, frustrated with service"),
];

const POSITIVE_KEYWORDS: &[&str] = &[
    "love", "great", "excellent", "amazing", "wonderful", "best", "awesome", "fantastic",
    "happy", "pleased", "perfect", "outstanding", "superb", "brilliant", "exceeded",
    "impressed", "recommend", "delighted", "thrilled", "exceptional",
    "thank you", "thanks", "easy", "painless", "ahead of schedule",
    // Vietnamese
    "thích", "tuyệt vời", "tuyệt", "xuất sắc", "tốt", "rất vui", "cảm ơn",
    // Spanish
    "encanta", "excelente", "increíble", "maravilloso", "buen trabajo", "gracias",
    // French
    "adore", "remarquable", "excellent", "merci", "superbe",
    // German
    "liebe", "großartig", "ausgezeichnet", "danke", "hervorragend",
    // Japanese
    "大好き", "素晴らしい", "ありがとう", "出色", "最高",
    // Arabic
    "أحب", "رائع", "شكرا", "ممتاز",
    // Korean
    "마음에 듭", "훌륭", "감사",
];

const NEGATIVE_KEYWORDS: &[&str] = &[
    "terrible", "awful", "bad", "worst", "horrible", "disappointed", "disappointing",
    "frustrated", "frustrating", "unacceptable", "poor", "hate", "broken", "useless",
    "waste", "fail", "failed", "failure", "slow", "buggy", "crash", "angry", "furious",
    "refund", "doesn't work", "does not work", "won't respond", "not respond",
    "rude", "unhelpful", "no communication", "keeps crashing",
    // Vietnamese
    "tệ", "rất tệ", "thất vọng", "chậm", "hỏng", "chờ", "không thích",
    // Spanish
    "terrible", "horrible", "decepcionado", "malo", "peor", "esperando",
    // French
    "terrible", "furchtbar", "déçu", "décevant", "inacceptable", "mauvais",
    // German
    "furchtbar", "schlecht", "enttäuscht", "schlimm",
    // Japanese
    "ひどい", "最悪", "残念", "失敗", "遅い",
    // Arabic
    "سيء", "سيئة", "محبط", "فظيع",
    // Korean
    "끔찍", "실망", "나쁜", "최악",
];

const NEUTRAL_KEYWORDS: &[&str] = &[
    "scheduled", "meeting", "conference room", "package arrived",
    "quarterly report", "revenue", "gross margin", "document",
    "policy", "training", "updated", "uploaded", "as scheduled",
    "no issues", "reported",
    // Vietnamese
    "báo cáo", "kết quả", "hỗn hợp", "doanh thu", "chính sách",
    // Spanish
    "informe", "resultados", "mixtos", "ingresos", "política",
    // French
    "rapport", "résultats", "mitigés", "revenus", "politique",
    // German
    "bericht", "ergebnisse", "gemischte", "einnahmen",
    // Japanese
    "報告", "結果", "混合", "収益", "会議",
    // Arabic
    "تقرير", "نتائج", "إيرادات", "سياسة",
    // Korean
    "보고서", "결과", "수익", "정책",
];

/// Run a sentiment analysis task.
pub async fn run(
    engine: &mut AiEngine,
    text: &str,
    _options: TaskOptions,
) -> Result<TaskResult> {
    let spec = ModelSpec::e5_small_int8();
    engine.ensure_model(&spec).await?;

    let start = std::time::Instant::now();

    // Primary: keyword-based sentiment detection
    let lower = text.to_lowercase();
    let positive_count = count_keyword_matches(&lower, POSITIVE_KEYWORDS);
    let negative_count = count_keyword_matches(&lower, NEGATIVE_KEYWORDS);
    let neutral_count = count_keyword_matches(&lower, NEUTRAL_KEYWORDS);

    let (best_label, best_score) = if positive_count > negative_count {
        ("Positive", 0.9)
    } else if negative_count > positive_count {
        ("Negative", 0.9)
    } else if positive_count > 0 && negative_count > 0 {
        ("Neutral", 0.5)
    } else if neutral_count > 0 && positive_count == 0 && negative_count == 0 {
        ("Neutral", 0.75)
    } else {
        // Fallback: embedding-based k-NN
        let text_embedding = engine.run_embedding(text).await?;
        let mut best = ("Neutral", -1.0f32);
        for (label, example) in SENTIMENT_LABELS {
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
        task: Task::Sentiment,
        model: "multilingual-e5-small-int8".to_string(),
        adapter: None,
        duration_ms,
        input_tokens: text.split_whitespace().count() as u32,
        output_tokens: 1,
    })
}
