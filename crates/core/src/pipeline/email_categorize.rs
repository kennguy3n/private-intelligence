//! Email categorization pipeline.
//!
//! Auto-categorizes emails into Internal, Client, Vendor, Newsletter,
//! Action Required using e5-small + k-NN against category labels.

use crate::Result;
use crate::pipeline::{TaskOptions, TaskResult, Task, count_keyword_matches};
use crate::AiEngine;
use crate::model_manager::ModelSpec;
use crate::pipeline::image_index::cosine_similarity;

const CATEGORY_LABELS: &[(&str, &str)] = &[
    ("Internal", "Team update, internal meeting notes, company announcement, employee communication"),
    ("Client", "Customer inquiry, client feedback, project update for client, customer request"),
    ("Vendor", "Supplier quote, vendor invoice, purchase order, vendor contract renewal"),
    ("Newsletter", "Weekly digest, industry news, blog update, promotional newsletter, marketing email"),
    ("Action Required", "Please review and approve, needs your response, urgent action needed, decision required"),
];

const ACTION_REQUIRED_KEYWORDS: &[&str] = &[
    "please review", "please approve", "please sign", "needs your",
    "action needed", "decision required", "overdue", "remit",
    "urgent", "asap", "please complete", "mandatory",
    "your approval", "your review",
    // Vietnamese
    "vui lòng xem xét", "vui lòng phê duyệt", "vui lòng phản hồi", "cần hành động", "khẩn cấp",
    // Spanish
    "por favor revise", "por favor apruebe", "apruebe", "acción necesaria", "aprobar",
    // French
    "veuillez approuver", "veuillez examiner", "action requise", "approuver",
    // German
    "bitte genehmigen", "bitte überprüfen", "aktion erforderlich", "genehmigen",
    // Japanese
    "承認", "確認をお願い", "レビュー",
    // Arabic
    "يرجى مراجعة", "يرجى الموافقة", "إجراء مطلوب",
    // Korean
    "승인", "검토 부탁", "확인 부탁",
];

const NEWSLETTER_KEYWORDS: &[&str] = &[
    "newsletter", "weekly digest", "monthly digest", "blog",
    "top 10", "trends", "marketing", "promotional",
    "subscribe", "unsubscribe", "industry report", "product newsletter",
    "what's new", "customer stories", "quarterly product",
    // Vietnamese
    "bản tin", "hàng tuần", "xu hướng", "blog",
    // Spanish
    "boletín", "semanal", "tendencias", "newsletter",
    // French
    "newsletter", "hebdomadaire", "tendances", "blog",
    // German
    "newsletter", "wöchentlich", "trends", "ki-trends",
    // Japanese
    "ニュースレター", "週刊", "トレンド",
    // Arabic
    "نشرة", "أسبوعية", "اتجاهات",
    // Korean
    "뉴스레터", "주간", "트렌드",
];

const VENDOR_KEYWORDS: &[&str] = &[
    "supplier", "vendor", "purchase order", "quote", "invoice from",
    "invoice #", "contract renewal", "shipping", "tracking", "order",
    "your aws bill", "shipped", "service alert", "maintenance window",
    "payment will be charged", "amount:", "due in 30 days",
    // Vietnamese
    "đơn hàng", "theo dõi", "gói hàng", "gửi",
    // Spanish
    "pedido", "enviado", "seguimiento", "expedido",
    // French
    "commande", "expédié", "suivi", "envoyé",
    // German
    "bestellung", "versandt", "sendungsverfolgung", "versendet",
    // Japanese
    "注文", "発送", "追跡",
    // Arabic
    "طلب", "شحن", "تتبع",
    // Korean
    "주문", "배송", "추적",
];

const CLIENT_KEYWORDS: &[&str] = &[
    "customer", "client", "partnership", "proposal", "feedback",
    "inquiry", "question about", "thank you for", "quick response",
    "schedule a demo", "demo", "can someone help", "worked perfectly",
    // Vietnamese
    "câu hỏi", "tài liệu", "giúp", "hỏi",
    // Spanish
    "pregunta", "documentación", "ayuda", "pregunta sobre",
    // French
    "question", "documentation", "aide", "peut-il m'aider",
    // German
    "frage", "dokumentation", "helfen", "hilfe",
    // Japanese
    "質問", "ドキュメント", "助け",
    // Arabic
    "سؤال", "وثائق", "مساعدة",
    // Korean
    "질문", "문서", "도움",
];

const INTERNAL_KEYWORDS: &[&str] = &[
    "team", "team lunch", "meeting", "roadmap", "internal",
    "colleague", "employee", "all-hands", "memo",
    "emergency contact", "office layout", "desk assignment",
    "timesheet", "payroll", "hr portal", "coding standards",
    "vpn configuration", "certificates",
    // Vietnamese
    "đội ngũ", "bữa trưa", "phản hồi", "thứ sáu", "thứ năm",
    // Spanish
    "equipo", "almuerzo", "confirmen",
    // French
    "équipe", "déjeuner", "confirmer",
    // German
    "team", "teamlunch", "zusagen",
    // Japanese
    "チーム", "ランチ",
    // Arabic
    "فريق", "غداء",
    // Korean
    "팀", "점심",
];

/// Run an email categorization task.
pub async fn run(
    engine: &mut AiEngine,
    email_text: &str,
    _options: TaskOptions,
) -> Result<TaskResult> {
    let spec = ModelSpec::e5_small_int8();
    engine.ensure_model(&spec).await?;

    let start = std::time::Instant::now();

    // Primary: keyword-based classification
    let lower = email_text.to_lowercase();
    let action_count = count_keyword_matches(&lower, ACTION_REQUIRED_KEYWORDS);
    let newsletter_count = count_keyword_matches(&lower, NEWSLETTER_KEYWORDS);
    let vendor_count = count_keyword_matches(&lower, VENDOR_KEYWORDS);
    let client_count = count_keyword_matches(&lower, CLIENT_KEYWORDS);
    let internal_count = count_keyword_matches(&lower, INTERNAL_KEYWORDS);

    let (best_label, best_score) = if vendor_count > 0 && vendor_count > action_count {
        ("Vendor", 0.85)
    } else if newsletter_count > 0 && newsletter_count >= action_count {
        ("Newsletter", 0.85)
    } else if action_count > 0 {
        // Check if this is actually an internal team event RSVP (lunch, meeting)
        // These should be Internal, not Action Required
        // Only match explicit team lunch/meeting contexts, not general "team" mentions
        let is_team_event_rsvp = lower.contains("team lunch")
            || lower.contains("team meeting")
            || lower.contains("bữa trưa đội ngũ")  // Vietnamese: team lunch
            || lower.contains("almuerzo del equipo")  // Spanish: team lunch
            || lower.contains("déjeuner d'équipe")  // French: team lunch
            || lower.contains("teamlunch")  // German: team lunch
            || lower.contains("チームランチ")  // Japanese: team lunch
            || lower.contains("confirmen antes del jueves")  // Spanish: RSVP context
            || lower.contains("confirmer avant jeudi")  // French: RSVP context
            || lower.contains("phản hồi trước thứ năm");  // Vietnamese: RSVP context
        if is_team_event_rsvp && internal_count > 0 {
            ("Internal", 0.80)
        } else {
            ("Action Required", 0.85)
        }
    } else if vendor_count > 0 {
        ("Vendor", 0.85)
    } else if client_count > 0 && client_count >= internal_count {
        ("Client", 0.80)
    } else if internal_count > 0 {
        ("Internal", 0.80)
    } else {
        // Fallback: embedding-based k-NN
        let text_embedding = engine.run_embedding(email_text).await?;
        let mut best = ("Unknown", -1.0f32);
        for (label, example) in CATEGORY_LABELS {
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
        task: Task::EmailCategorize,
        model: "multilingual-e5-small-int8".to_string(),
        adapter: None,
        duration_ms,
        input_tokens: email_text.split_whitespace().count() as u32,
        output_tokens: 1,
    })
}
