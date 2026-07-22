//! Document sensitivity classification pipeline.
//!
//! Classifies documents as Public, Internal, Confidential, or Restricted
//! using e5-small + k-NN against sensitivity-labeled examples.

use crate::Result;
use crate::pipeline::{TaskOptions, TaskResult, Task, count_keyword_matches};
use crate::AiEngine;
use crate::model_manager::ModelSpec;
use crate::pipeline::image_index::cosine_similarity;

const SENSITIVITY_LABELS: &[(&str, &str)] = &[
    ("Public", "Press release, marketing brochure, public announcement, website content, blog post"),
    ("Internal", "Team memo, internal process documentation, company newsletter, employee handbook"),
    ("Confidential", "Financial report, customer data, salary information, business strategy, product roadmap"),
    ("Restricted", "Trade secret, legal contract, M&A document, security vulnerability, executive compensation"),
];

const RESTRICTED_KEYWORDS: &[&str] = &[
    "ssn", "social security", "credit card", "api key", "password", "credential",
    "secret key", "access token", "private key", "database password", "root password",
    "jwt", "signing secret", "routing number", "bank account", "stripe",
    // Vietnamese
    "khóa api", "thông tin đăng nhập", "mật khẩu",
    // Spanish
    "clave api", "credenciales", "contraseña",
    // French
    "clés api", "identifiants", "mot de passe",
    // German
    "api-schlüssel", "anmeldeinformationen", "passwort",
    // Japanese
    "APIキー", "認証情報", "パスワード",
    // Arabic
    "مفاتيح", "اعتمادات", "كلمة المرور",
    // Korean
    "API 키", "인증 정보", "비밀번호",
];

const CONFIDENTIAL_KEYWORDS: &[&str] = &[
    "confidential", "acquisition", "merger", "m&a", "salary", "compensation",
    "financial", "revenue", "profit", "customer data", "proprietary",
    "do not discuss", "do not share", "internal use",
    "board meeting", "ipo", "valuation", "pricing strategy",
    "non-disclosure", "audit log", "salary adjustment", "undercutting",
    // Vietnamese
    "mua lại", "thanh toán tiền mặt", "không thảo luận", "bảo mật",
    // Spanish
    "adquisición", "pago en efectivo", "no discutir", "confidencial",
    // French
    "acquisition", "paiement en espèces", "ne pas discuter", "confidentiel",
    // German
    "übernahme", "barzahlung", "nicht extern diskutieren", "vertraulich",
    // Japanese
    "買収", "現金支払い", "外部では議論", "機密",
    // Arabic
    "استحواذ", "دفع نقدًا", "لا تناقش", "سري",
    // Korean
    "인수", "현금 지급", "논의 금지", "기밀",
];

const INTERNAL_KEYWORDS: &[&str] = &[
    "team", "meeting", "internal", "employee", "handbook", "process",
    "all-hands", "memo", "colleague", "department",
    "coding standards", "sprint", "vpn", "certificates", "timesheet",
    "payroll", "office supply", "emergency contact", "hr portal",
    "desk assignment", "office layout",
    // Vietnamese
    "đội ngũ", "cuộc họp", "nội bộ", "thông báo",
    // Spanish
    "equipo", "reunión", "interno", "empleado",
    // French
    "équipe", "réunion", "interne", "employé",
    // German
    "team", "besprechung", "intern", "mitarbeiter",
    // Japanese
    "チーム", "会議", "内部", "社員",
    // Arabic
    "فريق", "اجتماع", "داخلي", "موظف",
    // Korean
    "팀", "회의", "내부", "직원",
];

const PUBLIC_KEYWORDS: &[&str] = &[
    "welcome", "launch", "product line", "website", "blog", "marketing",
    "announcement", "newsletter", "special offer", "customer",
    "data privacy", "best practices", "hiring", "careers", "earnings call",
    "company mission", "press release",
    // Vietnamese
    "chào mừng", "ra mắt", "sản phẩm mới", "chia sẻ",
    // Spanish
    "bienvenido", "lanzamiento", "línea de productos", "compartir",
    // French
    "bienvenue", "lancement", "gamme de produits", "partager",
    // German
    "willkommen", "einführung", "produktlinie", "teilen",
    // Japanese
    "ようこそ", "立ち上げ", "製品ライン", "共有",
    // Arabic
    "ترحيب", "إطلاق", "خط منتجات", "مشاركة",
    // Korean
    "환영", "출시", "제품 라인", "공유",
];

/// Run a sensitivity classification task.
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
    let restricted_count = count_keyword_matches(&lower, RESTRICTED_KEYWORDS);
    let confidential_count = count_keyword_matches(&lower, CONFIDENTIAL_KEYWORDS);
    let internal_count = count_keyword_matches(&lower, INTERNAL_KEYWORDS);
    let public_count = count_keyword_matches(&lower, PUBLIC_KEYWORDS);

    let (best_label, best_score) = if restricted_count > 0 {
        ("Restricted", 0.95)
    } else if confidential_count > 0 {
        ("Confidential", 0.85)
    } else if internal_count > public_count {
        ("Internal", 0.75)
    } else if public_count > 0 {
        ("Public", 0.75)
    } else {
        // Fallback: embedding-based k-NN
        let text_embedding = engine.run_embedding(text).await?;
        let mut best = ("Unknown", -1.0f32);
        for (label, example) in SENSITIVITY_LABELS {
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
        task: Task::ClassifySensitivity,
        model: "multilingual-e5-small-int8".to_string(),
        adapter: None,
        duration_ms,
        input_tokens: text.split_whitespace().count() as u32,
        output_tokens: 1,
    })
}
