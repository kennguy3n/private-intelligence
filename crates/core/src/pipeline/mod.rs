//! Task pipelines: summarization, translation, key-point extraction,
//! document generation, slide content generation, and image search.
//!
//! Each pipeline is a thin layer over the inference engine that:
//! 1. Constructs the appropriate prompt for the task + language
//! 2. Selects the right LoRA adapter
//! 3. Calls the inference session
//! 4. Post-processes the output into a structured result

use serde::{Deserialize, Serialize};

pub mod summarize;
pub mod translate;
pub mod key_points;
pub mod generate_doc;
pub mod generate_slides;
pub mod image_search;
pub mod image_index;
pub mod semantic_search;
pub mod text_index;

// B2C Category 1: Email & Messaging Intelligence
pub mod email_summary;
pub mod draft_reply;
pub mod smart_reply;
pub mod classify_tone;
pub mod chat_summary;
pub mod notif_summary;
pub mod prioritize;

// B2C Category 2: Meeting & Voice Intelligence
pub mod transcribe;
pub mod meeting_summary;
pub mod action_items;
pub mod voice_action;
pub mod live_transcribe;
pub mod meeting_qa;
pub mod audio;

// B2C Category 3: Document Productivity
pub mod loaders;
pub mod grammar_check;
pub mod simplify;

// B2C Category 4: Personal Knowledge & Search
pub mod local_file_index;
pub mod qa;
pub mod auto_tag;
pub mod find_similar;
pub mod daily_digest;
pub mod doc_chat;
pub mod cluster;

// B2C Category 5: Communication Assistance
pub mod rewrite_tone;
pub mod expand;
pub mod explain;
pub mod pre_send_check;
pub mod dictate_format;

// B2B Category 1: Document Intelligence & RAG
pub mod contract_analysis;
pub mod compare_docs;
pub mod find_clause;
pub mod extract_dates;
pub mod ticket_summary;
pub mod classify_urgency;
pub mod ticket_reply;
pub mod dedup;
pub mod email_categorize;
pub mod sentiment;

// B2B Category 4: Compliance & Privacy Intelligence
pub mod pii_scan;
pub mod classify_sensitivity;
pub mod compliance_report;

// B2B Category 5: Knowledge Management & Search
pub mod onboarding_qa;
pub mod policy_lookup;
pub mod auto_abstract;
pub mod find_expert;
pub mod rerank;

// B2B Category 6: Team Productivity
pub mod collab_summary;
pub mod extract_decisions;
pub mod meeting_minutes;
pub mod follow_up;

// RAG module
pub mod rag;

// Privacy module
pub mod privacy;

/// Check if a (lowercased) text contains a keyword.
///
/// For short ASCII keywords (≤4 chars), uses word-boundary matching to avoid
/// false positives (e.g. "down" won't match "download", "bad" won't match "badge").
/// For longer keywords or non-ASCII keywords (CJK, Arabic, etc.), uses substring
/// matching since word boundaries are language-dependent and harder to determine.
pub fn keyword_match(lower_text: &str, keyword: &str) -> bool {
    // For non-ASCII keywords (Japanese, Chinese, Arabic, Korean, etc.),
    // substring matching is the right approach.
    if !keyword.is_ascii() {
        return lower_text.contains(keyword);
    }

    // For short ASCII keywords (≤4 chars), require word boundaries to avoid
    // false positives like "down" in "download", "bad" in "badge", "order" in "border".
    if keyword.len() <= 4 {
        let needle = keyword.to_lowercase();
        // Search for the keyword surrounded by non-alphanumeric characters
        let text_bytes = lower_text.as_bytes();
        let needle_bytes = needle.as_bytes();
        let mut start = 0;
        while start + needle_bytes.len() <= text_bytes.len() {
            if let Some(pos) = lower_text[start..].find(&needle) {
                let abs_pos = start + pos;
                let end_pos = abs_pos + needle_bytes.len();
                let before_ok = abs_pos == 0
                    || !text_bytes[abs_pos - 1].is_ascii_alphanumeric();
                let after_ok = end_pos == text_bytes.len()
                    || !text_bytes[end_pos].is_ascii_alphanumeric();
                if before_ok && after_ok {
                    return true;
                }
                start = abs_pos + 1;
            } else {
                break;
            }
        }
        false
    } else {
        // For longer ASCII keywords, substring matching is safe enough
        lower_text.contains(keyword)
    }
}

/// Count how many keywords in a list match the given (lowercased) text.
pub fn count_keyword_matches(lower_text: &str, keywords: &[&str]) -> usize {
    keywords.iter().filter(|&k| keyword_match(lower_text, k)).count()
}

/// Normalize common SMS slang/abbreviations to their full forms.
///
/// This is applied before keyword matching to catch scam messages that use
/// informal abbreviations common in Southeast Asian SMS culture.
/// Only expands ASCII slang; non-ASCII text is passed through unchanged.
pub fn normalize_sms_slang(text: &str) -> String {
    let lower = text.to_lowercase();

    // Pad with spaces so that slang at the start or end of the text is
    // also matched (e.g., "UR account" at the start of a message).
    // Also replace newlines with spaces so slang after a newline is caught.
    let padded = format!(" {} ", lower.replace('\n', " "));

    let patterns: &[&str] = &[
        " ur ", " u ", " r ", " n ", " bcoz ", " bcos ", " bcus ",
        " plis ", " pls ", " plz ", " dun ", " dont ", " wat ", " wen ",
        " abt ", " frm ", " msg ", " info ", " tk ", " thx ", " tq ",
        " nvm ", " asap", " b4 ", " 2moro", " 2day", " 2nite", " rly ",
        " wat's ", " d ", " dat ", " dis ", " urself", " urslf",
        " pw ", " pwd ", " acc ", " acct ", " amt ", " bal ", " docs ",
        " req ", " reqd ", " appr ", " cnfm ", " vrfy ", " pmt ", " txn ",
    ];

    let replacements: &[&str] = &[
        " your ", " you ", " are ", " and ", " because ", " because ", " because ",
        " please ", " please ", " please ", " don't ", " don't ", " what ", " when ",
        " about ", " from ", " message ", " information ", " thanks ", " thanks ", " thanks ",
        " nevermind ", " as soon as possible", " before ", " tomorrow", " today", " tonight", " really ",
        " what's ", " the ", " that ", " this ", " yourself", " yourself",
        " password ", " password ", " account ", " account ", " amount ", " balance ", " documents ",
        " required ", " required ", " approved ", " confirm ", " verify ", " payment ", " transaction ",
    ];

    let ac = aho_corasick::AhoCorasick::new(patterns).unwrap();
    let result = ac.replace_all(&padded, replacements);

    // Remove the padding spaces we added at the start and end
    result.trim().to_string()
}

/// Compute Levenshtein edit distance between two ASCII strings.
/// Returns the distance (0 = identical). Caps at 255 for efficiency.
fn levenshtein(a: &[u8], b: &[u8]) -> u8 {
    let (a_len, b_len) = (a.len(), b.len());
    if a_len == 0 {
        return b_len.min(255) as u8;
    }
    if b_len == 0 {
        return a_len.min(255) as u8;
    }

    let mut prev: Vec<u8> = (0..=b_len).map(|i| i.min(255) as u8).collect();
    let mut curr: Vec<u8> = vec![0; b_len + 1];

    for i in 1..=a_len {
        curr[0] = i.min(255) as u8;
        for j in 1..=b_len {
            let cost = if a[i - 1] == b[j - 1] { 0 } else { 1 };
            curr[j] = (prev[j].min(curr[j - 1]) + cost)
                .min(prev[j - 1] + cost)
                .min(255);
        }
        std::mem::swap(&mut prev, &mut curr);
    }

    prev[b_len]
}

/// Maximum allowed edit distance based on keyword length.
///
/// - Keywords ≤4 chars: no fuzzy matching (too many false positives)
/// - Keywords 5-8 chars: edit distance 1
/// - Keywords 9+ chars: edit distance 2
fn max_edit_distance(keyword_len: usize) -> usize {
    if keyword_len <= 4 {
        0
    } else if keyword_len <= 8 {
        1
    } else {
        2
    }
}

/// Check if a (lowercased) text contains a keyword, with fuzzy matching fallback.
///
/// First tries exact `keyword_match`. If that fails and the keyword is long
/// enough (5+ chars), tries fuzzy matching by scanning each word in the text
/// and comparing with Levenshtein distance.
///
/// Returns `(matched, was_fuzzy)`.
pub fn keyword_match_fuzzy(lower_text: &str, keyword: &str) -> (bool, bool) {
    if keyword_match(lower_text, keyword) {
        return (true, false);
    }

    let max_dist = max_edit_distance(keyword.len());
    if max_dist == 0 {
        return (false, false);
    }

    let keyword_bytes = keyword.as_bytes();

    for word in lower_text.split(|c: char| !c.is_ascii_alphanumeric()) {
        if word.is_empty() {
            continue;
        }
        let word_bytes = word.as_bytes();
        let dist = levenshtein(word_bytes, keyword_bytes);
        if dist as usize <= max_dist {
            return (true, true);
        }
    }

    (false, false)
}

/// Count keyword matches with fuzzy matching support.
///
/// Returns `(total_matches, fuzzy_matches)` where `fuzzy_matches` is the count
/// of matches that were only found via fuzzy matching (not exact).
pub fn count_keyword_matches_fuzzy(lower_text: &str, keywords: &[&str]) -> (usize, usize) {
    let mut total = 0usize;
    let mut fuzzy = 0usize;
    for &k in keywords {
        let (matched, was_fuzzy) = keyword_match_fuzzy(lower_text, k);
        if matched {
            total += 1;
            if was_fuzzy {
                fuzzy += 1;
            }
        }
    }
    (total, fuzzy)
}

/// Supported AI tasks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Task {
    // Original tasks
    Summarize,
    Translate,
    KeyPoints,
    GenerateDoc,
    GenerateSlides,
    ImageSearch,
    SemanticSearch,
    // B2C Category 1: Email & Messaging Intelligence
    EmailSummary,
    DraftReply,
    SmartReply,
    ClassifyTone,
    ChatSummary,
    NotifSummary,
    Prioritize,
    // B2C Category 2: Meeting & Voice Intelligence
    Transcribe,
    MeetingSummary,
    ActionItems,
    VoiceAction,
    LiveTranscribe,
    MeetingQa,
    // B2C Category 3: Document Productivity
    GrammarCheck,
    Simplify,
    // B2C Category 4: Personal Knowledge & Search
    LocalFileIndex,
    Qa,
    AutoTag,
    FindSimilar,
    DailyDigest,
    DocChat,
    Cluster,
    // B2C Category 5: Communication Assistance
    RewriteTone,
    Expand,
    Explain,
    PreSendCheck,
    DictateFormat,
    // B2B Category 1: Document Intelligence & RAG
    ContractAnalysis,
    CompareDocs,
    FindClause,
    ExtractDates,
    // B2B Category 3: Email & Support Intelligence
    TicketSummary,
    ClassifyUrgency,
    TicketReply,
    Dedup,
    EmailCategorize,
    Sentiment,
    // B2B Category 4: Compliance & Privacy
    PiiScan,
    ClassifySensitivity,
    ComplianceReport,
    // B2B Category 5: Knowledge Management
    OnboardingQa,
    PolicyLookup,
    AutoAbstract,
    FindExpert,
    Rerank,
    // B2B Category 6: Team Productivity
    CollabSummary,
    ExtractDecisions,
    MeetingMinutes,
    FollowUp,
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
            Task::EmailSummary => write!(f, "email_summary"),
            Task::DraftReply => write!(f, "draft_reply"),
            Task::SmartReply => write!(f, "smart_reply"),
            Task::ClassifyTone => write!(f, "classify_tone"),
            Task::ChatSummary => write!(f, "chat_summary"),
            Task::NotifSummary => write!(f, "notif_summary"),
            Task::Prioritize => write!(f, "prioritize"),
            Task::Transcribe => write!(f, "transcribe"),
            Task::MeetingSummary => write!(f, "meeting_summary"),
            Task::ActionItems => write!(f, "action_items"),
            Task::VoiceAction => write!(f, "voice_action"),
            Task::LiveTranscribe => write!(f, "live_transcribe"),
            Task::MeetingQa => write!(f, "meeting_qa"),
            Task::GrammarCheck => write!(f, "grammar_check"),
            Task::Simplify => write!(f, "simplify"),
            Task::LocalFileIndex => write!(f, "local_file_index"),
            Task::Qa => write!(f, "qa"),
            Task::AutoTag => write!(f, "auto_tag"),
            Task::FindSimilar => write!(f, "find_similar"),
            Task::DailyDigest => write!(f, "daily_digest"),
            Task::DocChat => write!(f, "doc_chat"),
            Task::Cluster => write!(f, "cluster"),
            Task::RewriteTone => write!(f, "rewrite_tone"),
            Task::Expand => write!(f, "expand"),
            Task::Explain => write!(f, "explain"),
            Task::PreSendCheck => write!(f, "pre_send_check"),
            Task::DictateFormat => write!(f, "dictate_format"),
            Task::ContractAnalysis => write!(f, "contract_analysis"),
            Task::CompareDocs => write!(f, "compare_docs"),
            Task::FindClause => write!(f, "find_clause"),
            Task::ExtractDates => write!(f, "extract_dates"),
            Task::TicketSummary => write!(f, "ticket_summary"),
            Task::ClassifyUrgency => write!(f, "classify_urgency"),
            Task::TicketReply => write!(f, "ticket_reply"),
            Task::Dedup => write!(f, "dedup"),
            Task::EmailCategorize => write!(f, "email_categorize"),
            Task::Sentiment => write!(f, "sentiment"),
            Task::PiiScan => write!(f, "pii_scan"),
            Task::ClassifySensitivity => write!(f, "classify_sensitivity"),
            Task::ComplianceReport => write!(f, "compliance_report"),
            Task::OnboardingQa => write!(f, "onboarding_qa"),
            Task::PolicyLookup => write!(f, "policy_lookup"),
            Task::AutoAbstract => write!(f, "auto_abstract"),
            Task::FindExpert => write!(f, "find_expert"),
            Task::Rerank => write!(f, "rerank"),
            Task::CollabSummary => write!(f, "collab_summary"),
            Task::ExtractDecisions => write!(f, "extract_decisions"),
            Task::MeetingMinutes => write!(f, "meeting_minutes"),
            Task::FollowUp => write!(f, "follow_up"),
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
