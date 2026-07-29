//! Structural heuristic detectors.
//!
//! Pattern-based detectors that catch scams through structural message
//! features rather than keyword or embedding matching. These complement
//! the keyword and embedding pipelines by catching conversation-format,
//! wrong-number pivot, too-good-to-be-true pricing, and brand+action URL
//! patterns.

use crate::ontology::{IndicatorId, IndicatorHit, IndicatorStrength};
use crate::channel::Channel;

/// Check if a (lowercased) text contains a keyword as a whole word.
///
/// Uses non-alphanumeric boundaries to delimit words, so "accout" won't
/// match inside "account" or "accouter". This avoids false positives from
/// substring matching of misspelling patterns.
fn word_boundary_match(lower_text: &str, keyword: &str) -> bool {
    let text_bytes = lower_text.as_bytes();
    let needle = keyword.as_bytes();
    if needle.is_empty() || needle.len() > text_bytes.len() {
        return false;
    }
    let mut start = 0;
    while start + needle.len() <= text_bytes.len() {
        if let Some(pos) = lower_text[start..].find(keyword) {
            let abs_pos = start + pos;
            let end_pos = abs_pos + needle.len();
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
}

/// Detect indicators using structural heuristics.
///
/// Returns indicator hits that can be merged with keyword/embedding hits.
/// If a heuristic fires, it may boost existing hits or add new ones.
pub fn detect_heuristics(text: &str, channel: Channel) -> Vec<IndicatorHit> {
    let lower = text.to_lowercase();
    let mut hits = Vec::new();

    if let Some(hit) = detect_conversation_format(&lower, channel) {
        hits.push(hit);
    }

    hits.extend(detect_wrong_number_pivot(&lower));

    if let Some(hit) = detect_too_good_to_be_true(&lower) {
        hits.push(hit);
    }

    if let Some(hit) = detect_sms_misspelling_patterns(&lower) {
        hits.push(hit);
    }

    hits
}

/// Detect conversation-format messages (A:/B: or similar multi-turn logs).
///
/// These are sometimes used in social engineering to fabricate a conversation
/// that legitimizes a request. Common in investment and job scam lures.
fn detect_conversation_format(lower: &str, channel: Channel) -> Option<IndicatorHit> {
    // Handle both actual newlines and literal \n in text
    let normalized = lower.replace("\\n", "\n");
    let lines: Vec<&str> = normalized.lines().collect();
    if lines.len() < 3 {
        return None;
    }

    let prefix_patterns = [
        "a:", "b:", "me:", "them:", "scammer:", "victim:", "you:", "they:",
        "user:", "agent:", "customer:", "support:", "bot:", "stranger:",
    ];
    let mut prefixed_count = 0;

    for line in lines.iter().take(20) {
        let trimmed = line.trim();
        if prefix_patterns.iter().any(|p| trimmed.starts_with(p)) {
            prefixed_count += 1;
        }
    }

    if prefixed_count >= 3 {
        return Some(IndicatorHit {
            id: IndicatorId::SenderAnomaly,
            strength: IndicatorStrength::Medium,
            match_count: prefixed_count,
        });
    }

    let _ = channel;
    None
}

/// Detect wrong-number pivot pattern.
///
/// Message starts with an apology for having the wrong number, then pivots
/// to an investment opportunity, romance, or job offer. This is a well-known
/// social engineering pattern, especially in Southeast Asia.
fn detect_wrong_number_pivot(lower: &str) -> Vec<IndicatorHit> {
    let mut hits = Vec::new();

    // Handle both actual newlines and literal \n
    let normalized = lower.replace("\\n", "\n");

    let has_apology = normalized.contains("wrong number")
        || normalized.contains("wrong person")
        || normalized.contains("mistakenly contacted")
        || normalized.contains("texted the wrong")
        || normalized.contains("sorry, is this")
        || normalized.contains("accidentally")
        || normalized.contains("got your number from")
        || normalized.contains("mutual friend gave me")
        || normalized.contains("added your number")
        || normalized.contains("found your number")
        // Traveling/phone acting up — common wrong-number scam opener
        || normalized.contains("traveling") && normalized.contains("phone")
        || normalized.contains("travelling") && normalized.contains("phone")
        // Vietnamese
        || normalized.contains("nhầm số")
        || normalized.contains("nham so")
        || normalized.contains("nhắn nhầm")
        || normalized.contains("nhan nham")
        || normalized.contains("gửi nhầm")
        || normalized.contains("gui nham")
        // Thai
        || normalized.contains("หมายเลขผิด")
        || normalized.contains("เบอร์ผิด")
        // Indonesian
        || normalized.contains("salah nomor")
        || normalized.contains("salah kirim")
        // Malay
        || normalized.contains("salah nombor")
        || normalized.contains("tersalah hantar")
        // Filipino
        || normalized.contains("maling numero")
        || normalized.contains("maling tao");
        // Khmer
        // (Khmer wrong-number patterns are less common in text scams)

    if !has_apology {
        return hits;
    }

    let has_investment = lower.contains("investment")
        || lower.contains("crypto")
        || lower.contains("trading")
        || lower.contains("bitcoin")
        || lower.contains("returns")
        || lower.contains("forex")
        || lower.contains("stocks")
        || lower.contains("broker")
        || lower.contains("ipo")
        // Vietnamese
        || lower.contains("đầu tư")
        || lower.contains("dau tu")
        || lower.contains("chứng khoán")
        || lower.contains("chung khoan")
        // Thai
        || lower.contains("การลงทุน")
        || lower.contains("เทรด")
        // Indonesian
        || lower.contains("investasi")
        || lower.contains("saham")
        // Malay
        || lower.contains("pelaburan")
        || lower.contains("saham");

    let has_romance = lower.contains("nice to meet you")
        || lower.contains("you seem kind")
        || lower.contains("let's be friends")
        || lower.contains("can we chat")
        || lower.contains("fate brought")
        // Vietnamese
        || lower.contains("làm bạn")
        || lower.contains("lam ban")
        // Thai
        || lower.contains("ยินดีที่ได้รู้จัก")
        || lower.contains("เป็นเพื่อน")
        // Indonesian
        || lower.contains("senang berkenalan")
        || lower.contains("jadi teman")
        // Malay
        || lower.contains("senang berkenalan")
        || lower.contains("jadi kawan");

    let has_job = lower.contains("job")
        || lower.contains("work from home")
        || lower.contains("earn money")
        || lower.contains("part-time")
        || lower.contains("recruiter")
        || lower.contains("hiring")
        || lower.contains("position")
        || lower.contains("role for")
        || lower.contains("opening for")
        // Vietnamese
        || lower.contains("việc làm")
        || lower.contains("viec lam")
        || lower.contains("công việc")
        || lower.contains("cong viec")
        // Thai
        || lower.contains("งาน")
        || lower.contains("รับสมัคร")
        // Indonesian
        || lower.contains("lowongan")
        || lower.contains("kerja")
        // Malay
        || lower.contains("kerja")
        || lower.contains("jawatan");

    if has_investment {
        hits.push(IndicatorHit {
            id: IndicatorId::PromiseHighReturn,
            strength: IndicatorStrength::Medium,
            match_count: 2,
        });
    }

    if has_romance {
        hits.push(IndicatorHit {
            id: IndicatorId::RomanceGrooming,
            strength: IndicatorStrength::Medium,
            match_count: 2,
        });
    }

    if has_job {
        hits.push(IndicatorHit {
            id: IndicatorId::JobOffer,
            strength: IndicatorStrength::Medium,
            match_count: 2,
        });
    }

    // "Confidential" / "help me with something" — social engineering lure
    let has_confidential = lower.contains("confidential")
        || lower.contains("help me with something")
        || lower.contains("need your help with");
    if has_confidential {
        hits.push(IndicatorHit {
            id: IndicatorId::FinancialRequest,
            strength: IndicatorStrength::Medium,
            match_count: 1,
        });
    }

    if !hits.is_empty() {
        hits.push(IndicatorHit {
            id: IndicatorId::SenderAnomaly,
            strength: IndicatorStrength::Low,
            match_count: 1,
        });
    }

    hits
}

/// Check if a (lowercased) text contains a brand name.
///
/// For short brand names (≤4 chars), uses word-boundary matching to avoid
/// false positives (e.g., "ir" won't match "verify", "mom" won't match
/// "moment"). For longer brand names or multi-word brands, uses substring
/// matching since they are specific enough.
fn brand_match(lower_text: &str, brand: &str) -> bool {
    // Multi-word brands or brands with dots/special chars use substring
    if brand.contains(' ') || brand.contains('.') || brand.contains('&') {
        return lower_text.contains(brand);
    }
    // Non-ASCII brands (Thai, Vietnamese, etc.) use substring
    if !brand.is_ascii() {
        return lower_text.contains(brand);
    }
    // Short ASCII brands (≤4 chars) need word boundaries
    if brand.len() <= 4 {
        return word_boundary_match(lower_text, brand);
    }
    // Longer ASCII brands are specific enough for substring matching
    lower_text.contains(brand)
}

/// Detect too-good-to-be-true pricing for branded goods.
///
/// Catches messages offering well-known brands at suspiciously low prices
/// without needing keyword matches. Uses price extraction and brand matching.
fn detect_too_good_to_be_true(lower: &str) -> Option<IndicatorHit> {
    let brands = [
        "iphone", "samsung", "galaxy", "ipad", "macbook", "playstation",
        "xbox", "nintendo", "sony", "dyson", "rolex", "louis vuitton",
        "gucci", "hermes", "chanel", "tesla",
        // SEA popular brands
        "oppo", "vivo", "xiaomi", "realme", "redmi", "poco",
        "huawei", "oneplus", "nothing phone",
        // SEA luxury
        "prada", "burberry", "balenciaga", "dior",
        // Additional tech brands
        "dell", "xps", "asus", "acer", "lenovo", "hp ",
        // Vehicles
        "sh 150", "sh 350", "winner", "exciter", "air blade",
        // Concert/event tickets
        "blackpink", "concert", "vip ticket",
    ];

    let has_brand = brands.iter().any(|b| brand_match(lower, b));
    if !has_brand {
        return None;
    }

    let price_patterns = [
        "$50", "$100", "$200", "$300", "$400", "$500",
        "rm50", "rm100", "rm200", "rm300", "rm400", "rm500",
        "sgd 50", "sgd 100", "sgd 200", "sgd 300",
        "vnd 500k", "vnd 1m", "vnd 2m",
        "500k", "1tr", "2tr", "3tr",
        // Vietnamese "X triệu" (million) — common in fake marketplace scams
        "5 triệu", "12 triệu", "52 triệu", "990k",
        "5 trieu", "12 trieu", "52 trieu",
        "giá chỉ", "gia chi", "giá gốc",
        // Thai Baht
        "฿500", "฿1000", "฿2000", "฿5000",
        "baht 500", "baht 1000", "baht 2000",
        // Indonesian Rupiah
        "rp 500rb", "rp 1jt", "rp 2jt", "rp 500k",
        "500rb", "1jt", "2jt",
        // Filipino Peso
        "₱500", "₱1000", "₱2000", "₱5000",
        "php 500", "php 1000", "php 2000",
        // Generic low-price indicators
        "cheap", "below retail", "wholesale price", "cost price",
        "giá rẻ", "gia re", "rẻ",
        "murah", "termurah",
        "ถูก", "ราคาถูก",
        "mura", "presyong mura",
        // Vietnamese "hàng xách tay" (grey market goods)
        "hàng xách tay", "hang xach tay",
        // "số lượng có hạn" / "số lượng giới hạn" (limited quantity)
        "số lượng có hạn", "so luong co han",
        "số lượng giới hạn", "so luong gioi han",
    ];

    let has_low_price = price_patterns.iter().any(|p| lower.contains(p));
    if !has_low_price {
        return None;
    }

    Some(IndicatorHit {
        id: IndicatorId::FakeMarketplace,
        strength: IndicatorStrength::Medium,
        match_count: 2,
    })
}

/// Detect SMS misspelling patterns common in scam messages.
///
/// Scammers often use deliberate misspellings to bypass keyword filters.
/// This heuristic detects common scam-related misspelling patterns that
/// are unlikely to appear in legitimate messages.
fn detect_sms_misspelling_patterns(lower: &str) -> Option<IndicatorHit> {
    // Each entry is a deliberate misspelling that is unlikely to appear in
    // legitimate text. We use word-boundary matching to avoid matching
    // substrings of correctly-spelled words (e.g., "verif" inside "verify").
    let scam_misspellings: &[&str] = &[
        "accout", "accunt", "acoount", "accounnt",
        "passwrod", "pasword", "passworrd",
        "verfy", "verfiy",
        "urgnt", "urgant", "urgen",
        "suspendd", "suspened", "susppended",
        "securty", "securiy", "securt",
        "confrm", "confim", "confrim",
        "paymnt", "paymnet",
        "transfr", "transer",
        "clik", "clikk", "clikc",
        "prizee", "priize",
    ];

    let mut misspelling_count = 0;
    for &ms in scam_misspellings {
        if word_boundary_match(lower, ms) {
            misspelling_count += 1;
        }
    }

    if misspelling_count >= 2 {
        return Some(IndicatorHit {
            id: IndicatorId::SenderAnomaly,
            strength: IndicatorStrength::Medium,
            match_count: misspelling_count,
        });
    }

    None
}
