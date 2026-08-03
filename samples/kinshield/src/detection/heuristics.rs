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

    if let Some(hit) = detect_qr_code_pattern(&lower) {
        hits.push(hit);
    }

    if let Some(hit) = detect_subscription_trap_pattern(&lower) {
        hits.push(hit);
    }

    if let Some(hit) = detect_impersonation_pattern(&lower, channel) {
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
        // Only fire if the conversation also contains scam-like content.
        // Conversation format alone is not suspicious — many legitimate
        // messages use A:/B: format. Require at least one scam signal.
        let has_scam_signal = lower.contains("investment")
            || lower.contains("crypto")
            || lower.contains("trading")
            || lower.contains("bitcoin")
            || lower.contains("forex")
            || lower.contains("returns")
            || lower.contains("work from home")
            || lower.contains("earn money")
            || lower.contains("part-time")
            || lower.contains("hiring")
            || lower.contains("recruiter")
            || lower.contains("transfer")
            || lower.contains("bank account")
            || lower.contains("send money")
            || lower.contains("wire")
            || lower.contains("paypal")
            || lower.contains("gift card")
            || lower.contains("western union")
            || lower.contains("deposit")
            || lower.contains("refund")
            || lower.contains("fee")
            || lower.contains("otp")
            || lower.contains("verification code")
            || lower.contains("password")
            || lower.contains("login")
            || lower.contains("click the link")
            || lower.contains("shortlink")
            || lower.contains("bit.ly")
            // Wrong-number pivot patterns (common scam opener in conversation format)
            || lower.contains("wrong number")
            || lower.contains("wrong person")
            || lower.contains("texted the wrong")
            || lower.contains("accidentally")
            || lower.contains("got your number")
            || lower.contains("found your number")
            || lower.contains("dating app")
            || lower.contains("singles group")
            || lower.contains("resume")
            || lower.contains("position")
            || lower.contains("salary")
            || lower.contains("reimburse")
            || lower.contains("assessment")
            || lower.contains("insurance claim")
            // Vietnamese scam signals
            || lower.contains("đầu tư")
            || lower.contains("dau tu")
            || lower.contains("chuyển khoản")
            || lower.contains("chuyen khoan")
            || lower.contains("việc làm")
            || lower.contains("viec lam")
            || lower.contains("tuyển dụng")
            || lower.contains("tuyen dung")
            || lower.contains("mã otp")
            || lower.contains("ma otp")
            || lower.contains("xác thực")
            || lower.contains("xac thuc")
            || lower.contains("hoàn tiền")
            || lower.contains("hoan tien")
            || lower.contains("phí")
            || lower.contains("phi ")
            // Vietnamese wrong-number / romance patterns
            || lower.contains("nhầm số")
            || lower.contains("nham so")
            || lower.contains("nhắn nhầm")
            || lower.contains("nhan nham")
            || lower.contains("nhầm rồi")
            || lower.contains("nham roi")
            || lower.contains("đăng tin")
            || lower.contains("dang tin")
            // Vietnamese job/delivery scam signals
            || lower.contains("lương")
            || lower.contains("luong")
            || lower.contains("fanpage")
            || lower.contains("grant")
            || lower.contains("viện phí")
            || lower.contains("vien phi")
            // Romance / social engineering
            || lower.contains("nice to meet you")
            || lower.contains("fate brought")
            || lower.contains("let's be friends")
            || lower.contains("can we be friends")
            || lower.contains("làm bạn")
            || lower.contains("lam ban")
            // Thai
            || lower.contains("การลงทุน")
            || lower.contains("เทรด")
            || lower.contains("โอนเงิน")
            // Indonesian
            || lower.contains("investasi")
            || lower.contains("transfer")
            || lower.contains("lowongan")
            // Malay
            || lower.contains("pelaburan")
            || lower.contains("transfer")
            || lower.contains("kerja");

        if has_scam_signal {
            return Some(IndicatorHit {
                id: IndicatorId::SenderAnomaly,
                strength: IndicatorStrength::Medium,
                match_count: prefixed_count,
            });
        }
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
        || normalized.contains("got your number by mistake")
        // Note: removed standalone "by mistake" — too common in legitimate messages
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
            id: IndicatorId::WrongNumberPivot,
            strength: IndicatorStrength::Medium,
            match_count: 1,
        });
        // Only emit SenderAnomaly if there's an actual financial/investment/romance/job pivot.
        // A wrong-number apology alone is not a sender anomaly.
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

/// Detect QR code patterns in text.
///
/// Catches messages that ask users to scan QR codes for payment, verification,
/// or claiming rewards — a growing phishing vector (quishing).
fn detect_qr_code_pattern(lower: &str) -> Option<IndicatorHit> {
    let qr_keywords = [
        "qr code", "scan qr", "scan to pay", "scan this code",
        "scan here", "scan to receive", "scan to claim",
        "scan to verify", "quishing",
        // Multilingual
        "mã qr", "quét mã qr", "quét để thanh toán",
        "kode qr", "pindai qr", "scan qr",
        "kod qr", "imbas qr",
        "i-scan ang qr", "scan para bayad",
        "คิวอาร์โค้ด", "สแกน qr",
        "កូដ qr", "ស្កេន qr",
        "二维码", "扫码",
    ];

    let mut count = 0;
    for &kw in &qr_keywords {
        if lower.contains(kw) {
            count += 1;
        }
    }

    if count > 0 {
        // Check for payment/credential context to boost strength
        let has_payment = lower.contains("pay") || lower.contains("payment")
            || lower.contains("thanh toán") || lower.contains("bayar")
            || lower.contains("จ่าย") || lower.contains("bayad");
        let has_credential = lower.contains("verify") || lower.contains("confirm")
            || lower.contains("xác thực") || lower.contains("verifikasi");

        let strength = if has_payment || has_credential {
            IndicatorStrength::High
        } else {
            IndicatorStrength::Medium
        };

        return Some(IndicatorHit {
            id: IndicatorId::QRCodeScan,
            strength,
            match_count: count,
        });
    }

    None
}

/// Detect subscription trap patterns.
///
/// Catches messages about free trials ending, auto-renewal charges,
/// or subscription activations with hidden fees.
fn detect_subscription_trap_pattern(lower: &str) -> Option<IndicatorHit> {
    let trial_keywords = [
        "free trial", "trial ends", "trial expires", "trial has ended",
        "auto-renew", "auto renew", "recurring payment",
        "monthly charge", "subscription activated",
        "membership fee", "renewal fee", "will be charged",
        // Multilingual
        "dùng thử miễn phí", "tự động gia hạn",
        "ทดลองใช้ฟรี", "ต่ออายุอัตโนมัติ",
        "uji coba gratis", "perpanjang otomatis",
        "percubaan percuma", "diperbaharui secara automatik",
    ];

    let mut count = 0;
    for &kw in &trial_keywords {
        if lower.contains(kw) {
            count += 1;
        }
    }

    if count >= 1 {
        // Check for cancellation difficulty patterns
        let has_cancel_barrier = lower.contains("call to cancel")
            || lower.contains("cancel anytime")
            || lower.contains("premium rate")
            || lower.contains("hotline")
            || lower.contains("cancel by calling");

        let strength = if has_cancel_barrier || count >= 2 {
            IndicatorStrength::High
        } else {
            IndicatorStrength::Medium
        };

        return Some(IndicatorHit {
            id: IndicatorId::SubscriptionTrap,
            strength,
            match_count: count,
        });
    }

    None
}

/// Detect impersonation patterns — official-sounding language without brand tags.
///
/// Catches messages that use authority-claiming language ("official",
/// "department", "bureau") but lack any recognizable sender brand tag,
/// which is a strong impersonation signal.
fn detect_impersonation_pattern(lower: &str, channel: Channel) -> Option<IndicatorHit> {
    let _ = channel;

    let official_words = [
        "official", "department", "bureau", "authority", "agency",
        "directorate", "division", "bộ", "cục", "tổng cục",
        "กรม", "หน่วยงาน",
        "dinast", "direktorat", "instansi",
        "jabatan", "agensi",
        "kagawaran", "buró",
    ];

    let has_official = official_words.iter().any(|w| lower.contains(w));
    if !has_official {
        return None;
    }

    // Check for threat language that commonly accompanies impersonation
    let has_threat = lower.contains("arrest") || lower.contains("warrant")
        || lower.contains("legal action") || lower.contains("penalty")
        || lower.contains("suspend") || lower.contains("deactivate")
        || lower.contains("bắt") || lower.contains("khởi tố")
        || lower.contains("จับ") || lower.contains("ดำเนินคดี")
        || lower.contains("penangkapan") || lower.contains("tuntutan")
        || lower.contains("denda") || lower.contains("saman");

    // Check for urgency
    let has_urgency = lower.contains("urgent") || lower.contains("immediately")
        || lower.contains("within 24 hours") || lower.contains("deadline")
        || lower.contains("khẩn cấp") || lower.contains("ด่วน")
        || lower.contains("mendesak") || lower.contains("mamadali");

    if has_threat || has_urgency {
        return Some(IndicatorHit {
            id: IndicatorId::AuthorityClaim,
            strength: if has_threat && has_urgency {
                IndicatorStrength::High
            } else {
                IndicatorStrength::Medium
            },
            match_count: 1,
        });
    }

    None
}
