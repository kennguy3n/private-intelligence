//! URL and link analysis for suspicious link detection.
//!
//! Detects shortened URLs, lookalike domains, IP addresses in URLs,
//! and other suspicious link patterns — all without any network calls.

use std::sync::LazyLock;
use regex_lite::Regex;
use crate::ontology::{IndicatorHit, IndicatorStrength};
use crate::allowlist;

/// Check if a domain contains a brand name, using word-boundary matching
/// for short brand names (≤4 chars) to avoid false positives.
fn domain_contains_brand(domain: &str, brand: &str) -> bool {
    // Multi-word brands or brands with dots/special chars use substring
    if brand.contains(' ') || brand.contains('.') || brand.contains('&') {
        return domain.contains(brand);
    }
    // Non-ASCII brands use substring
    if !brand.is_ascii() {
        return domain.contains(brand);
    }
    // Short ASCII brands (≤4 chars) need word boundaries.
    // In domains, the delimiters are dots, hyphens, and underscores
    // (not just non-alphanumeric), so we treat those as boundaries too.
    if brand.len() <= 4 {
        // Split domain on non-alphanumeric chars and check each part
        for part in domain.split(|c: char| !c.is_ascii_alphanumeric()) {
            if part == brand {
                return true;
            }
        }
        return false;
    }
    domain.contains(brand)
}

/// Known URL shortener domains.
const URL_SHORTENERS: &[&str] = &[
    "bit.ly", "tinyurl.com", "t.co", "shorte.st", "cutt.ly",
    "ow.ly", "is.gd", "buff.ly", "rebrand.ly", "rb.gy",
    "s.id", "lnk.to", "tiny.cc", "soo.gd", "t.ly",
    "shorturl.at", "tiny.ie", "v.gd",
    "shrtco.de", "cutt.us", "ht.ly",
    "yourls.org", "snip.ly", "qr.ae", "x.co",
    // Additional common shorteners
    "goo.gl", "fb.me", "wa.me", "tiny.pl",
    "t.hk", "reurl.cc", "lihi.cc", "psee.io",
    "0rz.tw", "moa.tw", "bitly.kr",
];

/// Suspicious TLDs commonly used in scam URLs.
const SUSPICIOUS_TLDS: &[&str] = &[
    ".top", ".xyz", ".click", ".loan", ".work", ".men",
    ".country", ".kim", ".science", ".review",
    ".bid", ".date", ".download", ".stream", ".gdn",
    ".racing", ".accountant", ".cricket", ".faith",
    ".trade", ".webcam", ".party",
];

/// Regex to extract URLs from text.
static URL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"https?://[^\s<>\[\]{}|\\^`]+")
        .expect("invalid URL regex")
});

/// Regex to detect raw IP addresses in URLs.
static IP_IN_URL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
        .expect("invalid IP URL regex")
});

/// Extract all URLs from text.
pub fn extract_urls(text: &str) -> Vec<String> {
    URL_RE
        .find_iter(text)
        .map(|m| m.as_str().to_string())
        .collect()
}

/// Known brands and their legitimate domain patterns.
/// If a URL contains a brand name but the domain doesn't match,
/// it's likely a lookalike/phishing domain.
const KNOWN_BRANDS: &[(&str, &[&str])] = &[
    // Singapore banks
    ("dbs", &["dbs.com", "dbs.com.sg", "dbs.sg"]),
    ("posb", &["posb.com.sg", "posb.sg"]),
    ("ocbc", &["ocbc.com", "ocbc.com.sg"]),
    ("uob", &["uob.com", "uob.com.sg", "uob.sg"]),
    // Singapore e-commerce/services
    ("grab", &["grab.com", "grab.sg"]),
    ("shopee", &["shopee.sg", "shopee.com", "shopee.vn"]),
    ("lazada", &["lazada.sg", "lazada.com", "lazada.vn"]),
    ("carousell", &["carousell.sg", "carousell.com"]),
    ("qoo10", &["qoo10.sg", "qoo10.com"]),
    // Singapore delivery/logistics
    ("singpost", &["singpost.com"]),
    ("ninja van", &["ninjavan.co", "ninjavan.com"]),
    ("ninja", &["ninjavan.co", "ninjavan.com"]),
    ("qexpress", &["qoo10.com"]),
    ("ezbuy", &["ezbuy.sg"]),
    // Singapore government
    ("gov.sg", &["gov.sg"]),
    ("ir", &["iras.gov.sg"]),
    ("moh", &["moh.gov.sg"]),
    ("mom", &["mom.gov.sg"]),
    ("ica", &["ica.gov.sg"]),
    ("hdb", &["hdb.gov.sg"]),
    ("cpf", &["cpf.gov.sg"]),
    // Singapore telcos
    ("singtel", &["singtel.com"]),
    ("starhub", &["starhub.com"]),
    ("m1", &["m1.com.sg"]),
    // International tech
    ("netflix", &["netflix.com"]),
    ("apple", &["apple.com", "icloud.com"]),
    ("icloud", &["icloud.com", "apple.com"]),
    ("microsoft", &["microsoft.com", "live.com", "outlook.com"]),
    ("google", &["google.com"]),
    ("spotify", &["spotify.com"]),
    ("youtube", &["youtube.com", "youtu.be"]),
    // Gaming
    ("garena", &["garena.sg", "garena.com"]),
    ("steam", &["steampowered.com", "steamcommunity.com"]),
    ("valve", &["valvesoftware.com"]),
    ("riot", &["riotgames.com"]),
    // Social media
    ("telegram", &["telegram.org"]),
    ("whatsapp", &["whatsapp.com"]),
    ("facebook", &["facebook.com"]),
    ("instagram", &["instagram.com"]),
    ("tiktok", &["tiktok.com"]),
    // Vietnam banks
    ("vietcombank", &["vietcombank.com.vn", "vcb.vn"]),
    ("vcb", &["vietcombank.com.vn", "vcb.vn"]),
    ("tpbank", &["tpb.vn", "tpbank.vn"]),
    ("techcombank", &["techcombank.com.vn", "tcb.vn"]),
    ("vietinbank", &["vietinbank.com.vn"]),
    ("bidv", &["bidv.com.vn"]),
    ("hdbank", &["hdbank.com.vn"]),
    ("vpbank", &["vpbank.com.vn"]),
    ("agribank", &["agribank.com.vn"]),
    ("acb", &["acb.com.vn"]),
    ("mb bank", &["mbbank.com.vn"]),
    ("mbbank", &["mbbank.com.vn"]),
    ("sacombank", &["sacombank.com.vn"]),
    ("eximbank", &["eximbank.com.vn"]),
    // Vietnam fintech/telco
    ("momo", &["momo.vn"]),
    ("vnpay", &["vnpay.vn"]),
    ("zalo", &["zalo.me", "zaloapp.com"]),
    ("viettel", &["viettel.com.vn"]),
    ("vietnamobile", &["vietnamobile.com.vn"]),
    // Vietnam delivery
    ("ghn", &["ghn.vn"]),
    ("ghtk", &["ghtk.vn"]),
    ("tiki", &["tiki.vn"]),
    ("sendo", &["sendo.vn"]),
    ("vietnam post", &["vnpost.vn"]),
    ("vnpost", &["vnpost.vn"]),
    // Thailand banks
    ("bangkok bank", &["bbl.co.th"]),
    ("bbl", &["bbl.co.th"]),
    ("kasikorn", &["kasikornbank.com", "kbank.com"]),
    ("kbank", &["kasikornbank.com", "kbank.com"]),
    ("krungthai", &["krungthai.com"]),
    ("krungsri", &["krungsri.com"]),
    ("scb", &["scb.co.th"]),
    ("k plus", &["kplus.com"]),
    // Thailand telco/services
    ("ais", &["ais.co.th"]),
    ("truemoney", &["truemoney.com"]),
    ("lalamove", &["lalamove.com"]),
    ("thai post", &["thailandpost.co.th"]),
    ("thailand post", &["thailandpost.co.th"]),
    // Indonesia banks
    ("bca", &["bca.co.id"]),
    ("mandiri", &["bankmandiri.co.id"]),
    ("bni", &["bni.co.id"]),
    ("bri", &["bri.co.id"]),
    ("cimb niaga", &["cimbniaga.co.id"]),
    ("permata", &["permatabank.com"]),
    ("danamon", &["bankdanamon.co.id"]),
    // Indonesia e-commerce/telco/fintech
    ("tokopedia", &["tokopedia.com"]),
    ("bukalapak", &["bukalapak.com"]),
    ("telkomsel", &["telkomsel.com"]),
    ("indosat", &["indosat.com"]),
    ("gojek", &["gojek.com", "go-jek.com"]),
    ("gopay", &["gojek.com"]),
    ("ovo", &["ovo.id"]),
    ("dana", &["dana.id"]),
    ("jne", &["jne.co.id"]),
    ("j&t", &["jet.co.id"]),
    ("pos indonesia", &["posindonesia.co.id"]),
    // Malaysia banks
    ("maybank", &["maybank2u.com", "maybank.com"]),
    ("cimb", &["cimbclicks.com", "cimb.com"]),
    ("public bank", &["pbebank.com"]),
    ("rhb", &["rhbgroup.com"]),
    ("ambank", &["ambankgroup.com"]),
    ("bank rakyat", &["bankrakyat.com.my"]),
    // Malaysia telco/services
    ("maxis", &["maxis.com.my"]),
    ("celcom", &["celcom.com.my"]),
    ("digi", &["digi.com.my"]),
    ("pos malaysia", &["pos.com.my"]),
    // Philippines banks/services
    ("bdo", &["bdo.com.ph"]),
    ("bpi", &["bpi.com.ph"]),
    ("metrobank", &["metrobank.com.ph"]),
    ("gcash", &["gcash.com"]),
    ("globe", &["globe.com.ph"]),
    ("smart", &["smart.com.ph"]),
    ("lbc", &["lbcexpress.com"]),
    // International banks
    ("hsbc", &["hsbc.com", "hsbc.com.sg"]),
    ("standard chartered", &["sc.com", "standardchartered.com"]),
    // International delivery
    ("dhl", &["dhl.com"]),
    ("fedex", &["fedex.com"]),
    ("ups", &["ups.com"]),
    ("yodel", &["yodel.co.uk"]),
    ("royal mail", &["royalmail.com"]),
    ("jnt", &["jet.co.id"]),
    // Vietnam government
    ("gov.vn", &["gov.vn"]),
    ("ubnd", &["gov.vn"]),
    ("bo tai chinh", &["mof.gov.vn"]),
    ("mof", &["mof.gov.vn"]),
    ("sbv", &["sbv.gov.vn"]),
    ("ngan hang nha nuoc", &["sbv.gov.vn"]),
    ("tax", &["tax.gov.vn", "gdt.gov.vn"]),
    ("thue", &["tax.gov.vn", "gdt.gov.vn"]),
    ("vnpt", &["vnpt.com.vn"]),
    ("mobi", &["mobifone.vn"]),
    ("mobifone", &["mobifone.vn"]),
    ("vinaphone", &["vinaphone.vn"]),
    ("fpt", &["fpt.com"]),
    ("winmart", &["winmart.vn"]),
    ("thegioididong", &["thegioididong.com"]),
    ("dien may xanh", &["dienmayxanh.com"]),
    ("chotot", &["chotot.com"]),
    ("zalopay", &["zalopay.vn"]),
    ("binance", &["binance.com", "binance.vn"]),
];

/// Action words commonly used in phishing URLs combined with brand names.
const PHISHING_ACTION_WORDS: &[&str] = &[
    "verify", "secure", "login", "update", "confirm", "alert",
    "billing", "delivery", "customs", "unlock", "activate",
    "reset", "recovery", "support", "validate", "check",
    "suspend", "reactivate", "auth", "signin", "register",
    "claim", "collect", "redeem", "restore", "unlock",
    "reward", "cashback", "won", "prize", "gift",
    "verify-account", "secure-login", "update-info",
];

/// Check if a domain is a lookalike domain impersonating a known brand.
///
/// Detects:
/// - Brand name + hyphen + action word in domain (e.g., `dbs-secure-login.com`)
/// - Brand name in domain but domain doesn't match any legitimate domain
/// - Brand name + action word TLD pattern (e.g., `dbs-verify.xyz`)
fn detect_lookalike_domain(url: &str) -> bool {
    let lower = url.to_lowercase();
    let domain_part = lower
        .strip_prefix("https://")
        .or_else(|| lower.strip_prefix("http://"))
        .unwrap_or(&lower);
    let domain = domain_part.split('/').next().unwrap_or(domain_part);
    let domain_no_port = domain.split(':').next().unwrap_or(domain);

    // 1. Hyphenated domains containing brand names are almost always scams
    //    Legitimate companies don't use hyphens in their primary domains
    if domain_no_port.contains('-') {
        for (brand, _) in KNOWN_BRANDS {
            if domain_contains_brand(domain_no_port, brand) {
                return true;
            }
        }
    }

    // 2. Brand name + phishing action word in domain (without hyphen)
    //    e.g., "dbsverify.com", "grabsecure.net"
    for (brand, _) in KNOWN_BRANDS {
        if domain_contains_brand(domain_no_port, brand) {
            for &action in PHISHING_ACTION_WORDS {
                if domain_no_port.contains(action) {
                    // Check it's not a legitimate domain
                    let is_legit = KNOWN_BRANDS
                        .iter()
                        .filter(|(b, _)| **b == **brand)
                        .flat_map(|(_, legit)| legit.iter())
                        .any(|&legit| domain_no_port == legit || domain_no_port.ends_with(&format!(".{}", legit)));
                    if !is_legit {
                        return true;
                    }
                }
            }
        }
    }

    // 3. Brand name in domain but domain doesn't match any legitimate domain
    //    Only flag if the domain is NOT in the legitimate list
    for (brand, legit_domains) in KNOWN_BRANDS {
        if domain_contains_brand(domain_no_port, brand) {
            let is_legit = legit_domains
                .iter()
                .any(|&legit| domain_no_port == legit || domain_no_port.ends_with(&format!(".{}", legit)));
            if !is_legit && domain_contains_brand(domain_no_port, brand) {
                // Extra check: if domain has action words or suspicious patterns
                let has_action = PHISHING_ACTION_WORDS.iter().any(|&a| domain_no_port.contains(a));
                let has_suspicious_tld = SUSPICIOUS_TLDS.iter().any(|&tld| domain_no_port.ends_with(tld));
                if has_action || has_suspicious_tld {
                    return true;
                }
            }
        }
    }

    false
}

/// Lure words commonly used in phishing URLs without brand names.
const PHISHING_LURE_WORDS: &[&str] = &[
    "toll", "parcel", "package", "delivery", "customs", "tax",
    "fine", "penalty", "prize", "reward", "gift", "won", "claim",
    "refund", "invoice", "receipt", "order", "shipment",
    // Vietnamese lure words
    "hotro", "dangky", "nhanthuong", "khuyenmai", "tuyendung",
    "hoanthue", "trocap", "hocbong", "kichcau",
];

/// Financial/payment words commonly used in phishing domains.
const PHISHING_FINANCIAL_WORDS: &[&str] = &[
    "payment", "pay", "fee", "settle", "billing", "refund",
    "transfer", "bank", "cash", "wallet", "deposit",
    // Vietnamese financial words
    "thanhtoan", "chuyentien", "gui tien", "nap tien",
    "vay", "giaingan",
];

/// Suspicious domain suffixes that strongly indicate phishing
/// when combined with action or financial words.
const SUSPICIOUS_DOMAIN_SUFFIXES: &[&str] = &[
    "-authority", "-official", "-support", "-secure",
    "-verify", "-payment", "-hold", "-settle",
    "-unlock", "-restore", "-reactivate", "-confirm",
    "-update", "-validate", "-reset", "-activate",
    // Vietnamese suspicious suffixes
    "-hotro", "-dangky", "-nhanthuong", "-khuyenmai",
    "-tuyendung", "-hoanthue", "-trocap", "-kichcau",
    "-thanhtoan", "-giaingan", "-xacnhan", "-xacminh",
    "-baomat", "-dangnhap",
];

/// Detect generic phishing domains that don't contain known brand names.
///
/// Catches domains like `toll-settle-now.com`, `yodel-payment.com`,
/// `parcel-hold.co.uk`, `verify-garena.net` by looking for combinations
/// of action words, financial words, and lure words in the domain.
fn detect_generic_phishing_domain(url: &str) -> bool {
    let lower = url.to_lowercase();
    let domain_part = lower
        .strip_prefix("https://")
        .or_else(|| lower.strip_prefix("http://"))
        .unwrap_or(&lower);
    let domain = domain_part.split('/').next().unwrap_or(domain_part);
    let domain_no_port = domain.split(':').next().unwrap_or(domain);

    // Skip if it's a known shortener
    if URL_SHORTENERS.iter().any(|&s| domain_no_port.contains(s)) {
        return false;
    }

    // Skip if it's a known legitimate brand domain
    for (_, legit_domains) in KNOWN_BRANDS {
        for &legit in legit_domains.iter() {
            if domain_no_port == legit || domain_no_port.ends_with(&format!(".{}", legit)) {
                return false;
            }
        }
    }

    // 1. Hyphenated domain with suspicious suffix (e.g., toll-settle-now.com)
    if domain_no_port.contains('-') {
        for &suffix in SUSPICIOUS_DOMAIN_SUFFIXES {
            if domain_no_port.contains(suffix) {
                return true;
            }
        }
    }

    // 2. Domain containing both an action word and a lure/financial word
    let has_action = PHISHING_ACTION_WORDS.iter().any(|&a| domain_no_port.contains(a));
    let has_lure = PHISHING_LURE_WORDS.iter().any(|&l| domain_no_port.contains(l));
    let has_financial = PHISHING_FINANCIAL_WORDS.iter().any(|&f| domain_no_port.contains(f));

    if has_action && (has_lure || has_financial) {
        return true;
    }

    // 3. Hyphenated domain with financial word (e.g., parcel-hold.co.uk/payment)
    if domain_no_port.contains('-') && (has_financial || has_lure) {
        return true;
    }

    // 4. Domain with suspicious TLD + action word
    let has_suspicious_tld = SUSPICIOUS_TLDS.iter().any(|&tld| domain_no_port.ends_with(tld));
    if has_suspicious_tld && (has_action || has_financial) {
        return true;
    }

    false
}

/// Extract the domain from a URL string.
fn extract_domain(url: &str) -> String {
    let lower = url.to_lowercase();
    let domain_part = lower
        .strip_prefix("https://")
        .or_else(|| lower.strip_prefix("http://"))
        .unwrap_or(&lower);
    domain_part.split('/').next().unwrap_or(domain_part).to_string()
}

/// Analyze URLs in text for suspicious patterns.
///
/// Returns an IndicatorHit if any suspicious URL patterns are found.
/// Also returns whether all URLs are from allowlisted domains.
pub fn analyze_urls(text: &str) -> Option<IndicatorHit> {
    let urls = extract_urls(text);
    if urls.is_empty() {
        return None;
    }

    let mut suspicious_count = 0usize;

    for url in &urls {
        let lower = url.to_lowercase();
        let domain = extract_domain(url);
        let domain_no_port = domain.split(':').next().unwrap_or(&domain);

        // Skip allowlisted domains entirely — they are known legitimate
        if allowlist::is_allowed_domain(domain_no_port) {
            continue;
        }

        // Check for lookalike domains (brand impersonation)
        if detect_lookalike_domain(url) {
            suspicious_count += 2; // Brand impersonation is highly suspicious
        }

        // Check for generic phishing domains (no brand name but suspicious pattern)
        if detect_generic_phishing_domain(url) {
            suspicious_count += 2;
        }

        // Check for URL shorteners (match against domain only, not full URL path)
        if URL_SHORTENERS.iter().any(|&s| domain_no_port == s || domain_no_port.ends_with(&format!(".{}", s))) {
            suspicious_count += 1;
        }

        // Check for raw IP addresses in URLs
        if IP_IN_URL_RE.is_match(&lower) {
            suspicious_count += 2; // IP in URL is more suspicious
        }

        // Check for suspicious TLDs
        if SUSPICIOUS_TLDS.iter().any(|&tld| lower.ends_with(tld) || lower.contains(&format!("{}/", tld))) {
            suspicious_count += 1;
        }

        // Check for excessive subdomains (e.g., a.b.c.d.example.com)
        let dot_count = domain_no_port.matches('.').count();
        if dot_count >= 4 {
            suspicious_count += 1;
        }

        // Check for @ symbol in URL (used to obscure real destination)
        // Only flag when the part before @ contains a dot (looks like a domain
        // being used to trick the user, e.g., https://google.com@evil.com).
        // Legitimate user:pass@domain URLs have credentials before @, not domains.
        if lower.contains('@') && !lower.starts_with("https://@") && !lower.starts_with("http://@") {
            if let Some(at_pos) = lower.find('@') {
                let before_at = &lower[lower.find("://").unwrap_or(0)..at_pos];
                let after_at = &lower[at_pos + 1..];
                // Flag only if before_at looks like a domain (contains a dot)
                // and after_at also contains a dot (different destination)
                if before_at.contains('.') && after_at.contains('.') {
                    suspicious_count += 2;
                }
            }
        }
    }

    if suspicious_count == 0 {
        return None;
    }

    let strength = match suspicious_count {
        1 => IndicatorStrength::Medium,
        _ => IndicatorStrength::High,
    };

    Some(IndicatorHit {
        id: crate::ontology::IndicatorId::LinkSuspicious,
        strength,
        match_count: suspicious_count,
    })
}

/// Check if all URLs in the text are from allowlisted domains.
pub fn all_urls_allowed(text: &str) -> bool {
    let urls = extract_urls(text);
    if urls.is_empty() {
        return false;
    }
    urls.iter().all(|url| {
        let domain = extract_domain(url);
        let domain_no_port = domain.split(':').next().unwrap_or(&domain);
        allowlist::is_allowed_domain(domain_no_port)
    })
}
