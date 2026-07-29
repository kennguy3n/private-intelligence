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
            // Also check if a part starts with the brand name followed by
            // additional chars (e.g., "gdtalert" starts with "gdt").
            // This catches lookalike domains that prepend the brand name
            // to action words or other suffixes.
            if part.starts_with(brand) && part.len() > brand.len() {
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
    ".vip", ".icu", ".buzz", ".fun", ".site", ".online",
    ".store", ".tech", ".space", ".live", ".media",
    ".info", ".biz", ".rest", ".bar", ".cam",
];

/// Regex to extract URLs from text (with http:// or https:// prefix).
static URL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"https?://[^\s<>\[\]{}|\\^`]+")
        .expect("invalid URL regex")
});

/// Regex to extract bare domains (without http:// prefix) from text.
/// Matches domains that have at least one dot and a known TLD suffix.
/// Supports both single-dot (domain.tld) and multi-dot (sub.domain.tld) forms.
static BARE_DOMAIN_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*\.[a-z]{2,}(?:/[^\s]*)?")
        .expect("invalid bare domain regex")
});

/// Regex to detect raw IP addresses in URLs.
static IP_IN_URL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
        .expect("invalid IP URL regex")
});

/// Extract all URLs from text, including bare domains without http:// prefix.
pub fn extract_urls(text: &str) -> Vec<String> {
    let mut urls: Vec<String> = URL_RE
        .find_iter(text)
        .map(|m| m.as_str().to_string())
        .collect();

    // Also extract bare domains (without protocol prefix)
    // These are common in scam SMS where the URL is written as
    // "vietnamobile-confirm.net" without http://
    let lower = text.to_lowercase();
    for m in BARE_DOMAIN_RE.find_iter(&lower) {
        let bare = m.as_str();
        // Skip if already captured by URL_RE (with protocol)
        let already_captured = urls.iter().any(|u| u.to_lowercase().contains(bare));
        if !already_captured {
            // Add with synthetic http:// prefix for consistent processing
            urls.push(format!("http://{}", bare));
        }
    }

    urls
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
    ("vib", &["vib.com.vn"]),
    ("namabank", &["namabank.com.vn"]),
    ("ocb", &["ocb.com.vn"]),
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
    ("fpt", &["fpt.com", "fpt.vn", "fpt.com.vn"]),
    ("winmart", &["winmart.vn"]),
    ("thegioididong", &["thegioididong.com"]),
    ("dien may xanh", &["dienmayxanh.com"]),
    ("chotot", &["chotot.com"]),
    ("zalopay", &["zalopay.vn"]),
    ("binance", &["binance.com", "binance.vn"]),
    // International payment/services
    ("paypal", &["paypal.com"]),
    ("stripe", &["stripe.com"]),
    ("wise", &["wise.com"]),
    ("revolut", &["revolut.com"]),
    // Vietnam additional
    ("tcbs", &["tcbs.com.vn"]),
    ("vndirect", &["vndirect.com.vn"]),
    ("vn30", &["vn30.com.vn"]),
    ("ssi", &["ssi.com.vn"]),
    ("hsc", &["hsc.com.vn"]),
    ("vps", &["vps.com.vn"]),
    ("dnse", &["dnse.com.vn"]),
    ("best express", &["best-inc.com", "best-inc.vn"]),
    ("best", &["best-inc.com", "best-inc.vn"]),
    ("vnid", &["vnid.vn"]),
    ("vneid", &["dichvucong.gov.vn"]),
    ("dvc", &["dichvucong.gov.vn"]),
    ("dichvucong", &["dichvucong.gov.vn"]),
    ("kho bac", &["kbnn.gov.vn"]),
    ("kho bạc", &["kbnn.gov.vn"]),
    // Additional tech/consumer brands
    ("xiaomi", &["mi.com", "xiaomi.com"]),
    ("dell", &["dell.com"]),
    ("asus", &["asus.com"]),
    ("acer", &["acer.com"]),
    ("hp", &["hp.com"]),
    ("lenovo", &["lenovo.com"]),
    ("blackpink", &[]),
    ("concert", &[]),
    ("tiger brokers", &["tigerbrokers.com", "tigerbrokers.com.sg"]),
    ("tigerbrokers", &["tigerbrokers.com", "tigerbrokers.com.sg"]),
    ("spx", &["spx.co", "spx.vn"]),
    ("spx express", &["spx.co", "spx.vn"]),
    ("sendo", &["sendo.vn"]),
    ("gdt", &["gdt.gov.vn", "tax.gov.vn"]),
    ("tong cuc thue", &["gdt.gov.vn", "tax.gov.vn"]),
    ("tổng cục thuế", &["gdt.gov.vn", "tax.gov.vn"]),
    ("skillsfuture", &["skillsfuture.gov.sg", "skillsfuture.sg"]),
    ("people's association", &["pa.gov.sg"]),
    ("pa", &["pa.gov.sg"]),
    ("ninja van", &["ninjavan.co", "ninjavan.com"]),
    ("ninjavan", &["ninjavan.co", "ninjavan.com"]),
    ("mas", &["mas.gov.sg"]),
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
    //    Flag even without action words — if a brand name appears in a
    //    domain that isn't the brand's legitimate domain, it's suspicious.
    for (brand, legit_domains) in KNOWN_BRANDS {
        if domain_contains_brand(domain_no_port, brand) {
            let is_legit = legit_domains
                .iter()
                .any(|&legit| domain_no_port == legit || domain_no_port.ends_with(&format!(".{}", legit)));
            if !is_legit {
                // Brands with empty legit_domains (e.g., "concert") always flag
                if legit_domains.is_empty() {
                    return true;
                }
                // Check if the domain TLD differs from all legit domains
                // e.g., sacombank.co vs sacombank.com.vn
                let domain_tld = domain_no_port.rsplit('.').next().unwrap_or("");
                let legit_tlds: Vec<&str> = legit_domains.iter()
                    .map(|d| d.rsplit('.').next().unwrap_or(""))
                    .collect();
                let has_action = PHISHING_ACTION_WORDS.iter().any(|&a| domain_no_port.contains(a));
                let has_suspicious_tld = SUSPICIOUS_TLDS.iter().any(|&tld| domain_no_port.ends_with(tld));
                let has_hyphen = domain_no_port.contains('-');
                let tld_mismatch = !legit_tlds.contains(&domain_tld);
                // Flag if: action word + suspicious TLD, or hyphenated, or TLD mismatch
                if has_action || has_suspicious_tld || has_hyphen || tld_mismatch {
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
    // Additional suspicious suffixes
    "-giare", "-flashsale", "-reinvest", "-bonus",
    "-account", "-wallet", "-login", "-signin",
    "-claim", "-collect", "-redeem", "-reward",
    "-cashback", "-hoantien", "-nhan", "-confirm",
    "-giahan", "-dangky", "-kichhoat",
];

/// Check if two strings differ by at most 1 edit (insertion, deletion, or substitution).
fn is_close_typo(a: &str, b: &str) -> bool {
    let a_chars: Vec<char> = a.chars().collect();
    let b_chars: Vec<char> = b.chars().collect();
    let (la, lb) = (a_chars.len(), b_chars.len());

    if la == lb {
        // Check substitution: at most 1 char differs
        let diffs = a_chars.iter().zip(b_chars.iter()).filter(|(x, y)| x != y).count();
        return diffs <= 1;
    }

    if la.abs_diff(lb) == 1 {
        // Check insertion/deletion: at most 1 char difference
        let (longer, shorter) = if la > lb { (&a_chars, &b_chars) } else { (&b_chars, &a_chars) };
        let mut skip = 0;
        let mut diffs = 0;
        for i in 0..longer.len() {
            if skip < shorter.len() && longer[i] == shorter[skip] {
                skip += 1;
            } else {
                diffs += 1;
            }
        }
        return diffs <= 1;
    }

    false
}

/// Detect typosquatting domains — domains that are a close edit distance
/// match to a known brand name but on a different TLD.
fn detect_typosquat_domain(url: &str) -> bool {
    let lower = url.to_lowercase();
    let domain_part = lower
        .strip_prefix("https://")
        .or_else(|| lower.strip_prefix("http://"))
        .unwrap_or(&lower);
    let domain = domain_part.split('/').next().unwrap_or(domain_part);
    let domain_no_port = domain.split(':').next().unwrap_or(domain);

    // Get the main domain part (before the TLD)
    let parts: Vec<&str> = domain_no_port.split('.').collect();
    if parts.len() < 2 {
        return false;
    }

    // Check the main label (second-to-last part for simple domains,
    // or the last non-TLD part)
    let main_label = if parts.len() >= 2 { parts[parts.len() - 2] } else { parts[0] };

    for (brand, legit_domains) in KNOWN_BRANDS {
        // Only check brands with ≥5 chars to avoid false positives
        if brand.len() < 5 || !brand.is_ascii() || brand.contains(' ') || brand.contains('.') {
            continue;
        }

        // Check if this is a close typo of the brand
        if !is_close_typo(main_label, brand) {
            continue;
        }

        // Make sure it's not actually a legitimate domain
        let is_legit = legit_domains
            .iter()
            .any(|&legit| domain_no_port == legit || domain_no_port.ends_with(&format!(".{}", legit)));
        if is_legit {
            continue;
        }

        return true;
    }

    false
}

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
    let domain = domain_part.split('/').next().unwrap_or(domain_part);
    // Strip trailing punctuation that may be captured from sentence context
    domain.trim_end_matches(|c: char| !c.is_ascii_alphanumeric() && c != '.').trim_end_matches('.').to_string()
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

        // Check for typosquatting domains (close edit distance to known brands)
        if detect_typosquat_domain(url) {
            suspicious_count += 2;
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
