//! URL and link analysis for suspicious link detection.
//!
//! Detects shortened URLs, lookalike domains, IP addresses in URLs,
//! and other suspicious link patterns — all without any network calls.

use std::sync::LazyLock;
use regex_lite::Regex;
use crate::ontology::{IndicatorHit, IndicatorStrength};

/// Known URL shortener domains.
const URL_SHORTENERS: &[&str] = &[
    "bit.ly", "tinyurl.com", "t.co", "shorte.st", "cutt.ly",
    "ow.ly", "is.gd", "buff.ly", "rebrand.ly", "rb.gy",
    "s.id", "lnk.to", "tiny.cc", "soo.gd", "t.ly",
];

/// Suspicious TLDs commonly used in scam URLs.
const SUSPICIOUS_TLDS: &[&str] = &[
    ".top", ".xyz", ".click", ".loan", ".work", ".men",
    ".country", ".kim", ".science", ".review",
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

/// Analyze URLs in text for suspicious patterns.
///
/// Returns an IndicatorHit if any suspicious URL patterns are found.
pub fn analyze_urls(text: &str) -> Option<IndicatorHit> {
    let urls = extract_urls(text);
    if urls.is_empty() {
        return None;
    }

    let mut suspicious_count = 0usize;

    for url in &urls {
        let lower = url.to_lowercase();

        // Check for URL shorteners
        if URL_SHORTENERS.iter().any(|&s| lower.contains(s)) {
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
        let domain_part = lower
            .strip_prefix("https://")
            .or_else(|| lower.strip_prefix("http://"))
            .unwrap_or(&lower);
        let domain = domain_part.split('/').next().unwrap_or(domain_part);
        let dot_count = domain.matches('.').count();
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
