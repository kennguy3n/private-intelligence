//! HTML text extraction loader.
//!
//! Strips HTML tags and extracts readable text content.
//! No external dependency — uses a simple tag-stripping parser.

use crate::Result;
use crate::ZkAiError;
use std::path::Path;

/// Extract text from an HTML file by stripping tags.
pub fn extract(path: &Path) -> Result<String> {
    let html = std::fs::read_to_string(path).map_err(ZkAiError::Io)?;
    Ok(strip_html(&html))
}

/// Strip HTML tags and extract readable text.
pub fn strip_html(html: &str) -> String {
    let mut result = String::with_capacity(html.len() / 2);
    let mut in_tag = false;
    let mut in_script = false;
    let chars: Vec<char> = html.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        if !in_tag {
            if chars[i] == '<' {
                // Check for script/style tags
                let remaining: String = chars[i..].iter().take(10).collect();
                let lower = remaining.to_lowercase();
                if lower.starts_with("<script") || lower.starts_with("<style") {
                    in_script = true;
                }
                in_tag = true;
            } else {
                result.push(chars[i]);
            }
        } else {
            if chars[i] == '>' {
                if in_script {
                    // Check if this is the closing script/style tag
                    let before: String = chars[i.saturating_sub(8)..i].iter().collect();
                    let lower = before.to_lowercase();
                    if lower.contains("script") || lower.contains("style") {
                        in_script = false;
                    }
                }
                in_tag = false;
            }
        }
        i += 1;
    }

    // Decode common HTML entities
    result
        .replace("&nbsp;", " ")
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&apos;", "'")
        .trim()
        .to_string()
}
