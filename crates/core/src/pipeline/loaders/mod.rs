//! Document loaders for text extraction from various file formats.
//!
//! Currently supports plain text, HTML, and basic PDF text extraction.
//! No new model required — these are pure text processing utilities.

pub mod pdf;
pub mod html;
pub mod txt;

use crate::Result;
use crate::ZkAiError;
use std::path::Path;

/// Extract text content from a file based on its extension.
pub fn extract_text(path: &Path) -> Result<String> {
    let ext = path.extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_lowercase())
        .unwrap_or_default();

    match ext.as_str() {
        "txt" | "md" | "markdown" => txt::extract(path),
        "html" | "htm" => html::extract(path),
        "pdf" => pdf::extract(path),
        _ => {
            // Fallback: try reading as UTF-8 text
            std::fs::read_to_string(path)
                .map_err(|e| ZkAiError::Io(e))
        }
    }
}
