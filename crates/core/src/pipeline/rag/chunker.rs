//! Document chunker for RAG.
//!
//! Splits documents into overlapping chunks suitable for embedding.

use serde::{Deserialize, Serialize};

/// A document chunk with metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RagChunk {
    /// Chunk text content.
    pub text: String,
    /// Source file path.
    pub source: String,
    /// Page number (if applicable).
    pub page: Option<u32>,
    /// Section heading (if detected).
    pub section: Option<String>,
    /// Chunk index within the source document.
    pub chunk_index: usize,
}

/// Chunk a document into overlapping pieces.
///
/// `target_len` is the target chunk size in characters.
/// `overlap` is the overlap between consecutive chunks in characters.
pub fn chunk_document(
    text: &str,
    source: &str,
    target_len: usize,
    overlap: usize,
) -> Vec<RagChunk> {
    if text.len() <= target_len {
        return vec![RagChunk {
            text: text.to_string(),
            source: source.to_string(),
            page: None,
            section: detect_section(text),
            chunk_index: 0,
        }];
    }

    let mut chunks = Vec::new();
    let mut start = 0;
    let mut idx = 0;

    while start < text.len() {
        let end = (start + target_len).min(text.len());

        // Try to break at sentence boundary
        let mut break_point = end;
        if break_point < text.len() {
            for i in (start + target_len / 2..end).rev() {
                if let Some(&c) = text.as_bytes().get(i) {
                    if c == b'.' || c == b'\n' || c == b';' {
                        break_point = i + 1;
                        break;
                    }
                }
            }
        }

        let chunk_text = &text[start..break_point];
        chunks.push(RagChunk {
            text: chunk_text.to_string(),
            source: source.to_string(),
            page: None,
            section: detect_section(chunk_text),
            chunk_index: idx,
        });

        idx += 1;
        start = if break_point > overlap {
            break_point - overlap
        } else {
            break_point
        };
    }

    chunks
}

/// Detect a section heading from the first line of a chunk.
fn detect_section(text: &str) -> Option<String> {
    let first_line = text.lines().next()?;
    let trimmed = first_line.trim();

    // Markdown-style heading
    if trimmed.starts_with('#') {
        return Some(trimmed.trim_start_matches('#').trim().to_string());
    }

    // ALL CAPS heading (short)
    if trimmed.len() < 80 && trimmed.chars().all(|c| c.is_uppercase() || c.is_whitespace() || c == ':') && !trimmed.is_empty() {
        return Some(trimmed.trim_end_matches(':').to_string());
    }

    None
}
