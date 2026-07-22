//! Local file indexing pipeline.
//!
//! Walks directories, extracts text from files, embeds with e5-small,
//! and stores in a TextIndex for semantic search. No new model required.

use crate::Result;
use crate::AiEngine;
use crate::model_manager::ModelSpec;
use crate::pipeline::text_index::TextIndex;
use std::path::Path;

/// Index a directory of files for semantic search.
///
/// Walks the directory recursively, extracts text from supported file formats,
/// embeds each file with e5-small, and stores in a TextIndex.
///
/// Supported formats: .txt, .md, .html, .pdf (basic extraction).
pub async fn index_directory(
    engine: &mut AiEngine,
    dir: &Path,
) -> Result<TextIndex> {
    let spec = ModelSpec::e5_small_int8();
    engine.ensure_model(&spec).await?;

    let mut index = TextIndex::new();
    let files = walk_files(dir);

    for file_path in files {
        let relative = file_path.strip_prefix(dir)
            .unwrap_or(&file_path)
            .to_string_lossy()
            .to_string();

        match super::loaders::extract_text(&file_path) {
            Ok(text) => {
                if text.is_empty() {
                    continue;
                }
                // Chunk large files
                let chunks = chunk_text(&text, 1000);
                for (i, chunk) in chunks.iter().enumerate() {
                    let emb = engine.run_embedding(chunk).await?;
                    let id = format!("{}#chunk_{}", relative, i);
                    index.add_text(&id, chunk, emb, Some(&relative));
                }
                tracing::debug!(file = %relative, "indexed file");
            }
            Err(e) => {
                tracing::warn!(file = %relative, error = %e, "failed to extract text");
            }
        }
    }

    tracing::info!(files = index.len(), "directory indexed");
    Ok(index)
}

/// Save a TextIndex to disk as JSON.
pub fn save_index(index: &TextIndex, path: &Path) -> Result<()> {
    let json = index.to_json().map_err(|e| crate::ZkAiError::Serialization(e.to_string()))?;
    std::fs::write(path, json).map_err(crate::ZkAiError::Io)
}

/// Load a TextIndex from disk.
pub fn load_index(path: &Path) -> Result<TextIndex> {
    let json = std::fs::read_to_string(path).map_err(crate::ZkAiError::Io)?;
    TextIndex::from_json(&json).map_err(|e| crate::ZkAiError::Serialization(e.to_string()))
}

/// Recursively walk a directory and return all file paths.
fn walk_files(dir: &Path) -> Vec<std::path::PathBuf> {
    let mut files = Vec::new();
    walk_files_recursive(dir, &mut files);
    files
}

fn walk_files_recursive(dir: &Path, files: &mut Vec<std::path::PathBuf>) {
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk_files_recursive(&path, files);
            } else if is_supported_file(&path) {
                files.push(path);
            }
        }
    }
}

fn is_supported_file(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|e| e.to_str()).map(|e| e.to_lowercase()).as_deref(),
        Some("txt") | Some("md") | Some("markdown") | Some("html") | Some("htm") | Some("pdf")
    )
}

/// Split text into overlapping chunks.
fn chunk_text(text: &str, target_len: usize) -> Vec<String> {
    if text.len() <= target_len {
        return vec![text.to_string()];
    }
    let mut chunks = Vec::new();
    let mut start = 0;
    while start < text.len() {
        let mut end = (start + target_len).min(text.len());
        while end < text.len() && !text.is_char_boundary(end) {
            end -= 1;
        }
        if end == start {
            end = text.len();
        }
        chunks.push(text[start..end].to_string());
        start = end;
    }
    chunks
}
