//! RAG index management.
//!
//! Manages a TextIndex with RAG-specific metadata (source, page, section).

use crate::Result;
use crate::pipeline::text_index::TextIndex;
use super::chunker::RagChunk;
use std::path::Path;

/// Build a TextIndex from RAG chunks by embedding each chunk.
pub async fn build_index(
    engine: &mut crate::AiEngine,
    chunks: &[RagChunk],
) -> Result<TextIndex> {
    let spec = crate::model_manager::ModelSpec::e5_small_int8();
    engine.ensure_model(&spec).await?;

    let mut index = TextIndex::new();

    for chunk in chunks {
        let emb = engine.run_embedding(&chunk.text).await?;
        let id = format!("{}#chunk_{}", chunk.source, chunk.chunk_index);
        let source = if let Some(section) = &chunk.section {
            format!("{} — {}", chunk.source, section)
        } else {
            chunk.source.clone()
        };
        index.add_text(&id, &chunk.text, emb, Some(&source));
    }

    tracing::info!(chunks = index.len(), "RAG index built");
    Ok(index)
}

/// Save a RAG index to disk.
pub fn save_index(index: &TextIndex, path: &Path) -> Result<()> {
    let json = index.to_json().map_err(|e| crate::ZkAiError::Serialization(e.to_string()))?;
    std::fs::write(path, json).map_err(crate::ZkAiError::Io)
}

/// Load a RAG index from disk.
pub fn load_index(path: &Path) -> Result<TextIndex> {
    let json = std::fs::read_to_string(path).map_err(crate::ZkAiError::Io)?;
    TextIndex::from_json(&json).map_err(|e| crate::ZkAiError::Serialization(e.to_string()))
}
