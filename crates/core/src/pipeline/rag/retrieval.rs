//! RAG retrieval.
//!
//! Retrieves relevant document chunks for a query using semantic search.

use crate::Result;
use crate::pipeline::text_index::{TextIndex, TextSearchHit};

/// Retrieve top-k relevant chunks for a query.
pub async fn retrieve(
    engine: &mut crate::AiEngine,
    query: &str,
    index: &TextIndex,
    top_k: usize,
) -> Result<Vec<TextSearchHit>> {
    let spec = crate::model_manager::ModelSpec::e5_small_int8();
    engine.ensure_model(&spec).await?;

    let query_emb = engine.run_embedding(query).await?;
    Ok(index.search(&query_emb, top_k))
}
