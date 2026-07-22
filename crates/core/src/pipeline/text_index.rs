//! Text index for semantic search using e5-small embeddings.
//!
//! Stores pre-computed text embeddings and provides cosine similarity
//! search to find the most relevant passages for a query.

use serde::{Deserialize, Serialize};

/// A single indexed text passage with its embedding and metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TextEntry {
    /// Unique identifier (e.g., document ID or chunk index).
    pub id: String,
    /// The text passage that was embedded.
    pub text: String,
    /// Optional source reference (e.g., file path, URL, channel name).
    pub source: Option<String>,
    /// L2-normalized e5-small embedding vector.
    pub embedding: Vec<f32>,
}

/// An index of text embeddings for fast semantic similarity search.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TextIndex {
    /// Indexed text passages.
    entries: Vec<TextEntry>,
}

/// A semantic search result with similarity score.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TextSearchHit {
    pub id: String,
    pub text: String,
    pub source: Option<String>,
    pub score: f32,
}

impl TextIndex {
    /// Create a new empty index.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a text entry to the index.
    pub fn add(&mut self, entry: TextEntry) {
        self.entries.push(entry);
    }

    /// Add a text passage with its embedding.
    pub fn add_text(&mut self, id: &str, text: &str, embedding: Vec<f32>, source: Option<&str>) {
        self.entries.push(TextEntry {
            id: id.to_string(),
            text: text.to_string(),
            source: source.map(|s| s.to_string()),
            embedding,
        });
    }

    /// Number of indexed passages.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the index is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Get all entries in the index (for clustering, iteration, etc.).
    pub fn entries(&self) -> &[TextEntry] {
        &self.entries
    }

    /// Search the index for the top-k most semantically similar passages.
    ///
    /// `query_embedding` should be L2-normalized for correct cosine similarity.
    /// Returns hits sorted by descending similarity score.
    pub fn search(&self, query_embedding: &[f32], top_k: usize) -> Vec<TextSearchHit> {
        let mut hits: Vec<TextSearchHit> = self
            .entries
            .iter()
            .map(|entry| {
                let score = super::image_index::cosine_similarity(query_embedding, &entry.embedding);
                TextSearchHit {
                    id: entry.id.clone(),
                    text: entry.text.clone(),
                    source: entry.source.clone(),
                    score,
                }
            })
            .collect();

        hits.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        hits.into_iter().take(top_k).collect()
    }

    /// Serialize the index to JSON.
    pub fn to_json(&self) -> serde_json::Result<String> {
        serde_json::to_string(self)
    }

    /// Deserialize an index from JSON.
    pub fn from_json(json: &str) -> serde_json::Result<Self> {
        serde_json::from_str(json)
    }

    /// Build an index from a list of (id, text, embedding) tuples.
    pub fn from_entries(
        entries: impl IntoIterator<Item = (String, String, Vec<f32>)>,
    ) -> Self {
        let mut index = Self::new();
        for (id, text, embedding) in entries {
            index.add_text(&id, &text, embedding, None);
        }
        index
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_text_index_search() {
        let mut index = TextIndex::new();
        index.add_text("doc1", "The cat sat on the mat", vec![1.0, 0.0, 0.0], None);
        index.add_text("doc2", "The dog ran in the park", vec![0.0, 1.0, 0.0], None);
        index.add_text("doc3", "A cat playing with yarn", vec![0.9, 0.1, 0.0], None);

        let query = vec![1.0, 0.0, 0.0];
        let hits = index.search(&query, 2);

        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0].id, "doc1");
        assert!((hits[0].score - 1.0).abs() < 1e-6);
        assert_eq!(hits[1].id, "doc3");
    }

    #[test]
    fn test_text_index_empty() {
        let index = TextIndex::new();
        let hits = index.search(&[1.0, 0.0], 5);
        assert!(hits.is_empty());
    }

    #[test]
    fn test_text_index_json_roundtrip() {
        let mut index = TextIndex::new();
        index.add_text("doc1", "test passage", vec![0.5, 0.5], Some("source.md"));
        let json = index.to_json().unwrap();
        let restored = TextIndex::from_json(&json).unwrap();
        assert_eq!(restored.len(), 1);
        let hits = restored.search(&[1.0, 0.0], 1);
        assert_eq!(hits[0].id, "doc1");
        assert_eq!(hits[0].source.as_deref(), Some("source.md"));
    }

    #[test]
    fn test_text_index_with_source() {
        let mut index = TextIndex::new();
        index.add_text("d1", "hello world", vec![1.0, 0.0], Some("file.txt"));
        let hits = index.search(&[1.0, 0.0], 1);
        assert_eq!(hits[0].source.as_deref(), Some("file.txt"));
    }
}
