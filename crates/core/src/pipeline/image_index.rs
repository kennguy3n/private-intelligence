//! Image index for CLIP-based image search.
//!
//! Stores pre-computed image embeddings and provides cosine similarity
//! search to find the most relevant images for a text query.

use serde::{Deserialize, Serialize};

/// A single indexed image with its embedding and metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageEntry {
    /// Unique identifier (e.g., file path or URL).
    pub id: String,
    /// Human-readable caption or description.
    pub caption: String,
    /// L2-normalized CLIP embedding vector.
    pub embedding: Vec<f32>,
}

/// An index of image embeddings for fast similarity search.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ImageIndex {
    /// Indexed images.
    entries: Vec<ImageEntry>,
}

/// A search result with similarity score.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageSearchHit {
    pub id: String,
    pub caption: String,
    pub score: f32,
}

impl ImageIndex {
    /// Create a new empty index.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an image entry to the index.
    pub fn add(&mut self, entry: ImageEntry) {
        self.entries.push(entry);
    }

    /// Add an image with its embedding and caption.
    pub fn add_image(&mut self, id: &str, caption: &str, embedding: Vec<f32>) {
        self.entries.push(ImageEntry {
            id: id.to_string(),
            caption: caption.to_string(),
            embedding,
        });
    }

    /// Number of indexed images.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the index is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Search the index for the top-k most similar images.
    ///
    /// `query_embedding` should be L2-normalized for correct cosine similarity.
    /// Returns hits sorted by descending similarity score.
    pub fn search(&self, query_embedding: &[f32], top_k: usize) -> Vec<ImageSearchHit> {
        let mut hits: Vec<ImageSearchHit> = self
            .entries
            .iter()
            .map(|entry| {
                let score = cosine_similarity(query_embedding, &entry.embedding);
                ImageSearchHit {
                    id: entry.id.clone(),
                    caption: entry.caption.clone(),
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

    /// Build an index from a list of (id, caption, embedding) tuples.
    pub fn from_entries(entries: impl IntoIterator<Item = (String, String, Vec<f32>)>) -> Self {
        let mut index = Self::new();
        for (id, caption, embedding) in entries {
            index.add_image(&id, &caption, embedding);
        }
        index
    }
}

/// Compute cosine similarity between two vectors.
///
/// Both vectors should be L2-normalized for correct results, but this
/// function handles un-normalized vectors as well.
pub fn cosine_similarity(a: &[f32], b: &[f32]) -> f32 {
    if a.is_empty() || b.is_empty() || a.len() != b.len() {
        return 0.0;
    }

    let dot: f32 = a.iter().zip(b.iter()).map(|(x, y)| x * y).sum();
    let norm_a: f32 = a.iter().map(|v| v * v).sum::<f32>().sqrt();
    let norm_b: f32 = b.iter().map(|v| v * v).sum::<f32>().sqrt();

    if norm_a > 0.0 && norm_b > 0.0 {
        dot / (norm_a * norm_b)
    } else {
        0.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cosine_similarity_identical() {
        let a = vec![1.0, 0.0, 0.0];
        let b = vec![1.0, 0.0, 0.0];
        let sim = cosine_similarity(&a, &b);
        assert!((sim - 1.0).abs() < 1e-6);
    }

    #[test]
    fn test_cosine_similarity_orthogonal() {
        let a = vec![1.0, 0.0];
        let b = vec![0.0, 1.0];
        let sim = cosine_similarity(&a, &b);
        assert!(sim.abs() < 1e-6);
    }

    #[test]
    fn test_cosine_similarity_opposite() {
        let a = vec![1.0, 0.0];
        let b = vec![-1.0, 0.0];
        let sim = cosine_similarity(&a, &b);
        assert!((sim + 1.0).abs() < 1e-6);
    }

    #[test]
    fn test_image_index_search() {
        let mut index = ImageIndex::new();
        index.add_image("img1", "a cat sitting on a mat", vec![1.0, 0.0, 0.0]);
        index.add_image("img2", "a dog running in the park", vec![0.0, 1.0, 0.0]);
        index.add_image("img3", "a cat playing with yarn", vec![0.9, 0.1, 0.0]);

        let query = vec![1.0, 0.0, 0.0]; // "cat" query
        let hits = index.search(&query, 2);

        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0].id, "img1");
        assert!((hits[0].score - 1.0).abs() < 1e-6);
        assert_eq!(hits[1].id, "img3");
    }

    #[test]
    fn test_image_index_empty() {
        let index = ImageIndex::new();
        let hits = index.search(&[1.0, 0.0], 5);
        assert!(hits.is_empty());
    }

    #[test]
    fn test_image_index_json_roundtrip() {
        let mut index = ImageIndex::new();
        index.add_image("img1", "test caption", vec![0.5, 0.5]);
        let json = index.to_json().unwrap();
        let restored = ImageIndex::from_json(&json).unwrap();
        assert_eq!(restored.len(), 1);
        let hits = restored.search(&[1.0, 0.0], 1);
        assert_eq!(hits[0].id, "img1");
    }
}
