//! Document clustering pipeline.
//!
//! Clusters documents by topic using e5-small embeddings + k-means with
//! cosine similarity. Pure CPU, ~1ms per 100 docs. No new model required.

use crate::Result;
use crate::pipeline::{TaskOptions, TaskResult, Task};
use crate::AiEngine;
use crate::model_manager::ModelSpec;
use crate::pipeline::text_index::TextIndex;
use crate::pipeline::image_index::cosine_similarity;

/// Run a clustering task.
///
/// Input: TextIndex of documents (with pre-computed embeddings).
/// Output: documents grouped into topic clusters.
pub async fn run(
    engine: &mut AiEngine,
    index: &TextIndex,
    num_clusters: usize,
    _options: TaskOptions,
) -> Result<TaskResult> {
    if index.is_empty() {
        return Ok(TaskResult {
            output: "No documents to cluster.".to_string(),
            task: Task::Cluster,
            model: "none".to_string(),
            adapter: None,
            duration_ms: 0,
            input_tokens: 0,
            output_tokens: 0,
        });
    }

    let spec = ModelSpec::e5_small_int8();
    engine.ensure_model(&spec).await?;

    let start = std::time::Instant::now();

    let all_entries = index.entries();

    if all_entries.is_empty() {
        return Ok(TaskResult {
            output: "No documents to cluster.".to_string(),
            task: Task::Cluster,
            model: "multilingual-e5-small-int8".to_string(),
            adapter: None,
            duration_ms: start.elapsed().as_millis() as u64,
            input_tokens: 0,
            output_tokens: 0,
        });
    }

    let k = num_clusters.min(all_entries.len()).max(1);

    // Extract embeddings from entries
    let embeddings: Vec<&[f32]> = all_entries.iter().map(|e| e.embedding.as_slice()).collect();

    let assignments = kmeans_cluster(&embeddings, k);

    // Group entries by cluster
    let mut clusters: Vec<Vec<&crate::pipeline::text_index::TextEntry>> = vec![Vec::new(); k];
    for (i, &cluster_idx) in assignments.iter().enumerate() {
        clusters[cluster_idx].push(&all_entries[i]);
    }

    let mut output = String::new();
    for (i, cluster) in clusters.iter().enumerate() {
        if cluster.is_empty() {
            continue;
        }
        output.push_str(&format!("Cluster {} ({} items):\n", i + 1, cluster.len()));
        for entry in cluster {
            let source = entry.source.as_deref().unwrap_or(&entry.id);
            output.push_str(&format!("  - {}\n", source));
        }
        output.push('\n');
    }

    let duration_ms = start.elapsed().as_millis() as u64;

    Ok(TaskResult {
        output,
        task: Task::Cluster,
        model: "multilingual-e5-small-int8".to_string(),
        adapter: None,
        duration_ms,
        input_tokens: 0,
        output_tokens: k as u32,
    })
}

/// K-means clustering using cosine similarity on embedding vectors.
///
/// Since embeddings are L2-normalized, cosine similarity = dot product.
/// Centroids are computed as the mean of member embeddings and then
/// L2-normalized so that cosine similarity remains valid.
///
/// Returns a vector of cluster assignments (one per entry).
fn kmeans_cluster(embeddings: &[&[f32]], k: usize) -> Vec<usize> {
    let n = embeddings.len();
    if n == 0 || k == 0 {
        return vec![];
    }
    if k >= n {
        return (0..n).collect();
    }

    let dim = embeddings[0].len();

    // Initialize centroids using k-means++ for better convergence
    let mut centroids = kmeans_plus_plus_init(embeddings, k);

    let mut assignments = vec![0usize; n];
    let max_iterations = 20;

    for _ in 0..max_iterations {
        let mut changed = false;

        // Assignment step: assign each point to nearest centroid
        for (i, emb) in embeddings.iter().enumerate() {
            let mut best = 0;
            let mut best_sim = -2.0f32; // cosine sim range is [-1, 1]
            for (j, centroid) in centroids.iter().enumerate() {
                let sim = cosine_similarity(emb, centroid);
                if sim > best_sim {
                    best_sim = sim;
                    best = j;
                }
            }
            if assignments[i] != best {
                assignments[i] = best;
                changed = true;
            }
        }

        if !changed {
            break;
        }

        // Update step: recompute centroids as mean of assigned points
        for j in 0..k {
            let members: Vec<usize> = (0..n).filter(|&i| assignments[i] == j).collect();
            if members.is_empty() {
                continue;
            }

            // Sum all member embeddings
            let mut new_centroid = vec![0.0f32; dim];
            for &m in &members {
                for d in 0..dim {
                    new_centroid[d] += embeddings[m][d];
                }
            }

            // Normalize centroid to unit length for cosine similarity
            let norm: f32 = new_centroid.iter().map(|v| v * v).sum::<f32>().sqrt();
            if norm > 0.0 {
                for v in &mut new_centroid {
                    *v /= norm;
                }
            }

            centroids[j] = new_centroid;
        }
    }

    assignments
}

/// K-means++ initialization: spread initial centroids for better convergence.
fn kmeans_plus_plus_init(embeddings: &[&[f32]], k: usize) -> Vec<Vec<f32>> {
    let n = embeddings.len();
    let mut centroids = Vec::with_capacity(k);

    // Pick first centroid randomly (use first point for determinism)
    centroids.push(embeddings[0].to_vec());

    for _ in 1..k {
        // For each point, compute distance to nearest chosen centroid
        // Distance = 1 - cosine_similarity (since embeddings are normalized)
        let mut distances: Vec<f32> = embeddings.iter().map(|emb| {
            let max_sim = centroids.iter()
                .map(|c| cosine_similarity(emb, c))
                .fold(-1.0f32, f32::max);
            1.0 - max_sim
        }).collect();

        // Pick the point with the maximum distance (farthest from existing centroids)
        let best_idx = distances.iter()
            .enumerate()
            .max_by(|(_, a), (_, b)| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal))
            .map(|(i, _)| i)
            .unwrap_or(0);

        // Avoid duplicate centroids
        if distances[best_idx] < 1e-6 {
            // All remaining points are very close to existing centroids;
            // pick a random-ish point to fill the remaining centroids
            let idx = centroids.len() % n;
            centroids.push(embeddings[idx].to_vec());
        } else {
            centroids.push(embeddings[best_idx].to_vec());
        }

        // Suppress unused variable warning for distances
        let _ = &mut distances;
    }

    centroids
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kmeans_two_clusters() {
        // Two well-separated clusters in 2D
        let emb1 = vec![1.0, 0.0];
        let emb2 = vec![0.98, 0.01];
        let emb3 = vec![0.0, 1.0];
        let emb4 = vec![0.01, 0.98];
        let embeddings: Vec<&[f32]> = vec![&emb1, &emb2, &emb3, &emb4];

        let assignments = kmeans_cluster(&embeddings, 2);
        assert_eq!(assignments.len(), 4);
        // First two should be in same cluster, last two in another
        assert_eq!(assignments[0], assignments[1]);
        assert_eq!(assignments[2], assignments[3]);
        assert_ne!(assignments[0], assignments[2]);
    }

    #[test]
    fn test_kmeans_single_cluster() {
        let emb = vec![1.0, 0.0, 0.0];
        let embeddings: Vec<&[f32]> = vec![&emb];
        let assignments = kmeans_cluster(&embeddings, 1);
        assert_eq!(assignments, vec![0]);
    }

    #[test]
    fn test_kmeans_empty() {
        let embeddings: Vec<&[f32]> = vec![];
        let assignments = kmeans_cluster(&embeddings, 3);
        assert!(assignments.is_empty());
    }

    #[test]
    fn test_kmeans_k_greater_than_n() {
        let emb1 = vec![1.0, 0.0];
        let emb2 = vec![0.0, 1.0];
        let embeddings: Vec<&[f32]> = vec![&emb1, &emb2];
        let assignments = kmeans_cluster(&embeddings, 5);
        // Each point gets its own cluster
        assert_eq!(assignments.len(), 2);
    }
}
