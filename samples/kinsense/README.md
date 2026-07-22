# KinSense — Semantic Perception with On-Device AI

A standalone demonstration of **zk-ai**'s semantic perception capabilities.
KinSense shows how to build embedding-based search, image search, document
clustering, auto-tagging, and find-similar workflows — all running locally
on-device with no network calls.

## Demonstrated Capabilities

| Feature | zk-ai API | Description |
|---------|----------|-------------|
| Semantic Search | `semantic_search` | Search documents by meaning, not keywords |
| Embedding Extraction | `run_embedding` | Get L2-normalized embedding vectors for text |
| Text Index | `TextIndex` | Build and query a local semantic search index |
| Image Search | `image_search` / `ImageIndex` | CLIP-based image search by text query |
| Cosine Similarity | `cosine_similarity` | Compare embedding vectors directly |
| Auto-Tag | `auto_tag` | Automatically tag documents with topic labels |
| Find Similar | `find_similar` | Find top-k similar documents in an index |
| Cluster | `cluster` | Group documents into topic clusters |
| Rerank | `rerank` | Rerank search results for improved precision |

## Run

```bash
cargo run -p kinsense
```

The demo creates a temporary model cache directory, initializes the `AiEngine`,
builds local indices, and runs each perception pipeline against sample data.
