use zk_ai_core::{
    AiEngine, ModelSpec, TaskOptions,
    TextIndex, TextSearchHit,
    ImageIndex, ImageSearchHit,
    cosine_similarity,
};

const SAMPLE_DOCS: &[(&str, &str)] = &[
    ("doc1", "Rust is a systems programming language focused on safety, speed, and concurrency. It prevents segfaults and guarantees thread safety."),
    ("doc2", "Python is a high-level programming language known for its readable syntax and extensive ecosystem for data science and machine learning."),
    ("doc3", "Kubernetes is a container orchestration platform that automates deployment, scaling, and management of containerized applications."),
    ("doc4", "Docker containers package applications and their dependencies into a standardized unit for consistent deployment across environments."),
    ("doc5", "Machine learning models can be trained on-device to preserve user privacy and reduce latency compared to cloud-based inference."),
    ("doc6", "Neural networks are computational models inspired by biological neurons, used for pattern recognition and prediction tasks."),
    ("doc7", "The Transformer architecture revolutionized natural language processing with self-attention mechanisms for sequence modeling."),
    ("doc8", "Vector databases store high-dimensional embeddings for fast similarity search in recommendation and retrieval systems."),
    ("doc9", "ONNX Runtime is a cross-platform inference engine that accelerates ML models across CPU, GPU, and NPU hardware."),
    ("doc10", "Edge computing processes data near the source, reducing latency and bandwidth costs for IoT and real-time applications."),
];

const SAMPLE_QUERY: &str = "programming language for safe systems development";

const SAMPLE_IMAGES: &[(&str, &str, &[f32])] = &[
    ("img1", "a golden retriever playing fetch in a sunny park", &[1.0, 0.1, 0.0, 0.0, 0.05]),
    ("img2", "a cat sleeping on a windowsill with sunlight", &[0.8, 0.0, 0.1, 0.0, 0.0]),
    ("img3", "a mountain landscape with snow peaks at sunset", &[0.0, 0.0, 0.0, 1.0, 0.1]),
    ("img4", "a dog running through a field of flowers", &[0.95, 0.05, 0.0, 0.0, 0.0]),
    ("img5", "a city skyline at night with illuminated buildings", &[0.0, 0.0, 0.0, 0.0, 1.0]),
    ("img6", "a kitten playing with a ball of yarn", &[0.85, 0.0, 0.05, 0.0, 0.0]),
];

fn print_section(title: &str) {
    println!("\n{}", "=".repeat(60));
    println!("  {}", title);
    println!("{}", "=".repeat(60));
}

fn print_result(label: &str, result: &zk_ai_core::TaskResult) {
    println!("\n--- {} ---", label);
    println!("Output: {}", result.output);
    println!("Model: {} | Adapter: {:?} | Duration: {}ms | Tokens: {}→{}",
        result.model, result.adapter, result.duration_ms,
        result.input_tokens, result.output_tokens);
}

fn print_text_hits(hits: &[TextSearchHit]) {
    for (i, hit) in hits.iter().enumerate() {
        println!("  {}. [{:.4}] {} — {}",
            i + 1, hit.score, hit.id,
            hit.text.chars().take(80).collect::<String>());
    }
}

fn print_image_hits(hits: &[ImageSearchHit]) {
    for (i, hit) in hits.iter().enumerate() {
        println!("  {}. [{:.4}] {} — {}",
            i + 1, hit.score, hit.id, hit.caption);
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter("zk_ai_core=info,kinsense=info")
        .init();

    println!("╔══════════════════════════════════════════════════════════╗");
    println!("║  KinSense — Semantic Perception with On-Device AI       ║");
    println!("║  Embeddings, search, clustering — all on-device.        ║");
    println!("╚══════════════════════════════════════════════════════════╝");

    let cache_dir = std::env::temp_dir().join("zk-ai-kinsense-models");
    println!("\nCache directory: {}", cache_dir.display());

    let mut engine = AiEngine::new(&cache_dir).await?;

    let profile = engine.profile();
    println!("Device tier: {:?} | Acceleration: {:?} | CPU cores: {} | Memory: {}MB",
        profile.tier, profile.acceleration, profile.cpu_cores, profile.available_memory_mb);

    println!("\nLoading mT5-small model...");
    engine.ensure_model(&ModelSpec::mt5_small_int8()).await?;

    // ── 1. Semantic Search Pipeline ──
    print_section("1. Semantic Search (AI Pipeline)");
    let result = engine.semantic_search(SAMPLE_QUERY, TaskOptions::default()).await?;
    print_result("Query: 'programming language for safe systems development'", &result);

    // ── 2. Build a TextIndex with synthetic embeddings ──
    print_section("2. Build Text Index");
    println!("Indexing {} documents...", SAMPLE_DOCS.len());

    let mut text_index = TextIndex::new();
    for (i, (id, text)) in SAMPLE_DOCS.iter().enumerate() {
        // Create synthetic embeddings: each doc gets a vector based on its position
        // In production, these would come from engine.run_embedding() with e5-small
        let mut emb = vec![0.0_f32; 10];
        // Simple hash-based embedding for demonstration
        let topic = i / 2; // 5 topics: langs, infra, ml, nlp, edge
        emb[topic * 2] = 0.9;
        emb[topic * 2 + 1] = 0.1;
        text_index.add_text(id, text, emb, Some("knowledge-base"));
    }
    println!("TextIndex built with {} entries.", text_index.len());

    // ── 3. Search the TextIndex ──
    print_section("3. Text Index Search");
    let query_embedding = vec![0.9, 0.1, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]; // "programming" topic
    let hits = text_index.search(&query_embedding, 3);
    println!("Query embedding: [0.9, 0.1, 0, ...] (programming topic)");
    println!("Top 3 results:");
    print_text_hits(&hits);

    // ── 4. Cosine Similarity Demo ──
    print_section("4. Cosine Similarity");
    let a = vec![1.0, 0.0, 0.0];
    let b = vec![1.0, 0.0, 0.0];
    let sim = cosine_similarity(&a, &b);
    println!("Identical vectors:   cosine_similarity = {:.4}", sim);

    let a = vec![1.0, 0.0, 0.0];
    let b = vec![0.0, 1.0, 0.0];
    let sim = cosine_similarity(&a, &b);
    println!("Orthogonal vectors:  cosine_similarity = {:.4}", sim);

    let a = vec![1.0, 0.0, 0.0];
    let b = vec![-1.0, 0.0, 0.0];
    let sim = cosine_similarity(&a, &b);
    println!("Opposite vectors:    cosine_similarity = {:.4}", sim);

    let a = vec![0.9, 0.1, 0.0];
    let b = vec![0.85, 0.05, 0.0];
    let sim = cosine_similarity(&a, &b);
    println!("Similar vectors:     cosine_similarity = {:.4}", sim);

    // ── 5. Build an ImageIndex ──
    print_section("5. Build Image Index");
    println!("Indexing {} images...", SAMPLE_IMAGES.len());

    let mut image_index = ImageIndex::new();
    for (id, caption, emb) in SAMPLE_IMAGES {
        image_index.add_image(id, caption, emb.to_vec());
    }
    println!("ImageIndex built with {} entries.", image_index.len());

    // ── 6. Image Search ──
    print_section("6. Image Search");
    let image_query = vec![1.0, 0.1, 0.0, 0.0, 0.0]; // "dog playing" query
    let hits = image_index.search(&image_query, 3);
    println!("Query embedding: [1.0, 0.1, 0, ...] (dog playing outdoors)");
    println!("Top 3 results:");
    print_image_hits(&hits);

    let image_query = vec![0.0, 0.0, 0.0, 0.0, 1.0]; // "city night" query
    let hits = image_index.search(&image_query, 2);
    println!("\nQuery embedding: [0, 0, 0, 0, 1.0] (city night skyline)");
    println!("Top 2 results:");
    print_image_hits(&hits);

    // ── 7. Image Search Pipeline ──
    print_section("7. Image Search (AI Pipeline)");
    let result = engine.image_search("a dog playing in the park", TaskOptions::default()).await?;
    print_result("Query: 'a dog playing in the park'", &result);

    // ── 8. Auto-Tag Documents ──
    print_section("8. Auto-Tag Documents");
    for (id, text) in SAMPLE_DOCS.iter().take(4) {
        let result = engine.auto_tag(text, TaskOptions::default()).await?;
        println!("  {} → {}", id, result.output);
    }

    // ── 9. Find Similar Documents ──
    print_section("9. Find Similar Documents");
    let query_text = "container orchestration for deploying applications at scale";
    let result = engine.find_similar(query_text, &text_index, 3, TaskOptions::default()).await?;
    print_result("Find similar to: 'container orchestration...'", &result);

    // ── 10. Cluster Documents ──
    print_section("10. Cluster Documents");
    let result = engine.cluster(&text_index, 3, TaskOptions::default()).await?;
    print_result("Cluster into 3 topic groups", &result);

    // ── 11. Rerank Search Results ──
    print_section("11. Rerank Search Results");
    let query_embedding = vec![0.9, 0.1, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0];
    let hits = text_index.search(&query_embedding, 5);
    println!("Original search results (top 5):");
    print_text_hits(&hits);

    let result = engine.rerank(SAMPLE_QUERY, &hits, TaskOptions::default()).await?;
    print_result("Reranked results", &result);

    // ── 12. Text Index Serialization ──
    print_section("12. Text Index Serialization");
    let json = text_index.to_json()?;
    println!("Serialized TextIndex to JSON ({} bytes)", json.len());
    let restored = TextIndex::from_json(&json)?;
    println!("Deserialized TextIndex with {} entries", restored.len());
    let hits = restored.search(&query_embedding, 2);
    println!("Search after roundtrip:");
    print_text_hits(&hits);

    // ── 13. Image Index Serialization ──
    print_section("13. Image Index Serialization");
    let json = image_index.to_json()?;
    println!("Serialized ImageIndex to JSON ({} bytes)", json.len());
    let restored = ImageIndex::from_json(&json)?;
    println!("Deserialized ImageIndex with {} entries", restored.len());
    let hits = restored.search(&vec![1.0, 0.1, 0.0, 0.0, 0.0], 2);
    println!("Search after roundtrip:");
    print_image_hits(&hits);

    println!("\n{}", "=".repeat(60));
    println!("  KinSense demo complete.");
    println!("  All semantic perception ran on-device.");
    println!("{}", "=".repeat(60));

    engine.shutdown().await?;
    Ok(())
}
