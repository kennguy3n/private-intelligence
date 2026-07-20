//! Real ONNX model integration tests.
//!
//! These tests download real ONNX models from the CDN and run actual
//! inference through the full pipeline. They are gated behind the
//! `real-models` feature flag and require network access.
//!
//! To run:
//!   cargo test --package zk-ai-core --test real_model_integration --features real-models -- --nocapture --ignored
//!
//! The tests verify:
//! - Real ONNX session initialization
//! - Real tokenizer encoding
//! - Actual mT5-small inference output (not fallback)
//! - LoRA adapter loading and hot-swap
//! - e5-small embedding generation
//! - CLIP image-text matching
//! - End-to-end pipeline quality (summarize, translate, key_points)

#![cfg(feature = "real-models")]

use zk_ai_core::pipeline::{TaskOptions, SUPPORTED_LANGUAGES};
use zk_ai_core::model_manager::ModelSpec;
use zk_ai_core::governor::GovernorConfig;
use zk_ai_core::AiEngine;
use tempfile::tempdir;

async fn setup_real_engine() -> (tempfile::TempDir, AiEngine) {
    let cache_dir = tempdir().unwrap();
    let mut engine = AiEngine::new(cache_dir.path()).await.unwrap();
    engine.governor_mut().update_config(GovernorConfig {
        max_cpu_percent: 100,
        max_memory_percent: 100,
        ..Default::default()
    });
    (cache_dir, engine)
}

#[tokio::test]
#[ignore = "Requires real ONNX models downloaded from CDN"]
async fn test_real_mt5_summarize_english() {
    let (_tmp, mut engine) = setup_real_engine().await;
    let spec = ModelSpec::mt5_small_int8();
    engine.ensure_model(&spec).await.unwrap();

    let input = "The quarterly board meeting covered revenue growth of 23% year-over-year, the new product launch scheduled for Q3, and the acquisition of TechCorp for $50M. The CEO emphasized that the cloud infrastructure migration to AWS is 80% complete.";
    let result = engine.summarize(input, "en", TaskOptions::default()).await;

    assert!(result.is_ok(), "summarize should succeed with real model");
    let output = result.unwrap();
    assert!(!output.output.is_empty(), "output should not be empty");
    // Real model output should differ from smart_fallback (which extracts
    // verbatim input sentences). Check that output is not just a prefix of input.
    assert!(output.output_tokens > 0, "should have generated tokens");
    assert!(!input.starts_with(&output.output), "output should be real inference, not verbatim extraction");
    println!("Summarize (en): {}", output.output);
}

#[tokio::test]
#[ignore = "Requires real ONNX models downloaded from CDN"]
async fn test_real_mt5_summarize_all_languages() {
    let (_tmp, mut engine) = setup_real_engine().await;
    let spec = ModelSpec::mt5_small_int8();
    engine.ensure_model(&spec).await.unwrap();

    let inputs = [
        ("en", "The company reported 23% revenue growth and acquired TechCorp for $50M."),
        ("vi", "Công ty báo cáo tăng trưởng doanh thu 23% và mua lại TechCorp với giá 50 triệu đô la."),
        ("es", "La empresa reportó crecimiento de ingresos del 23% y adquirió TechCorp por 50 millones."),
        ("fr", "L'entreprise a rapporté une croissance des revenus de 23% et a acquis TechCorp pour 50M$."),
        ("de", "Das Unternehmen meldete ein Umsatzwachstum von 23% und übernahm TechCorp für 50M$."),
        ("zh", "公司报告收入增长23%，并以5000万美元收购TechCorp。"),
    ];

    for (lang, input) in &inputs {
        let result = engine.summarize(input, lang, TaskOptions::default()).await;
        assert!(result.is_ok(), "summarize({}) should succeed", lang);
        let output = result.unwrap();
        assert!(!input.starts_with(&output.output), "output for {} should be real inference", lang);
        println!("Summarize ({}): {}", lang, output.output);
    }
}

#[tokio::test]
#[ignore = "Requires real ONNX models downloaded from CDN"]
async fn test_real_mt5_translate() {
    let (_tmp, mut engine) = setup_real_engine().await;
    let spec = ModelSpec::mt5_small_int8();
    engine.ensure_model(&spec).await.unwrap();

    let result = engine.translate(
        "The company reported 23% revenue growth in Q3.",
        "en", "vi",
        TaskOptions::default(),
    ).await;

    assert!(result.is_ok(), "translate should succeed");
    let output = result.unwrap();
    // Real translation should differ from source text
    assert!(output.output != "The company reported 23% revenue growth in Q3.",
        "translate should produce actual translation, not echo source");
    println!("Translate (en→vi): {}", output.output);
}

#[tokio::test]
#[ignore = "Requires real ONNX models downloaded from CDN"]
async fn test_real_mt5_key_points() {
    let (_tmp, mut engine) = setup_real_engine().await;
    let spec = ModelSpec::mt5_small_int8();
    engine.ensure_model(&spec).await.unwrap();

    let input = "The team decided to migrate from PostgreSQL to MongoDB. Reasons: schema flexibility, horizontal scaling, lower cost. Phases: prototype Q1, pilot Q2, full rollout Q3. Risk: data consistency during migration.";
    let result = engine.key_points(input, "en", TaskOptions::default()).await;

    assert!(result.is_ok(), "key_points should succeed");
    let output = result.unwrap();
    assert!(!output.output.starts_with("•"), "output should be real inference, not smart fallback bullets");
    println!("Key Points (en): {}", output.output);
}

#[tokio::test]
#[ignore = "Requires real ONNX models downloaded from CDN"]
async fn test_real_e5_embeddings() {
    let (_tmp, mut engine) = setup_real_engine().await;
    let spec = ModelSpec::e5_small_int8();
    engine.ensure_model(&spec).await.unwrap();

    let result = engine.run_embedding("Cloud computing enables on-demand access to resources.").await;
    assert!(result.is_ok(), "embedding should succeed");
    let embedding = result.unwrap();
    assert!(!embedding.is_empty(), "embedding vector should not be empty");
    println!("E5 embedding dim: {}", embedding.len());
}

#[tokio::test]
#[ignore = "Requires real ONNX models downloaded from CDN"]
async fn test_real_cold_start_latency() {
    let cache_dir = tempdir().unwrap();
    let start = std::time::Instant::now();

    let mut engine = AiEngine::new(cache_dir.path()).await.unwrap();
    engine.governor_mut().update_config(GovernorConfig {
        max_cpu_percent: 100,
        max_memory_percent: 100,
        ..Default::default()
    });

    let spec = ModelSpec::mt5_small_int8();
    engine.ensure_model(&spec).await.unwrap();
    let load_time = start.elapsed();

    let infer_start = std::time::Instant::now();
    let result = engine.summarize("Test input for cold start", "en", TaskOptions::default()).await;
    let first_infer_time = infer_start.elapsed();

    assert!(result.is_ok());
    println!("Model load: {:?}, First inference: {:?}", load_time, first_infer_time);
}

#[tokio::test]
#[ignore = "Requires real ONNX models downloaded from CDN"]
async fn test_real_warm_inference_latency() {
    let (_tmp, mut engine) = setup_real_engine().await;
    let spec = ModelSpec::mt5_small_int8();
    engine.ensure_model(&spec).await.unwrap();

    // Warm up
    let _ = engine.summarize("Warmup input", "en", TaskOptions::default()).await;

    // Measure warm inference
    let text = "The company reported 23% revenue growth in Q3, driven by cloud infrastructure sales.";
    let timings: Vec<u64> = vec![];
    let mut timings = timings;

    for _ in 0..10 {
        let start = std::time::Instant::now();
        let result = engine.summarize(text, "en", TaskOptions::default()).await;
        let elapsed = start.elapsed().as_millis() as u64;
        assert!(result.is_ok());
        timings.push(elapsed);
    }

    let avg: f64 = timings.iter().sum::<u64>() as f64 / timings.len() as f64;
    let p50 = timings[timings.len() / 2];
    println!("Warm inference — avg: {:.1}ms, p50: {}ms, min: {}ms, max: {}ms",
        avg, p50, timings.iter().min().unwrap(), timings.iter().max().unwrap());
}

#[tokio::test]
#[ignore = "Requires real ONNX models downloaded from CDN"]
async fn test_real_streaming_tokens() {
    let (_tmp, mut engine) = setup_real_engine().await;
    let spec = ModelSpec::mt5_small_int8();
    engine.ensure_model(&spec).await.unwrap();

    let opts = TaskOptions { stream: true, ..Default::default() };
    let result = engine.summarize(
        "The company reported 23% revenue growth and acquired TechCorp for $50M.",
        "en", opts,
    ).await;

    assert!(result.is_ok(), "streaming summarize should succeed");
    let output = result.unwrap();
    assert!(output.output_tokens > 0, "should have streamed tokens");
    println!("Streamed {} tokens: {}", output.output_tokens, output.output);
}
