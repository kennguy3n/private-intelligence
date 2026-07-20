//! Pipeline latency benchmarks: summarize, translate, key_points, generate_doc, generate_slides.
//!
//! Measures end-to-end pipeline overhead (prompt construction, adapter setup,
//! governor check, inference dispatch, result packaging) across all supported
//! languages. With fallback models this is the infrastructure floor; with real
//! ONNX models it includes actual mT5-small inference time.

use criterion::{criterion_group, criterion_main, Criterion, BenchmarkId};
use zk_ai_core::pipeline::TaskOptions;
use zk_ai_core::model_manager::ModelSpec;
use zk_ai_benchmarks::{setup_fallback_engine, sample_inputs};
use std::sync::Arc;
use tokio::sync::Mutex;

fn bench_summarize(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let (_tmp, mut engine) = rt.block_on(setup_fallback_engine());
    rt.block_on(async {
        let spec = ModelSpec::mt5_small_int8();
        engine.ensure_model(&spec).await.unwrap();
    });
    let engine = Arc::new(Mutex::new(engine));

    let mut group = c.benchmark_group("pipeline/summarize");
    for (lang, text) in sample_inputs() {
        group.bench_with_input(BenchmarkId::new("lang", lang), text, |b, text| {
            let engine = engine.clone();
            b.to_async(&rt).iter(|| {
                let engine = engine.clone();
                async move {
                    let mut e = engine.lock().await;
                    e.summarize(text, lang, TaskOptions::default()).await
                }
            });
        });
    }
    group.finish();
}

fn bench_translate(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let (_tmp, mut engine) = rt.block_on(setup_fallback_engine());
    rt.block_on(async {
        let spec = ModelSpec::mt5_small_int8();
        engine.ensure_model(&spec).await.unwrap();
    });
    let engine = Arc::new(Mutex::new(engine));

    let pairs = [("en", "vi"), ("en", "zh"), ("en", "ar"), ("vi", "en"), ("zh", "en")];
    let text = "The company reported 23% revenue growth in Q3.";

    let mut group = c.benchmark_group("pipeline/translate");
    for (src, tgt) in pairs {
        group.bench_with_input(BenchmarkId::new("pair", format!("{}→{}", src, tgt)), &(src, tgt), |b, &(src, tgt)| {
            let engine = engine.clone();
            b.to_async(&rt).iter(|| {
                let engine = engine.clone();
                async move {
                    e_translate(&engine, text, src, tgt).await
                }
            });
        });
    }
    group.finish();
}

async fn e_translate(engine: &Arc<Mutex<zk_ai_core::AiEngine>>, text: &str, src: &str, tgt: &str) -> zk_ai_core::Result<zk_ai_core::pipeline::TaskResult> {
    let mut e = engine.lock().await;
    e.translate(text, src, tgt, TaskOptions::default()).await
}

fn bench_key_points(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let (_tmp, mut engine) = rt.block_on(setup_fallback_engine());
    rt.block_on(async {
        let spec = ModelSpec::mt5_small_int8();
        engine.ensure_model(&spec).await.unwrap();
    });
    let engine = Arc::new(Mutex::new(engine));

    let text = "The team decided to migrate from PostgreSQL to MongoDB. Reasons: schema flexibility, horizontal scaling, lower cost. Phases: prototype Q1, pilot Q2, full rollout Q3. Risk: data consistency.";

    let mut group = c.benchmark_group("pipeline/key_points");
    for (lang, _) in sample_inputs() {
        group.bench_with_input(BenchmarkId::new("lang", lang), lang, |b, lang| {
            let engine = engine.clone();
            b.to_async(&rt).iter(|| {
                let engine = engine.clone();
                async move {
                    let mut e = engine.lock().await;
                    e.key_points(text, lang, TaskOptions::default()).await
                }
            });
        });
    }
    group.finish();
}

fn bench_generate_doc(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let (_tmp, mut engine) = rt.block_on(setup_fallback_engine());
    rt.block_on(async {
        let spec = ModelSpec::mt5_small_int8();
        engine.ensure_model(&spec).await.unwrap();
    });
    let engine = Arc::new(Mutex::new(engine));

    let topic = "Cloud Security Best Practices";
    let outline = "1. IAM with MFA. 2. Encryption at rest and in transit. 3. Network segmentation. 4. SIEM monitoring.";

    let mut group = c.benchmark_group("pipeline/generate_doc");
    for (lang, _) in sample_inputs() {
        group.bench_with_input(BenchmarkId::new("lang", lang), lang, |b, lang| {
            let engine = engine.clone();
            b.to_async(&rt).iter(|| {
                let engine = engine.clone();
                async move {
                    let mut e = engine.lock().await;
                    e.generate_doc(topic, outline, lang, TaskOptions::default()).await
                }
            });
        });
    }
    group.finish();
}

fn bench_generate_slides(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let (_tmp, mut engine) = rt.block_on(setup_fallback_engine());
    rt.block_on(async {
        let spec = ModelSpec::mt5_small_int8();
        engine.ensure_model(&spec).await.unwrap();
    });
    let engine = Arc::new(Mutex::new(engine));

    let topic = "Introduction to Machine Learning";
    let source = "Machine learning is a subset of AI. Types: supervised, unsupervised, reinforcement. Algorithms: regression, decision trees, neural networks.";

    let mut group = c.benchmark_group("pipeline/generate_slides");
    for (lang, _) in sample_inputs() {
        group.bench_with_input(BenchmarkId::new("lang", lang), lang, |b, lang| {
            let engine = engine.clone();
            b.to_async(&rt).iter(|| {
                let engine = engine.clone();
                async move {
                    let mut e = engine.lock().await;
                    e.generate_slides(topic, source, lang, TaskOptions::default()).await
                }
            });
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_summarize,
    bench_translate,
    bench_key_points,
    bench_generate_doc,
    bench_generate_slides,
);
criterion_main!(benches);
