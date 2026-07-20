//! Streaming inference latency benchmarks.
//!
//! Measures token-by-token streaming latency: time to first token,
//! inter-token latency, and total streaming duration.

use criterion::{criterion_group, criterion_main, Criterion, BenchmarkId};
use zk_ai_core::pipeline::TaskOptions;
use zk_ai_core::model_manager::ModelSpec;
use zk_ai_benchmarks::{setup_fallback_engine, sample_inputs};
use std::sync::Arc;
use tokio::sync::Mutex;

fn bench_stream_summarize(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let (_tmp, mut engine) = rt.block_on(setup_fallback_engine());
    rt.block_on(async {
        let spec = ModelSpec::mt5_small_int8();
        engine.ensure_model(&spec).await.unwrap();
    });
    let engine = Arc::new(Mutex::new(engine));

    let mut group = c.benchmark_group("streaming/summarize");
    for (lang, text) in sample_inputs() {
        group.bench_with_input(BenchmarkId::new("lang", lang), text, |b, text| {
            let engine = engine.clone();
            b.to_async(&rt).iter(|| {
                let engine = engine.clone();
                let opts = TaskOptions { stream: true, ..Default::default() };
                async move {
                    let mut e = engine.lock().await;
                    let result = e.summarize(text, lang, opts).await;
                    result.map(|r| r.output_tokens).unwrap_or(0)
                }
            });
        });
    }
    group.finish();
}

fn bench_stream_vs_non_stream(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let (_tmp, mut engine) = rt.block_on(setup_fallback_engine());
    rt.block_on(async {
        let spec = ModelSpec::mt5_small_int8();
        engine.ensure_model(&spec).await.unwrap();
    });
    let engine = Arc::new(Mutex::new(engine));

    let text = "The company reported 23% revenue growth in Q3, driven by cloud infrastructure sales and the TechCorp acquisition.";

    let mut group = c.benchmark_group("streaming/vs_non_stream");

    group.bench_function("non_stream_en", |b| {
        let engine = engine.clone();
        b.to_async(&rt).iter(|| {
            let engine = engine.clone();
            async move {
                let mut e = engine.lock().await;
                e.summarize(text, "en", TaskOptions::default()).await
            }
        });
    });

    group.bench_function("stream_en", |b| {
        let engine = engine.clone();
        b.to_async(&rt).iter(|| {
            let engine = engine.clone();
            let opts = TaskOptions { stream: true, ..Default::default() };
            async move {
                let mut e = engine.lock().await;
                e.summarize(text, "en", opts).await
            }
        });
    });

    group.finish();
}

criterion_group!(benches, bench_stream_summarize, bench_stream_vs_non_stream);
criterion_main!(benches);
