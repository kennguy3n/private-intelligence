//! Cold-start profiling benchmarks.
//!
//! Measures engine initialization, model loading (fallback path),
//! first inference latency, and warm vs cold inference comparison.

use criterion::{criterion_group, criterion_main, Criterion, BenchmarkId};
use zk_ai_core::pipeline::TaskOptions;
use zk_ai_core::model_manager::ModelSpec;
use zk_ai_core::governor::GovernorConfig;
use zk_ai_core::AiEngine;
use std::sync::Arc;
use tokio::sync::Mutex;

fn bench_engine_init(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    let mut group = c.benchmark_group("cold_start/engine_init");

    group.bench_function("new_engine", |b| {
        b.to_async(&rt).iter(|| async {
            let cache_dir = tempfile::tempdir().unwrap();
            let models_dir = cache_dir.path().join("models");
            std::fs::create_dir_all(&models_dir).unwrap();
            std::fs::write(models_dir.join("mt5-small-1.0.0-int8.onnx"), b"fake").unwrap();
            let adapters_dir = cache_dir.path().join("adapters");
            std::fs::create_dir_all(&adapters_dir).unwrap();
            std::fs::write(adapters_dir.join("summarize.en.bin"), b"fake").unwrap();

            let mut engine = AiEngine::new(cache_dir.path()).await.unwrap();
            engine.governor_mut().update_config(GovernorConfig {
                max_cpu_percent: 100,
                max_memory_percent: 100,
                ..Default::default()
            });
            engine
        });
    });

    group.finish();
}

fn bench_model_load(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    let mut group = c.benchmark_group("cold_start/model_load");

    let models = [
        ("mt5_small", ModelSpec::mt5_small_int8()),
        ("e5_small", ModelSpec::e5_small_int8()),
        ("clip", ModelSpec::clip_int8()),
    ];

    for (name, spec) in models {
        group.bench_with_input(BenchmarkId::new("ensure_model", name), &spec, |b, spec| {
            b.to_async(&rt).iter_with_setup(
                || {
                    let cache_dir = tempfile::tempdir().unwrap();
                    let models_dir = cache_dir.path().join("models");
                    std::fs::create_dir_all(&models_dir).unwrap();
                    std::fs::write(models_dir.join(spec.filename()), b"fake_model").unwrap();
                    let adapters_dir = cache_dir.path().join("adapters");
                    std::fs::create_dir_all(&adapters_dir).unwrap();
                    std::fs::write(adapters_dir.join("summarize.en.bin"), b"fake").unwrap();
                    cache_dir
                },
                |cache_dir| async move {
                    let mut engine = AiEngine::new(cache_dir.path()).await.unwrap();
                    engine.governor_mut().update_config(GovernorConfig {
                        max_cpu_percent: 100,
                        max_memory_percent: 100,
                        ..Default::default()
                    });
                    engine.ensure_model(spec).await.unwrap();
                    engine
                },
            );
        });
    }
    group.finish();
}

fn bench_cold_vs_warm_inference(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    let mut group = c.benchmark_group("cold_start/inference");

    // Cold: full engine setup + model load + first inference
    group.bench_function("cold_first_inference", |b| {
        b.to_async(&rt).iter(|| async {
            let cache_dir = tempfile::tempdir().unwrap();
            let models_dir = cache_dir.path().join("models");
            std::fs::create_dir_all(&models_dir).unwrap();
            std::fs::write(models_dir.join("mt5-small-1.0.0-int8.onnx"), b"fake").unwrap();
            let adapters_dir = cache_dir.path().join("adapters");
            std::fs::create_dir_all(&adapters_dir).unwrap();
            std::fs::write(adapters_dir.join("summarize.en.bin"), b"fake").unwrap();

            let mut engine = AiEngine::new(cache_dir.path()).await.unwrap();
            engine.governor_mut().update_config(GovernorConfig {
                max_cpu_percent: 100,
                max_memory_percent: 100,
                ..Default::default()
            });
            let spec = ModelSpec::mt5_small_int8();
            engine.ensure_model(&spec).await.unwrap();
            engine.summarize("Test input for cold start benchmark", "en", TaskOptions::default()).await
        });
    });

    // Warm: engine already initialized, model already loaded
    {
        let cache_dir = tempfile::tempdir().unwrap();
        let models_dir = cache_dir.path().join("models");
        std::fs::create_dir_all(&models_dir).unwrap();
        std::fs::write(models_dir.join("mt5-small-1.0.0-int8.onnx"), b"fake").unwrap();
        let adapters_dir = cache_dir.path().join("adapters");
        std::fs::create_dir_all(&adapters_dir).unwrap();
        std::fs::write(adapters_dir.join("summarize.en.bin"), b"fake").unwrap();

        let engine = Arc::new(Mutex::new(rt.block_on(async {
            let mut e = AiEngine::new(cache_dir.path()).await.unwrap();
            e.governor_mut().update_config(GovernorConfig {
                max_cpu_percent: 100,
                max_memory_percent: 100,
                ..Default::default()
            });
            let spec = ModelSpec::mt5_small_int8();
            e.ensure_model(&spec).await.unwrap();
            e
        })));

        group.bench_function("warm_inference", |b| {
            let engine = engine.clone();
            b.to_async(&rt).iter(|| {
                let engine = engine.clone();
                async move {
                    let mut e = engine.lock().await;
                    e.summarize("Test input for warm benchmark", "en", TaskOptions::default()).await
                }
            });
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_engine_init,
    bench_model_load,
    bench_cold_vs_warm_inference,
);
criterion_main!(benches);
