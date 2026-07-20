//! Search throughput and latency benchmarks: semantic search (TextIndex)
//! and image search (ImageIndex) at various corpus sizes.

use criterion::{criterion_group, criterion_main, Criterion, BenchmarkId, Throughput};
use zk_ai_core::pipeline::text_index::TextIndex;
use zk_ai_core::pipeline::image_index::ImageIndex;
use zk_ai_benchmarks::synthetic_embedding;

fn bench_semantic_search(c: &mut Criterion) {
    let corpus_sizes = [100, 1_000, 10_000];

    let mut group = c.benchmark_group("search/semantic");
    group.throughput(Throughput::Elements(1));

    for &size in &corpus_sizes {
        let mut index = TextIndex::new();
        let dim = 128;
        for i in 0..size {
            let text = format!("Document {} about topic {} with keywords", i, i % 20);
            let emb = synthetic_embedding(&text, dim);
            index.add_text(&format!("doc_{}", i), &text, emb, None);
        }
        let query = synthetic_embedding("cloud infrastructure computing resources", dim);

        group.bench_with_input(BenchmarkId::new("corpus", size), &size, |b, _| {
            b.iter(|| {
                let hits = index.search(&query, 10);
                assert!(!hits.is_empty());
                hits.len()
            });
        });
    }
    group.finish();
}

fn bench_image_search(c: &mut Criterion) {
    let corpus_sizes = [100, 1_000, 5_000];

    let mut group = c.benchmark_group("search/image");
    group.throughput(Throughput::Elements(1));

    for &size in &corpus_sizes {
        let mut index = ImageIndex::new();
        let dim = 64;
        for i in 0..size {
            let caption = format!("Image {} showing object category {}", i, i % 10);
            let emb = synthetic_embedding(&caption, dim);
            index.add_image(&format!("img_{}", i), &caption, emb);
        }
        let query = synthetic_embedding("dog playing in park", dim);

        group.bench_with_input(BenchmarkId::new("corpus", size), &size, |b, _| {
            b.iter(|| {
                let hits = index.search(&query, 10);
                assert!(!hits.is_empty());
                hits.len()
            });
        });
    }
    group.finish();
}

fn bench_text_index_build(c: &mut Criterion) {
    let sizes = [100, 1_000, 10_000];
    let dim = 128;

    let mut group = c.benchmark_group("search/index_build");
    for &size in &sizes {
        group.throughput(Throughput::Elements(size as u64));
        group.bench_with_input(BenchmarkId::new("add_text", size), &size, |b, &size| {
            b.iter(|| {
                let mut index = TextIndex::new();
                for i in 0..size {
                    let text = format!("Document {} about topic {}", i, i % 20);
                    let emb = synthetic_embedding(&text, dim);
                    index.add_text(&format!("doc_{}", i), &text, emb, None);
                }
                index.len()
            });
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_semantic_search,
    bench_image_search,
    bench_text_index_build,
);
criterion_main!(benches);
