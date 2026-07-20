# zk-ai SDK — Benchmarks & Evaluation

## Performance Benchmarks (Criterion)

Six benchmark harnesses covering all performance gaps:

### 1. Pipeline Latency (`bench_pipeline_latency.rs`)
Measures end-to-end pipeline overhead for summarize, translate, key_points, generate_doc, generate_slides across all supported languages.

```bash
cargo bench --bench bench_pipeline_latency
```

### 2. Search Throughput (`bench_search_throughput.rs`)
Measures semantic search (TextIndex) and image search (ImageIndex) latency at corpus sizes of 100, 1K, 10K documents, plus index build throughput.

```bash
cargo bench --bench bench_search_throughput
```

### 3. Streaming Latency (`bench_streaming.rs`)
Measures streaming vs non-streaming inference latency, token-by-token output timing.

```bash
cargo bench --bench bench_streaming
```

### 4. Swarm Coordination (`bench_swarm.rs`)
Measures device election and capability update latency at 3, 10, 20, 50 device swarm sizes.

```bash
cargo bench --bench bench_swarm
```

### 5. Cold-Start Profiling (`bench_cold_start.rs`)
Measures engine initialization, model loading, first inference (cold), and warm inference latency.

```bash
cargo bench --bench bench_cold_start
```

### 6. Governor Overhead (`bench_governor.rs`)
Measures resource governor check_resources, acquire/release semaphore, and thermal state check overhead across all device tiers.

```bash
cargo bench --bench bench_governor
```

### Run All Benchmarks

```bash
cargo bench --package zk-ai-benchmarks
```

Results are saved to `target/criterion/` with HTML reports.

---

## Accuracy Evaluation

### Deterministic Eval Harness (`accuracy_eval.rs`)

Runs all pipeline tasks across **22 languages** with deterministic scorers:

- **Term coverage** — fraction of expected key terms in output
- **Faithfulness** — entities grounded in input (no hallucination)
- **In-language correctness** — output in expected script
- **BLEU-2** — n-gram precision + brevity penalty for translations
- **Recall@k** — relevant results in top-k for search
- **MRR** — mean reciprocal rank for search

```bash
cargo test --package zk-ai-core --test accuracy_eval -- --nocapture
```

Generates a markdown leaderboard with per-language, per-task, and overall summary.

### Real Model Integration Tests (`real_model_integration.rs`)

Gated behind `real-models` feature. Downloads real ONNX models from CDN and runs actual inference:

```bash
cargo test --package zk-ai-core --test real_model_integration --features real-models -- --nocapture --ignored
```

Tests:
- Real mT5-small summarize across all languages
- Real translation (en→vi, en→fr, etc.)
- Real key_points extraction
- Real e5-small embedding generation
- Cold-start latency measurement
- Warm inference latency (10-run avg, p50, min, max)
- Streaming token output

---

## Language Coverage

22 languages across 7 language families:

| Family | Languages |
|--------|-----------|
| Germanic | English (en), German (de) |
| Romance | Spanish (es), French (fr), Portuguese (pt) |
| East Asian | Chinese (zh), Japanese (ja), Korean (ko) |
| Southeast Asian | Vietnamese (vi), Thai (th), Indonesian (id), Malay (ms), Tagalog (tl), Khmer (km) |
| South Asian | Hindi (hi), Bengali (bn), Nepali (ne), Urdu (ur) |
| Middle East / Central Asia | Arabic (ar), Persian (fa), Turkish (tr) |
| Slavic | Russian (ru) |

mT5-small was pre-trained on 101 languages — expanding to more requires only LoRA adapter training.
