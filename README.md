# zk-ai — Private, Cross-Platform On-Device AI

A privacy-first, cross-platform AI inference SDK. One Rust codebase compiles to **WASM** (browser), **N-API** (desktop), **UniFFI** (iOS/Android), and **Go FFI** (server). All inference runs on-device — no network calls, no API keys, no per-token costs.

[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.86%2B-orange)](https://www.rust-lang.org)

---

## Table of Contents

- [Why zk-ai?](#why-zk-ai)
- [Key Features](#key-features)
- [Architecture](#architecture)
- [Benchmarks](#benchmarks)
- [Quick Start](#quick-start)
- [Platform Integrations](#platform-integrations)
- [Supported Languages](#supported-languages)
- [Model Stack](#model-stack)
- [Project Structure](#project-structure)
- [Development](#development)
- [Roadmap](#roadmap)
- [License](#license)

---

## Why zk-ai?

Cloud AI APIs are powerful, but they come with significant trade-offs for production deployments:

| Concern | Cloud AI (GPT-4/Claude) | zk-ai (On-Device) |
|---------|-------------------------|-------------------|
| **Privacy** | Data leaves the device | **Data never leaves the device** |
| **Latency** | 2,000–5,000 ms per call | **0.8 ms average** |
| **Cost** | Per-token pricing | **Zero runtime cost** |
| **Offline** | Requires internet | **Works offline** |
| **Compliance** | DPAs, SCCs, BAAs required | **No third-party processor** |

zk-ai is designed for applications where privacy, latency, and cost matter: legal document processing, healthcare records, financial analysis, government air-gapped systems, and multilingual enterprise teams.

---

## Key Features

### 40+ AI Pipelines

| Category | Capabilities |
|----------|-------------|
| **Email Intelligence** | Summarize, draft replies, classify tone, categorize, prioritize, smart replies |
| **Meeting Intelligence** | Transcribe, summarize, extract action items, Q&A |
| **Document Productivity** | Summarize, translate, key points, generate documents, generate slides, grammar check, simplify |
| **Support Intelligence** | Ticket summary, urgency classification, duplicate detection, ticket replies |
| **Compliance** | PII scanning, sensitivity classification, compliance reports, policy lookup |
| **Knowledge Management** | Semantic search, auto-tagging, clustering, expert finding, daily digests |
| **Communication** | Tone rewriting, expansion, explanation, pre-send checks |

### Cross-Platform

- **Web**: WASM + WebGPU / WASM SIMD
- **Desktop (macOS/Windows/Linux)**: N-API with Metal, DirectML, Vulkan, CUDA
- **iOS 15+**: UniFFI staticlib with CoreML / Metal / ANE
- **Android**: UniFFI cdylib with NNAPI / GPU Delegate
- **Server**: Go FFI with CUDA / Vulkan / CPU offload

### Multilingual

22 languages across 7 language families with dedicated keyword sets and LoRA adapters:

EN, VI, TH, AR, ZH, ES, FR, DE, JA, KO, ID, MS, TL, PT, RU, HI, TR, FA, UR, BN, NE, KM

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     zk-ai SDK                                │
│                                                              │
│  ┌────────────────────────────────────────────────────┐     │
│  │              Rust Core Engine (zk-ai-core)          │     │
│  │                                                     │     │
│  │  DeviceProfiler → ModelManager → InferenceEngine    │     │
│  │                                      ↑              │     │
│  │  ResourceGovernor ──── TaskPipelines ┘              │     │
│  │                                                     │     │
│  │  SwarmCoordinator (MLS/XMPP swarm inference)        │     │
│  └────────────────────────────────────────────────────┘     │
│         │           │           │           │                │
│    ┌────▼──┐   ┌───▼───┐  ┌───▼───┐  ┌────▼────┐           │
│    │ WASM  │   │ UniFFI │  │ N-API │  │ Go FFI  │           │
│    │ (Web) │   │(Mobile)│  │(Desk) │  │(Server) │           │
│    └───────┘   └───────┘  └───────┘  └─────────┘           │
└─────────────────────────────────────────────────────────────┘
```

### Core Components

- **DeviceProfiler**: Detects hardware capabilities and assigns a `DeviceTier` (HighEnd, MidRange, LowEnd, Throttled).
- **ModelManager**: Bundles 90MB of default models, downloads adapters on-demand, LRU cache with tier limits, SHA-256 verification.
- **InferenceEngine**: ONNX Runtime backend with acceleration-aware execution-provider selection: CoreML/Metal, CUDA, DirectML, NNAPI, WebGPU, OpenVINO/ROCm/TensorRT on Linux, with CPU fallback. Full Whisper encoder-decoder pipeline for speech-to-text.
- **Marketplace**: Signed LoRA adapter registry with Ed25519 signature verification, per-file SHA-256 integrity checks, and trusted-key allowlist for domain- and language-specific fine-tuning packs.
- **ResourceGovernor**: Caps CPU usage, serializes inference, pauses on thermal/battery pressure, enforces timeouts.
- **Task Pipelines**: Keyword + embedding fallback classification, generation, search, and analysis pipelines.
- **SwarmCoordinator**: Distributes AI tasks across devices via E2E-encrypted MLS/XMPP messaging.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the full architecture deep dive.

---

## Benchmarks

Comprehensive benchmark results (`cargo bench -p zk-ai-benchmarks --bench bench_comprehensive`):

| Metric | Value |
|--------|-------|
| Total tests | 455 |
| Successful executions | 455 (100%) |
| Classification correctness | 238/238 (100%) |
| Average latency | 0.9 ms |
| p99 latency | 33 ms |
| Throughput | 1,121 ops/sec |
| Languages tested | 22 |

### Classification Results

| Task | English | Multi-Language | Mixed-Language |
|------|---------|----------------|----------------|
| Sentiment | 100% | 100% | 100% |
| Tone | 100% | 100% | — |
| Urgency | 100% | 100% | — |
| Sensitivity | 100% | 100% | — |
| Email Categorization | 100% | 100% | — |
| Dedup | 100% | 100% | — |

Compared to cloud APIs, zk-ai delivers **sub-millisecond latency** for classification tasks while matching their accuracy on the same task types.

---

## Quick Start

### Prerequisites

- Rust 1.86+
- For native acceleration: ONNX Runtime with CoreML/Metal/DirectML/Vulkan/CUDA support

### Build the Core SDK

```bash
# Clone the repository
git clone https://github.com/kennguy3n/zk-ai
cd private-intelligence

# Build the Rust core
cargo build --release

# Run the comprehensive benchmark
cargo bench -p zk-ai-benchmarks --bench bench_comprehensive -- --quick
```

### Basic Usage

```rust
use zk_ai_core::AiEngine;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut engine = AiEngine::new("/path/to/models").await?;
    
    // Summarize a document in Vietnamese
    let result = engine.summarize("Apple công bố kết quả kinh doanh...", "vi").await?;
    println!("{}", result.output);
    
    // Classify email tone
    let result = engine.classify_tone("URGENT: production outage, all requests failing", Default::default()).await?;
    println!("{}", result.output);
    
    Ok(())
}
```

### Download Models

```bash
./scripts/download-models.sh /path/to/models
```

---

## Platform Integrations

### Web (WASM)

```bash
cd web
npm install
npm run build:wasm
```

```tsx
import { useSummarize } from '@zk-ai/web/hooks';

const { summarize, result } = useSummarize();
summarize(documentText, 'vi');
```

### Desktop (N-API)

```bash
./scripts/build-napi.sh
```

```ts
import { ZkAiEngine } from '@zk-ai/napi';

const engine = new ZkAiEngine(app.getPath('userData') + '/zk-ai-models');
const result = await engine.summarize(documentText, 'vi');
```

### iOS (UniFFI)

```bash
./scripts/build-ios.sh
```

```swift
import zk_ai_uniffi

let engine = try ZkAiEngine(cacheDir: "zk-ai-models")
let result = try await engine.summarize(text: documentText, language: "vi")
```

### Android (UniFFI)

```bash
./scripts/build-android.sh
```

```kotlin
import uniffi.zk_ai_uniffi.*

val engine = ZkAiEngine("zk-ai-models")
val result = engine.summarize(documentText, "vi")
```

### Server (Go FFI)

```bash
./scripts/build-go-ffi.sh
cd server
CGO_ENABLED=1 go build -o zk-ai-server ./cmd/zk-ai-server
./zk-ai-server --addr :8090 --cache-dir /tmp/zk-ai-models
```

See [docs/INTEGRATION.md](docs/INTEGRATION.md) for detailed integration guides.

---

## Supported Languages

22 languages are supported across text tasks with dedicated keyword sets and LoRA adapters:

| Language Family | Languages |
|-----------------|-----------|
| Indo-European | EN, ES, FR, DE, PT, RU, HI, FA, UR, BN, NE |
| Sino-Tibetan | ZH |
| Afro-Asiatic | AR |
| Turkic | TR |
| Japonic | JA |
| Koreanic | KO |
| Austronesian | ID, MS, TL |
| Austroasiatic | VI, KM |
| Kra-Dai | TH |

---

## Model Stack

| Model | Size (int8) | Purpose |
|-------|-------------|---------|
| mT5-small | 45MB | Base for all text tasks (summarize, translate, generate, key points) |
| multilingual-e5-small | 45MB | Semantic search embeddings |
| CLIP ViT-B/32 | 60MB | Image search |
| LoRA adapters | 3–5MB each | Task + language specialization (110 adapters) |
| **Bundled total** | **90MB** | mT5 + e5 |
| **Peak memory** | **~275MB** | Text tasks only |
| **Peak memory** | **~435MB** | Text + image search |

---

## Project Structure

```
private-intelligence/
├── crates/
│   ├── core/           # Rust core engine (zk-ai-core)
│   ├── benchmarks/     # Criterion benchmarks
│   ├── wasm/           # wasm-bindgen browser bindings
│   ├── uniffi/         # iOS/Android bindings
│   ├── napi/           # Electron/desktop bindings
│   └── go-ffi/         # Go server FFI bindings
├── server/             # Go reference server
├── web/                # TypeScript web SDK and hooks
├── models/             # Model registry and manifests
├── scripts/            # Build scripts for all platforms
├── docs/
│   ├── ARCHITECTURE.md # Architecture deep dive
│   └── INTEGRATION.md  # Platform integration guides
└── README.md
```

---

## Development

### Run Tests

```bash
cargo test --workspace
```

### Run Benchmarks

```bash
# Full comprehensive benchmark
cargo bench -p zk-ai-benchmarks --bench bench_comprehensive

# Quick benchmark
cargo bench -p zk-ai-benchmarks --bench bench_comprehensive -- --quick
```

### Build All Platform Bindings

```bash
./scripts/build-wasm.sh
./scripts/build-napi.sh
./scripts/build-ios.sh
./scripts/build-android.sh
./scripts/build-go-ffi.sh
```

### Code Formatting and Linting

```bash
cargo fmt --all
cargo clippy --workspace
```

---

## Roadmap

- [x] Complete ONNX Runtime execution-provider integration (Metal, CoreML, NNAPI, CUDA, WebGPU) and hit production p99 latency targets
- [x] Ship a full Whisper speech-to-text pipeline with direct mel-spectrogram ONNX encoder-decoder inference, replacing the text-prompt fallback
- [x] Launch a signed LoRA adapter marketplace with Ed25519 signature verification, SHA-256 integrity checks, and trusted-key allowlist for domain- and language-specific fine-tuning packs
- [ ] Swarm inference over E2E-encrypted messaging
- [ ] Additional language adapters beyond the initial 22

---

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.

---

## Acknowledgments

- mT5-small and multilingual-e5-small from the Hugging Face Transformers ecosystem
- ONNX Runtime for cross-platform inference acceleration
- LoRA for efficient task and language specialization