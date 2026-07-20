# zk-ai Architecture

Privacy-first cross-platform on-device AI inference SDK. One Rust codebase compiled to WASM (browser), N-API (Electron desktop), UniFFI (iOS/Android), and cgo (Go server).

## Overview

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

## Core Components

### DeviceProfiler
Detects hardware capabilities at startup and assigns a `DeviceTier`:
- **HighEnd**: dedicated GPU / Apple Silicon / 8GB+ RAM / NPU ≥10 TOPS
- **MidRange**: integrated GPU / 4-8GB RAM / NPU 5-10 TOPS
- **LowEnd**: CPU-only / <4GB RAM
- **Throttled**: battery <20% or thermal pressure

### ModelManager
- Bundles 90MB of default models (mT5-small + e5-small)
- Downloads larger models/adapters from CDN on-demand
- LRU cache eviction with tier-based limits (high: 2GB, mid: 512MB, low: 150MB)
- SHA-256 integrity verification on download

### InferenceEngine
- ONNX Runtime backend (CoreML, DirectML, NNAPI, CUDA, Vulkan, WebGPU, CPU)
- LoRA adapter hot-swap (<10ms) — one 45MB base + 3-5MB per-task adapters
- Tier-dependent decoding: beam search (high), nucleus sampling (mid), greedy (low)

### ResourceGovernor
- Max 60% CPU for inference (30% on low-end)
- Max 1 concurrent inference (prevents GPU contention)
- Pauses on battery <20% or thermal throttle
- Hard timeout per inference call (10-30s depending on tier)

### Task Pipelines
| Task | Model | LoRA Adapter |
|------|-------|-------------|
| Summarize | mT5-small | summarize.{lang} |
| Translate | mT5-small | translate.{src→dst} |
| Key Points | mT5-small | keypoints.{lang} |
| Generate Doc | mT5-small | gendoc.{lang} |
| Generate Slides | mT5-small | slides.{lang} |
| Image Search | CLIP ViT-B/32 | — |

### SwarmCoordinator
- One device processes AI tasks for the entire group
- Uses existing KChat MLS/XMPP messaging for E2E-encrypted transport
- Device election: highest-tier idle device with required model
- Falls back to local inference or server offload if no volunteer

## Platform Matrix

| Platform | Binding | Acceleration |
|----------|---------|-------------|
| Web (Chrome 113+) | WASM + wasm-bindgen | WebGPU / WASM SIMD |
| Web (Safari/Firefox) | WASM | WASM SIMD |
| macOS | N-API (napi-rs) | Metal / CoreML |
| Windows | N-API | DirectML / CUDA |
| Linux | N-API | Vulkan / CUDA |
| iOS 15+ | UniFFI staticlib | Metal / CoreML / ANE |
| Android | UniFFI cdylib | NNAPI / GPU Delegate |

## Language Coverage

22 languages across 7 language families — mT5-small was pre-trained on 101 languages; we ship LoRA adapters for:

EN, VI, TH, AR, ZH, ES, FR, DE, JA, KO, ID, MS, TL, PT, RU, HI, TR, FA, UR, BN, NE, KM

— 22 languages × 5 text tasks = 110 LoRA adapters (~3-5MB each).

## Model Sizes

| Model | Quantized | Purpose |
|-------|-----------|---------|
| mT5-small (int8) | 45MB | Base for all text tasks |
| multilingual-e5-small (int8) | 45MB | Semantic search embeddings |
| CLIP ViT-B/32 (int8) | 60MB | Image search |
| LoRA adapters | 3-5MB each | Task + language specialization |
| **Bundled total** | **90MB** | mT5 + e5 |
| **Peak memory** | **~275MB** | Text tasks only |
| **Peak memory** | **~435MB** | Text + image search |
