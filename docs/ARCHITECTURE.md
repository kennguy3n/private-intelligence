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

## KinShield — Privacy-Preserving Scam Detection

### Overview

KinShield is an on-device scam detection system built on top of the zk-ai core engine. It runs entirely locally — no message content ever leaves the device. Only quantized, aggregated counter tables are shared with the server for model improvement.

### Detection Pipeline

```
Message → Keyword Match (25 indicators, multi-language)
        → URL Analysis (suspicious link detection)
        → PII Detection (credential/financial requests)
        → Semantic Embedding (e5-small similarity)
        → Threat Intel Boost (external campaign matching)
        → Risk Scoring (1-5 bucket)
        → Calibration Layer (local feedback adjustment)
        → DetectionResult + IndicatorExplanations
```

### Key Components

| Component | Purpose |
|-----------|---------|
| **Ontology** (v1.0.0) | 25 fixed indicators with explanations and contribution ranks |
| **Taxonomy** (v1.0.0) | 15 scam families + OtherUnknown fallback |
| **CalibrationLayer** | Adjusts risk buckets based on local feedback (trust-weighted) |
| **AggregationBuffer** | Collects decision traces, generates aggregate reports |
| **CounterTables** | 5 persistent counter types (risk calibration, family accuracy, indicator usefulness, family confusion, model-version comparison) |
| **ContributionLimits** | Weekly caps: 20 feedback, 5 missed reports, 50 total; per-indicator and per-family cell caps |
| **PrivacyBudget** | DP epsilon tracking (default 1.0/week, 10 queries max) |
| **PrivacySettings** | Per-type opt-out (aggregates, feedback, missed reports) + event retention (14 days traces, 7 days pending) |
| **ThreatIntelFeed** | External scam campaign ingestion, keyword/URL pattern matching, indicator boosting |
| **FamilyCircle** | Family-level alerts and policy enforcement |

### Privacy Guarantees

1. **No raw content leaves the device** — only quantized counter tables are shared
2. **Cohort suppression** — cohorts with <5 devices are suppressed server-side
3. **Differential privacy** — Laplace noise added to all aggregated counts (ε=1.0/week)
4. **Contribution limits** — per-device weekly caps prevent any single device from dominating
5. **Trust-level weighting** — feedback is weighted: Correct=0.3, explicit corrections=0.7, Uncertain=0.0
6. **Event retention** — local data auto-expires after 14 days (configurable)
7. **User opt-out** — users can disable any contribution type at any time
8. **Delete local data** — one-call wipe of all traces, counters, calibration, and pending contexts

### Data Flow

```
Device A                Server (Mock)              Device B
─────────              ──────────────              ─────────
Detect → Trace    →    Aggregate        →    Improved calibration
Feedback → Counter    Cohort suppress       (downloaded as model
Missed → Counter      DP noise              updates, not raw data)
                      Privacy budget
```

### Aggregation Report Types

1. ConfirmationRateByBucket — P(user confirms scam | risk_bucket, channel, language)
2. FalsePositiveRateByIndicator — FP rate per top indicator
3. ScamTypeConfusionMatrix — predicted × corrected family
4. IndicatorPairPerformance — co-occurrence accuracy
5. PerformanceByLangChannel — coarse language × channel breakdown
6. IndicatorStrengthFeedback — indicator × strength × feedback type
7. ExplanationQuality — wrong-reasons rate by indicator
8. ModelVersionComparison — model version × channel × feedback

### Schema Versioning

All decision traces and aggregation reports carry schema version fields:
- `indicator_schema_version` (ontology)
- `taxonomy_schema_version` (taxonomy)
- `aggregation_schema_version` (aggregation)

This ensures forward compatibility as the ontology and taxonomy evolve.
