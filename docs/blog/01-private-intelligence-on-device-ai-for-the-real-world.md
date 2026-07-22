# Private Intelligence: On-Device AI That Actually Works in the Real World

**A product-focused look at how zk-ai delivers 100% classification correctness across 22 languages — at sub-millisecond latency, entirely offline.**

---

## The Problem with Cloud AI

Every time you send a document to GPT-4 or Claude, three things happen:

1. **Your data leaves the device.** Sensitive contracts, internal memos, customer PII — all transmitted to a third-party server you don't control.
2. **You wait.** 2–5 seconds per request, every time, even for simple classification tasks like "is this email urgent?"
3. **You pay.** Per-token pricing compounds quickly: a team of 50 processing 100 documents/day at GPT-4 rates spends $500+/month just on summarization.

For compliance-heavy industries — legal, healthcare, finance, government — the first point is often a dealbreaker. For everyone else, the latency and cost are constant friction.

## What We Built

**zk-ai** is a privacy-first AI SDK that runs entirely on-device. No network calls. No API keys. No per-token costs. It bundles 90MB of quantized models (mT5-small + multilingual-e5-small) and delivers 40+ AI pipelines across text, email, meetings, documents, and compliance.

We just ran a comprehensive benchmark: **455 real-world tests across 22 languages**, covering everything from sentiment analysis on Vietnamese product reviews to duplicate ticket detection across Spanish-English language pairs.

The results:

| Metric | Value |
|--------|-------|
| Total tests | 455 |
| Successful executions | 455 (100%) |
| Classification correctness | 238/238 (100%) |
| Average latency | 0.9ms |
| p99 latency | 33ms |
| Throughput | 1,121 ops/sec |
| Languages tested | 22 |
| Total model size | 90MB |

## What Can It Do?

### Email & Messaging Intelligence
- **Summarize** long email threads into actionable summaries
- **Draft replies** with intent detection (agree, decline, request info, escalate)
- **Classify tone** — Urgent, FYI, Action Needed, Positive, Concerned
- **Categorize emails** — Action Required, Newsletter, Vendor, Client, Internal
- **Prioritize** what needs a response vs. what can wait
- **Smart replies** for chat messages

### Meeting & Voice Intelligence
- **Transcribe** audio with full Whisper encoder-decoder speech-to-text
- **Generate meeting summaries** with key points and decisions
- **Extract action items** automatically
- **Answer questions** about meeting content ("What was the Q3 revenue?")
- **Live transcription** for real-time captioning

### Document Productivity
- **Summarize** documents in 22 languages
- **Translate** between any of 22 language pairs
- **Extract key points** from long documents
- **Generate documents** from outlines
- **Create slide decks** from topics
- **Grammar check** with error detection
- **Simplify** jargon-heavy text

### Knowledge & Search
- **Semantic search** across your document corpus
- **Find similar documents** by meaning, not keywords
- **Auto-tag** documents with topic labels
- **Cluster** documents into thematic groups
- **Daily digests** of your activity
- **Document Q&A** with context-aware answers
- **Find experts** — locate colleagues who know about a topic

### Compliance & Privacy
- **PII scanning** — detect SSNs, credit cards, emails, phone numbers
- **Sensitivity classification** — Public, Internal, Confidential, Restricted
- **Compliance reports** — audit trail of all AI tasks run
- **Policy lookup** — query internal policies naturally

### Support Intelligence
- **Ticket summarization** and reply drafting
- **Urgency classification** — P1 (Critical) through P4 (Low)
- **Duplicate detection** — find related tickets even across languages
- **Contract analysis** — extract key terms from legal documents
- **Date extraction** from contracts and emails

## The Multilingual Edge

Most AI tools are English-first. We designed zk-ai to be multilingual from the ground up. The benchmark includes **130 dedicated multi-language and mixed-language tests** in Vietnamese, Spanish, French, German, Japanese, Arabic, Korean, Russian, and Chinese — plus code-switching samples that mix languages mid-sentence.

Results by language category:

| Task | English | Multi-Language | Mixed-Language |
|------|---------|----------------|----------------|
| Sentiment | 100% | 100% | 100% |
| Tone | 100% | 100% | — |
| Urgency | 100% | 100% | — |
| Sensitivity | 100% | 100% | — |
| Email Categorization | 100% | 100% | — |
| Dedup | 100% | 100% | — |

A real example from the benchmark — the system correctly identifies this Vietnamese ticket as Critical urgency:

> **Input:** "Hệ thống production bị sập. Tất cả requests thất bại. ONNX session init failed."
> **Output:** Critical (score: 0.950)

And this Japanese feature request as Medium urgency:

> **Input:** "機能リクエスト：ダークモードを追加してください"
> **Output:** Medium (score: 0.750)

## Latency: Why It Matters

At **0.9ms average latency**, zk-ai is 2,000–5,000x faster than cloud APIs:

| Solution | Avg Latency | Cost per 1K requests |
|----------|-------------|----------------------|
| GPT-4 API | ~2,000–5,000ms | $0.03 |
| Claude 3.5 API | ~2,000–4,000ms | $0.25/1M tokens |
| zk-ai (on-device) | 0.9ms | $0.00 |

This isn't just about speed — it changes what's possible. Real-time email triage as you type. Instant document classification on mobile devices with no connectivity. Batch processing 10,000 documents in under 10 seconds.

## Where It Falls Short

Transparency matters. Here's what the benchmark revealed:

- **Text generation quality**: Summaries and translations are substantive but not GPT-4 quality. The mT5-small model (45MB) can't match a 1.7T-parameter model. Outputs average 174 characters — useful for briefs, not for long-form generation.
- **Audio transcription**: Full Whisper encoder-decoder pipeline with direct mel-spectrogram ONNX tensor input. Output quality depends on the Whisper-tiny int8 model (30MB) — suitable for clear speech, may struggle with heavy accents or noisy environments.

## Who Is This For?

- **Enterprise teams** that can't send data to cloud AI providers due to compliance, regulatory, or security requirements
- **Mobile-first products** that need AI capabilities without network dependency
- **High-volume workflows** where per-token API costs are prohibitive
- **Multilingual teams** operating across Asia, Europe, and the Middle East
- **Edge and IoT deployments** where connectivity is unreliable

## What's Next

- [x] Complete ONNX Runtime execution-provider integration (Metal, CoreML, NNAPI, CUDA, WebGPU) and hit production p99 latency targets
- [x] Ship a full Whisper speech-to-text pipeline with direct mel-spectrogram ONNX encoder-decoder inference, replacing the text-prompt fallback
- [x] Launch a signed LoRA adapter marketplace with Ed25519 signature verification, SHA-256 integrity checks, and trusted-key allowlist for domain- and language-specific fine-tuning packs
- Swarm inference — distribute AI tasks across devices in a team via E2E-encrypted messaging

---

*zk-ai is a Rust-based SDK compiling to WASM, N-API, UniFFI, and Go FFI from a single codebase. It runs on web, desktop, iOS, Android, and server.*
