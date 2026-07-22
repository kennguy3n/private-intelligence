# zk-ai Sample Implementations

Four standalone demonstrations showing how to integrate [zk-ai](../README.md) into
different product contexts. Each sample runs independently — just `cargo run -p <name>`.

All inference runs **on-device**. No network calls, no API keys, no per-token costs.

## Samples

| Sample | Package | Description |
|--------|---------|-------------|
| **KChat B2C** | `kchat-b2c` | Consumer chat app — email summaries, smart replies, meeting summaries, notification digests, daily digests, pre-send checks |
| **KChat B2B** | `kchat-b2b` | Enterprise chat app — contract analysis, document comparison, ticket intelligence, compliance, meeting minutes, collaboration summaries |
| **KinShield** | `kinshield-scam-demo` | Scam detection — multi-channel (SMS, email, messaging, browser, call) scam detection with 25-indicator ontology, 15 SEA scam types, family construct with guardian alerts, privacy-bounded decision traces, on-device calibration, structured feedback, audit logs, PII detection, policy engine |
| **KinSense** | `kinsense` | Family safety — activity classification, anomaly detection, SOS urgency, smart replies, daily safety digest, PII redaction, policy engine, location recognition, audit trail, ZK attestation |

## Quick Start

```bash
# From the repository root

# Run any sample individually
cargo run -p kchat-b2c
cargo run -p kchat-b2b
cargo run -p kinshield-scam-demo
cargo run -p kinsense

# Build all samples
cargo build -p kchat-b2c -p kchat-b2b -p kinshield-scam-demo -p kinsense
```

## Architecture

Each sample is a standalone Rust binary that depends on `zk-ai-core`:

```
samples/
├── kchat-b2c/          # Consumer chat demo
│   ├── Cargo.toml
│   ├── README.md
│   └── src/main.rs
├── kchat-b2b/          # Enterprise chat demo
│   ├── Cargo.toml
│   ├── README.md
│   └── src/main.rs
├── kinshield-scam-demo/  # Scam detection demo
│   ├── Cargo.toml
│   ├── README.md
│   └── src/main.rs
├── kinsense/           # Family safety demo
│   ├── Cargo.toml
│   ├── README.md
│   └── src/main.rs
└── README.md           # This file
```

Each sample:
1. Creates a temporary model cache directory
2. Initializes the `AiEngine` (runs device profiling)
3. Loads the mT5-small model (or uses privacy APIs that don't require a model)
4. Runs multiple AI pipelines against realistic sample data
5. Prints results with timing and token metrics
6. Shuts down cleanly

## zk-ai Pipelines Used

### KChat B2C
`email_summary`, `smart_reply`, `classify_tone`, `chat_summary`, `notif_summary`,
`meeting_summary`, `action_items`, `pre_send_check`, `daily_digest`

### KChat B2B
`contract_analysis`, `compare_docs`, `find_clause`, `extract_dates`,
`ticket_summary`, `classify_urgency`, `ticket_reply`, `email_categorize`,
`sentiment`, `meeting_minutes`, `extract_decisions`, `follow_up`,
`collab_summary`, `auto_abstract`

### KinShield
`detect_pii`, `redact`, `AuditLog`, `PolicyEngine`, `PolicyDecision`,
`detect_pii`, `run_embedding`, `keyword_match`, `count_keyword_matches`,
`ZkAttestation`, `NetworkMonitor`, `ResidencyCertificate`, `verify_file`

### KinSense
`auto_tag`, `find_similar`, `cluster`, `rerank`, `classify_urgency`,
`smart_reply`, `notif_summary`, `pii_scan`, `classify_sensitivity`,
`semantic_search`, `image_search`, `run_embedding`,
`TextIndex`, `ImageIndex`, `cosine_similarity`,
`detect_pii`, `redact_with_report`,
`PolicyEngine`, `PolicyDecision`, `AuditLog`, `ZkAttestation`,
`NetworkMonitor`, `ResidencyCertificate`, `verify_file`
