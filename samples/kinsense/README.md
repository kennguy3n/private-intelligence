# KinSense — Family Safety with On-Device AI

A standalone demonstration of how [zk-ai](../../README.md) powers **[KinSense](https://getkinsense.com)** —
a family safety & health product that connects family members through mutual consent
and advanced privacy technologies. All AI processing runs locally on-device with no
network calls, ensuring sensitive family data never leaves the device.

## KinSense Product Features → zk-ai Capabilities

| KinSense Feature | zk-ai API | Description |
|-----------------|----------|-------------|
| Arrival/departure alerts | `auto_tag` | Auto-tag safety events (arrivals, departures, anomalies) with topic labels |
| Safety event search | `TextIndex`, `semantic_search` | Build and query a semantic index of family safety events |
| Health anomaly detection | `find_similar`, `cosine_similarity` | Compare activity patterns against known normal/anomalous signals |
| Activity pattern comparison | `cosine_similarity` | Detect mismatches between expected and observed activity patterns |
| Routine detection | `cluster` | Group safety events into routine patterns (commute, school, errands) |
| Alert prioritization | `rerank` | Rerank safety alerts by urgency for family members |
| SOS urgency classification | `classify_urgency` | Classify SOS messages as Critical, High, Medium, or Low |
| Family check-in replies | `smart_reply` | Generate suggested replies to family check-in messages |
| Daily safety digest | `notif_summary` | Summarize a day's safety notifications into a brief digest |
| PII redaction before sharing | `detect_pii`, `redact_with_report` | Scan and redact PII from shared family data before E2EE transmission |
| PII scan (AI) | `pii_scan` | AI-powered PII scanning of shared family data |
| Data sensitivity classification | `classify_sensitivity` | Classify family data as Public, Internal, Confidential, or Restricted |
| Data sharing policy engine | `PolicyEngine`, `PolicyDecision` | Enforce opt-in sharing rules based on data sensitivity |
| Location recognition | `ImageIndex`, `image_search` | Index and search known safe locations (home, school, hospital) |
| Safety event audit trail | `AuditLog` | Tamper-evident audit log of all safety AI processing |
| ZK attestation for SOS | `ZkAttestation` | Cryptographic proof that SOS classification ran on-device |
| Network verification | `NetworkMonitor` | Verify no outbound connections during safety processing |
| Data residency | `ResidencyCertificate` | Certificate proving all inference was local |
| Index persistence | `TextIndex::to_json` / `ImageIndex::to_json` | Serialize/deserialize safety indices for offline persistence |
| File integrity | `verify_file` | Verify audit log file integrity via SHA-256 |

## Run

```bash
cargo run -p kinsense
```

The demo creates a temporary work directory, initializes the `AiEngine`,
builds local safety event and health signal indices, and runs 23 pipeline
sections covering the full KinSense family safety workflow — all on-device.
