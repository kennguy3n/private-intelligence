# KinShield — On-Device Scam Risk Detection & Prevention

A privacy-first scam detection engine that runs entirely on-device, protecting family units across SMS, email, browser, messaging, and voice call channels. Built on [zk-ai-core](../core) with Southeast Asia multilingual focus.

## Key Features

- **25-indicator ontology** with SEA multi-language keyword detection (VI, TH, ID, MS, TL, KM, ZH, EN)
- **15 scam type families** with Southeast Asia focus (bank impersonation, delivery scam, telco impersonation, etc.)
- **Family construct** with per-member sensitivity thresholds, guardian alerts, and role-based protection
- **Bounded decision traces** — privacy-preserving, no raw text transmitted
- **Structured feedback** separating detection, classification, and explanation correctness
- **On-device calibration** from local feedback history (no core model retraining)
- **Report missed scam** mechanism for recall improvement
- **Anti-manipulation** via contribution caps, label hierarchy, and robust aggregation
- **URL analysis** — shortened URLs, IP addresses, suspicious TLDs, lookalike domains

## Architecture

```
Input: (text, channel, language)
  │
  ├─ Keyword detection (25 indicators × 8 languages)
  ├─ URL analysis (suspicious link patterns)
  ├─ Embedding detection (e5-small, semantic indicators)
  │
  ├─ Risk scoring → 5-bucket quantization + monotonic constraints
  ├─ Scam type classification → 15 families
  │
  └─ DetectionResult + DecisionTrace → AggregationBuffer
```

## Usage

```rust
use kinshield::{KinShieldEngine, Channel, FeedbackKind, ScamType};

# async fn example() -> Result<(), Box<dyn std::error::Error>> {
let mut engine = KinShieldEngine::new("/tmp/kinshield-cache").await?;

// Detect scam risk
let result = engine.detect(
    "Your account is suspended! Verify your password now!",
    Channel::Sms,
    "en",
).await?;

println!("Risk: {}/5, Type: {:?}", result.risk_bucket, result.scam_type);

// Submit feedback
engine.submit_feedback(&result.id, FeedbackKind::Correct, None)?;

// Report a missed scam
engine.report_missed("Suspicious message not caught", Channel::Sms, "vi", Some(ScamType::BankImpersonation))?;

// Flush aggregate reports
let reports = engine.flush_aggregates();

engine.shutdown().await?;
# Ok(())
# }
```

## Family Construct

```rust
use kinshield::{FamilyCircle, FamilyMember, MemberRole};

let mut family = FamilyCircle::new("fam-001");
family.alert_threshold = 3;

// Guardian
family.add_member(FamilyMember::new("adult", "Parent", MemberRole::Adult));

// Elderly member — lower threshold, alerts guardian
family.add_member(
    FamilyMember::new("elderly", "Grandparent", MemberRole::Elderly)
        .with_guardian("adult"),
);

engine.set_family(family);
```

## Indicator Ontology (25 indicators)

| Category | Indicators |
|----------|-----------|
| Psychological | urgency, authority_claim, threat_legal, threat_account, limited_time_offer |
| Financial | financial_request, promise_high_return, crypto_scheme, gift_card, bank_transfer, tax_penalty |
| Credential | credential_request, verification_request |
| Technical | remote_access, link_suspicious |
| Sender | sender_anomaly |
| Social | romance_grooming, charity_appeal, family_emergency |
| E-commerce | delivery_lure |
| Lottery | prize_lure |
| Employment | job_offer |
| Lure | free_gift |
| Contact | phone_callback |
| PII | personal_info_request |

Each indicator has keyword sets in 8 languages. Strength is quantized to Low/Medium/High.

## Scam Type Taxonomy (15 families, SEA-focused)

| Type | SEA Relevance |
|------|---------------|
| bank_impersonation | #1 in VN, TH, ID |
| government_impersonation | Common in VN, TH, KH |
| investment_fraud | High in VN, ID, MY |
| delivery_scam | Epidemic in TH, VN, ID |
| romance_scam | Cross-regional |
| job_scam | Rising in VN, TH, ID |
| lottery_prize | Common across SEA |
| tech_support | Growing in MY, SG |
| charity_scam | Seasonal in TH, ID, PH |
| family_emergency | Targets elderly across SEA |
| e_commerce_fraud | High in VN, TH, ID, PH |
| telco_impersonation | SEA-specific |
| social_media_takeover | High in PH, ID, VN |
| loan_scam | Rising in VN, MY, TH |
| parcel_customs | SEA-specific |

## Privacy

**What is collected:** Bounded decision trace (model_version, channel, language, predicted_outcome, scam_type, risk_bucket, top 3 indicators, feedback, prompt_version, label_confidence).

**What is NOT collected:** Raw text, sender, domain, URL, message length, exact timestamp, exact location, device identifier, embeddings, token probabilities, attention maps, hidden states, SHAP vectors, full logits, gradients, free-text explanations.

## Language Coverage

| Language | Code | Priority |
|----------|------|----------|
| Vietnamese | vi | Tier 1 (SEA core) |
| Thai | th | Tier 1 |
| Indonesian | id | Tier 1 |
| Malay | ms | Tier 1 |
| Tagalog | tl | Tier 1 |
| Khmer | km | Tier 1 |
| English | en | Tier 2 |
| Chinese | zh | Tier 2 |

## Integration with zk-ai-core

| zk-ai-core API | KinShield Usage |
|----------------|-----------------|
| `AiEngine::run_embedding()` | Semantic indicator detection (e5-small) |
| `keyword_match()` / `count_keyword_matches()` | Multi-language keyword detection |
| `AuditLog` | Tamper-evident detection log |
| `ZkAttestation` | Prove detection ran on-device |
| `NetworkMonitor` | Verify no network calls |
| `PolicyEngine` | Family policy enforcement |

## Running the Demo

```bash
cargo run -p kinshield-scam-demo
```

## Running Tests

```bash
cargo test -p kinshield
```

## Future Work

- Server-side secure aggregation (extend Go server)
- Differential privacy on released analytics
- Channel integration (Android SMS, browser extension, call transcription)
- Federated calibration training
- Delayed local confirmation
- Honeypot integration for holdout validation
