# KinShield — On-Device Scam Risk Detection & Prevention

A privacy-first scam detection engine that runs entirely on-device, protecting family units across SMS, email, browser, messaging, and voice call channels. Built on [zk-ai-core](../core) with Southeast Asia multilingual focus.

## Key Features

- **33-indicator ontology** with SEA multi-language keyword detection (VI, TH, ID, MS, TL, KM, ZH, EN)
- **30 scam type families** with Southeast Asia focus (bank impersonation, delivery scam, telco impersonation, pig butchering, fake QR code, subscription trap, etc.)
- **Family construct** with per-member sensitivity thresholds, guardian alerts, and role-based protection
- **Bounded decision traces** — privacy-preserving, no raw text transmitted
- **Structured feedback** separating detection, classification, and explanation correctness
- **On-device calibration** from local feedback history (no core model retraining)
- **Report missed scam** mechanism for recall improvement
- **Anti-manipulation** via contribution caps, label hierarchy, and robust aggregation
- **URL analysis** — shortened URLs, IP addresses, suspicious TLDs, lookalike domains, typosquatting, punycode/IDN detection, data URI/javascript protocol detection, non-standard ports, credential phishing patterns

## Architecture

```
Input: (text, channel, language)
  │
  ├─ Keyword detection (33 indicators × 8 languages)
  ├─ URL analysis (suspicious link patterns, lookalike domains, QR codes, punycode)
  ├─ Embedding detection (e5-small, semantic indicators)
  ├─ Heuristic detection (wrong-number pivot, QR code, subscription trap, impersonation)
  │
  ├─ Risk scoring → 5-bucket quantization + monotonic constraints + legitimacy signals
  ├─ Scam type classification → 30 families (scored classification)
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

## Indicator Ontology (33 indicators, v1.2.0)

| Category | Indicators |
|----------|-----------|
| Psychological | urgency, authority_claim, threat_legal, threat_account, limited_time_offer |
| Financial | financial_request, promise_high_return, crypto_scheme, gift_card, bank_transfer, tax_penalty, subscription_trap |
| Credential | credential_request, verification_request |
| Technical | remote_access, link_suspicious, qr_code_scan, deepfake_impersonation |
| Sender | sender_anomaly |
| Social | romance_grooming, charity_appeal, family_emergency, wrong_number_pivot |
| E-commerce | delivery_lure, fake_marketplace |
| Lottery | prize_lure |
| Employment | job_offer |
| Lure | free_gift, government_benefit_lure |
| Contact | phone_callback |
| PII | personal_info_request |
| Extortion | sextortion |
| Recovery | recovery_scam |

Each indicator has keyword sets in 8 languages. Strength is quantized to Low/Medium/High.

## Scam Type Taxonomy (30 families, SEA-focused)

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
| pig_butchering | Major threat in VN, TH, CN |
| money_mule | Rising across SEA |
| sextortion | Cross-regional |
| recovery_scam | Targets prior victims |
| customer_service_scam | Shopee/Lazada impersonation |
| sim_swap_fraud | Growing in VN, TH |
| utility_impersonation | Common in PH, VN |
| account_takeover | Cross-regional |
| property_rental | Rising in SG, VN |
| business_email_compromise | Corporate targeting |
| fake_qr_code | Emerging in TH, VN, MY |
| subscription_trap | Growing across SEA |
| social_media_impersonation | Instagram/Facebook cloning |
| toll_road_scam | VN-specific |
| other_unknown | Fallback |

Classification uses a scored approach: each scam type receives a score based on which indicators are present and text keyword boosts, with the highest-scoring type selected. This reduces `other_unknown` fallbacks.

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

## Running the Demos

```bash
# Scam detection demo (SMS, email, messaging, browser, call)
cargo run -p kinshield --bin kinshield-scam-demo

# Privacy & compliance demo (PII scanning, redaction, audit logs)
cargo run -p kinshield --bin kinshield-privacy-demo

# Evaluation harness (runs detection on SMS eval dataset)
cargo run -p kinshield --bin kinshield-eval

# Debug embedding prototypes
cargo run -p kinshield --bin debug-embed
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
- Deepfake audio/video detection (beyond keyword matching)
- Real-time QR code image analysis
- Cross-message conversation pattern tracking
