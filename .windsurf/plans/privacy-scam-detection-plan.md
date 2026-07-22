# Privacy-Preserving Scam Detection — Full Implementation Plan

## Objective
Implement a full-stack privacy-preserving scam detection improvement system with:
- On-device detection, structured feedback, counter tables, contribution limits
- Threat intelligence feed integration for external scam campaign data
- Mocked server-side aggregation with cohort suppression and DP noise simulation
- Comprehensive multi-region test data (SEA, Asia, Europe, Latin America)
- Governance and privacy documentation

## Current State Assessment

### Already Implemented
- 25 indicators with 3-level strength (Low/Medium/High), 8 languages
- 15 scam families with stable IDs, labels, prototypes
- Top-3 indicator selection, 5 risk buckets
- 5 structured feedback kinds with learning targets
- Missed-scam reporting with false-negative calibration
- DecisionTrace with local_id stripping (privacy-bounded)
- AggregationBuffer with daily contribution caps (50/day), 5 report types
- CalibrationLayer with risk bucket adjustment and indicator weights
- AuditLog with tamper-evident SHA-256 hashing
- FamilyCircle with PolicyEngine
- Go server with privacy guard, rate limiting, memory wipe

### Gaps to Address
1. No `ScamType::OtherUnknown` fallback
2. No indicator explanations or contribution rank in output
3. No schema versioning in decision traces or aggregation reports
4. No persistent counter tables (traces held in memory until flush)
5. No weekly contribution limits or per-cell caps
6. Confusion matrix lacks corrected_family dimension
7. No indicator strength × feedback breakdown
8. No explanation-quality tracking (wrong-reasons rate)
9. No label trust-level weighting
10. No privacy budget accountant or system health metrics
11. No local event retention/expiry or user opt-out
12. No threat intelligence feed integration
13. No server-side aggregation endpoint (mock)
14. No cohort suppression or DP noise simulation
15. No comprehensive multi-region test data

## Implementation Phases

### Phase 1: Taxonomy & Ontology Enhancements (p1-p2)

#### p1: Add ScamType::OtherUnknown
- Add `OtherUnknown` variant to `ScamType` enum in `taxonomy.rs`
- Add `as_str()` → `"other_unknown"`, `label()` → `"Other / Unknown Scam"`
- Add to `all()` slice
- Add prototype text for embedding k-NN
- Update `classify_scam_type()` in `scoring.rs` to return `OtherUnknown` when indicators are present but no specific family matches

#### p2: Indicator Explanations & Contribution Rank
- Add `explanation()` method to `IndicatorId` in `ontology.rs` — returns a user-facing string explaining why this indicator is suspicious
- Add `contribution_rank()` method to `IndicatorId` — returns a u8 rank (1=highest contribution) for sorting/display
- Add `IndicatorHit::with_explanation()` helper that produces a serializable struct with id, strength, match_count, explanation, contribution_rank
- Update `DetectionResult` to include indicator explanations in output
- Update `DecisionTrace` to include indicator explanations (max 3)

### Phase 2: Schema Versioning (p3)

#### p3: Schema Versioning
- Add `indicator_schema_version: String` field to `DecisionTrace` (value: `ONTOLOGY_VERSION`)
- Add `taxonomy_schema_version: String` field to `DecisionTrace`
- Add `aggregation_schema_version: String` to `AggregateReport` variants
- Add `SCAM_TAXONOMY_VERSION: &str = "1.0.0"` constant to `taxonomy.rs`
- Ensure all serialized outputs include schema versions for forward compatibility

### Phase 3: Counter Tables & Contribution Limits (p4-p5)

#### p4: Persistent Counter Tables
Create a new `CounterTables` struct in `aggregation.rs` (or new `counter_tables.rs`):

```rust
pub struct CounterTables {
    // A. Risk calibration: (channel, language, risk_bucket) × feedback_type → count
    risk_calibration: HashMap<(String, String, u8, FeedbackKind), usize>,
    // B. Scam-family accuracy: (predicted_family) × feedback_type → count
    family_accuracy: HashMap<(String, FeedbackKind), usize>,
    // C. Indicator usefulness: (indicator_id, indicator_strength) × feedback_type → count
    indicator_usefulness: HashMap<(String, String, FeedbackKind), usize>,
    // D. Family confusion matrix: (predicted_family, corrected_family) → count
    family_confusion: HashMap<(String, String), usize>,
    // E. Model-version comparison: (model_version, channel) × feedback_type → count
    model_version_stats: HashMap<(String, String, FeedbackKind), usize>,
    // Metadata
    last_updated: chrono::DateTime<chrono::Utc>,
    total_events: usize,
}
```

- `update_from_trace(trace: &DecisionTrace, feedback: Option<FeedbackKind>)` — updates all 5 tables from a trace + feedback
- `snapshot()` — returns a serializable snapshot of all counter tables
- `merge(other: &CounterTables)` — merges another device's counters (for aggregation)
- `clear()` — resets all tables after successful contribution
- Integrate into `AggregationBuffer`: on `add()`, immediately update counter tables and optionally discard the trace
- Integrate into `submit_feedback()`: update counter tables with feedback

#### p5: Weekly Contribution Limits + Per-Cell Caps
- Add `ContributionLimits` struct:
  ```rust
  pub struct ContributionLimits {
      max_feedback_events_per_week: usize,    // default: 20
      max_missed_scam_reports_per_week: usize, // default: 5
      max_per_indicator_cell_per_week: usize,  // default: 5
      max_per_family_cell_per_week: usize,     // default: 5
      max_total_contributions_per_week: usize, // default: 50
  }
  ```
- Add per-cell tracking: `HashMap<(indicator_id, week), usize>` and `HashMap<(family, week), usize>`
- Add weekly reset logic (based on ISO week number)
- Integrate into `AggregationBuffer::add()` — check all applicable limits before accepting
- Integrate into `submit_feedback()` — check feedback event limit
- Integrate into `report_missed()` — check missed-scam report limit
- Log when limits are hit (for system health metrics)

### Phase 4: Aggregation Improvements (p6-p7)

#### p6: Confusion Matrix + Indicator Strength Breakdown
- Update `ConfusionMatrixEntry` to include `corrected_family: Option<String>`:
  ```rust
  pub struct ConfusionMatrixEntry {
      pub predicted_type: String,
      pub corrected_type: Option<String>,
      pub count: usize,
  }
  ```
- Update `aggregate_confusion_matrix()` to produce predicted × corrected pairs
- Add new report type: `IndicatorStrengthBreakdown`:
  ```rust
  pub struct IndicatorStrengthFb {
      pub indicator: String,
      pub strength: String,
      pub feedback_type: String,
      pub count: usize,
  }
  ```
- Add `AggregateQuery::IndicatorStrengthFeedback` variant
- Update `flush_query()` to handle the new query type

#### p7: Explanation-Quality Tracking
- Add `ExplanationQualityReport` to aggregation:
  ```rust
  pub struct ExplanationQualityEntry {
      pub indicator: String,
      pub total_wrong_reasons: usize,
      pub total_feedback: usize,
      pub wrong_reasons_rate: f32,
  }
  ```
- Add `AggregateQuery::ExplanationQuality` variant
- Implement `aggregate_explanation_quality()` — counts `WrongReasons` feedback per indicator
- Integrate into counter tables: track wrong_reasons per indicator in `indicator_usefulness`

### Phase 5: Trust Levels & Privacy (p8-p10)

#### p8: Label Trust-Level Weighting
- Add `LabelTrust` enum to `feedback.rs`:
  ```rust
  pub enum LabelTrust {
      Exclude,    // "Not sure" feedback — exclude from learning
      Low,        // Thumbs-up only
      Medium,     // Corrected family, missed scam report
      High,       // External confirmation, expert review
  }
  ```
- Add `trust_level()` to `FeedbackKind`:
  - `Correct` → `Low`
  - `NotAScam` → `Medium` (explicit false positive)
  - `WrongType` → `Medium` (corrected family)
  - `WrongReasons` → `Medium`
  - `Uncertain` → `Exclude`
- Add `trust_weight()` returning f32: Exclude=0.0, Low=0.3, Medium=0.7, High=1.0
- Apply trust weighting in `CalibrationLayer::update_calibration()` — multiply count increments by trust weight
- Add external confirmation support: `FeedbackRecord` gains `source: FeedbackSource` enum (User, ExpertReview, ExternalThreatIntel)

#### p9: Privacy Budget Accountant + System Health
- Create `privacy_budget.rs`:
  ```rust
  pub struct PrivacyBudget {
      total_epsilon: f64,           // e.g., 1.0 per week
      consumed_epsilon: f64,
      delta: f64,                   // e.g., 1e-9
      queries_made: usize,
      max_queries: usize,           // e.g., 10 per week
  }
  ```
- `consume(epsilon: f64) -> bool` — checks and consumes budget
- `remaining() -> f64` — returns remaining budget
- `reset_weekly()` — resets consumed budget
- Create `SystemHealth` struct in aggregation:
  ```rust
  pub struct SystemHealth {
      pub contribution_caps_hit: usize,
      pub privacy_budget_remaining: f64,
      pub suppressed_cohorts: usize,
      pub aggregation_rounds: usize,
      pub failed_aggregations: usize,
      pub last_flush: Option<chrono::DateTime<chrono::Utc>>,
  }
  ```
- Integrate into `AggregationBuffer` — track when caps are hit, when flushes occur

#### p10: Event Retention/Expiry + User Opt-Out
- Add `EventRetention` config to `AggregationBuffer`:
  ```rust
  pub struct EventRetention {
      pub max_age_days: usize,          // default: 14
      pub max_pending_aggregate_days: usize, // default: 7
  }
  ```
- Add `purge_expired()` method — removes traces older than `max_age_days`
- Add `PrivacySettings` struct:
  ```rust
  pub struct PrivacySettings {
      pub contribute_aggregates: bool,   // default: true
      pub contribute_feedback: bool,     // default: true
      pub contribute_missed_reports: bool, // default: true
  }
  ```
- Integrate into `KinShieldEngine` — check settings before adding to aggregation buffer
- Add `delete_local_data()` method — clears all local traces, counters, and calibration data

### Phase 6: Threat Intelligence (p11)

#### p11: Threat Intelligence Feed Module
- Create `threat_intel.rs`:
  ```rust
  pub struct ThreatIntelFeed {
      campaigns: Vec<ScamCampaign>,
      last_updated: chrono::DateTime<chrono::Utc>,
      source: String,
  }

  pub struct ScamCampaign {
      pub campaign_id: String,
      pub scam_type: ScamType,
      pub indicators: Vec<IndicatorId>,
      pub regions: Vec<String>,        // ["SEA", "EU", "LATAM"]
      pub channels: Vec<Channel>,
      pub first_seen: chrono::NaiveDate,
      pub last_seen: chrono::NaiveDate,
      pub severity: u8,                // 1-5
      pub keywords: Vec<String>,       // campaign-specific keywords
      pub url_patterns: Vec<String>,   // known malicious URL patterns
      pub status: CampaignStatus,      // Active, Declining, Resolved
  }
  ```
- `ingest_json()` — parse external threat intel JSON feed
- `match_campaign(text, channel, language)` — check if a message matches known campaign patterns
- `boost_indicators(indicators, campaign)` — boost indicator strength based on active campaign matches
- Integrate into `KinShieldEngine::detect()` — after indicator extraction, check threat intel and boost matching indicators
- Add `ThreatIntelReport` to `DetectionResult` — shows which campaigns matched (if any)
- Support multiple feed sources with `ThreatIntelFeed::merge()`

### Phase 7: Mock Server Aggregation (p12)

#### p12: Server-Side Mock Aggregation Endpoint
- Create `server/internal/aggregation/` package in Go:
  - `handler.go` — POST `/api/aggregation/submit` endpoint
  - `cohort.go` — cohort suppression logic (min 100 devices)
  - `dp_noise.go` — differential privacy noise simulation (Laplace mechanism)
  - `store.go` — in-memory store for aggregate contributions
- Request format:
  ```json
  {
    "device_pseudonym": "hashed_pseudonym",
    "schema_version": "1.0.0",
    "counter_tables": { ... },
    "contribution_count": 42,
    "week_bucket": "2024-W29"
  }
  ```
- Response:
  ```json
  {
    "accepted": true,
    "cohort_size": 1342,
    "suppressed": false,
    "dp_noise_applied": true
  }
  ```
- Cohort suppression: if cohort size < 100, return `suppressed: true` and don't release aggregates
- DP noise: apply Laplace noise to all counter values before releasing aggregates
- Track system health metrics: total contributions, suppressed cohorts, DP budget consumption

### Phase 8: Comprehensive Test Data (p13)

#### p13: Multi-Region Test Data Sets
Create `tests/test_data/` directory with comprehensive scam samples:

**Structure:**
```
tests/test_data/
├── sea/
│   ├── vietnam.json      # 50+ samples: bank impersonation (Vietcombank), delivery scams, gov impersonation
│   ├── thailand.json     # 50+ samples: lottery, delivery, loan scams
│   ├── indonesia.json     # 50+ samples: e-commerce, telco impersonation, job scams
│   ├── philippines.json   # 50+ samples: romance, OFW, lottery, gov
│   ├── malaysia.json      # 50+ samples: macau scam, parcel customs, investment
│   ├── cambodia.json      # 30+ samples: delivery, gov impersonation
│   └── singapore.json     # 30+ samples: bank, gov, e-commerce
├── asia/
│   ├── china.json         # 50+ samples: delivery, gov, e-commerce, social media takeover
│   ├── japan.json         # 30+ samples: delivery, tech support, romance
│   ├── korea.json         # 30+ samples: delivery, investment, phishing
│   └── india.json         # 50+ samples: UPI fraud, delivery, gov, lottery
├── europe/
│   ├── uk.json            # 40+ samples: bank impersonation, delivery, HMRC
│   ├── germany.json       # 30+ samples: package, bank, phishing
│   ├── france.json        # 30+ samples: delivery, bank, crypto
│   └── spain.json         # 30+ samples: delivery, lottery, bank
├── latam/
│   ├── brazil.json        # 40+ samples: PIX fraud, delivery, lottery, phishing
│   ├── mexico.json        # 30+ samples: delivery, bank, extortion
│   └── colombia.json      # 30+ samples: lottery, bank, delivery
└── benign/
    └── legitimate.json    # 100+ samples: real bank SMS, delivery notifications, job offers, etc.
```

**Each sample includes:**
```json
{
  "id": "vn_bank_001",
  "text": "Thân gửi khách hàng, tài khoản của bạn tại Vietcombank bị khóa...",
  "language": "vi",
  "channel": "sms",
  "expected_outcome": "scam",
  "expected_scam_type": "bank_impersonation",
  "expected_risk_bucket": 5,
  "expected_indicators": ["sender_anomaly", "urgency", "verification_request"],
  "region": "SEA",
  "country": "VN",
  "notes": "Vietcombank impersonation SMS with verification link"
}
```

- Create a test harness that loads all JSON files and runs detection against each sample
- Generate a test report showing detection accuracy, false positive rate, confusion matrix
- Include benign messages to test false positive rates
- Add Rust integration tests in `tests/` that load and run the test data

### Phase 9: Governance Docs (p14)

#### p14: Documentation
- Update `docs/ARCHITECTURE.md` with KinShield scam detection architecture
- Create `docs/PRIVACY_PROMISE.md` — user-facing privacy commitment
- Create `docs/DATA_FLOW.md` — data flow diagram showing what leaves device and what stays local
- Create `docs/THREAT_MODEL.md` — threat model for the scam detection system
- Create `docs/SCAM_DETECTION_PLAN.md` — the full implementation plan document

### Phase 10: Compile & Test (p15)

#### p15: Verification
- `cargo build` — ensure all crates compile
- `cargo test` — run all unit and integration tests
- Run multi-region test data suite
- Verify zero raw content in serialized decision traces
- Verify contribution limits enforced
- Verify privacy budget accounting
- Verify cohort suppression logic
- Run demo application with comprehensive test data

## File Impact Summary

### Files to Modify
- `crates/kinshield/src/taxonomy.rs` — add OtherUnknown, SCAM_TAXONOMY_VERSION
- `crates/kinshield/src/ontology.rs` — add explanation(), contribution_rank(), schema version
- `crates/kinshield/src/decision_trace.rs` — add schema version fields, indicator explanations
- `crates/kinshield/src/aggregation.rs` — counter tables, weekly limits, per-cell caps, new report types
- `crates/kinshield/src/feedback.rs` — LabelTrust, FeedbackSource
- `crates/kinshield/src/calibration.rs` — trust-weighted updates
- `crates/kinshield/src/lib.rs` — integrate privacy settings, threat intel, event retention
- `crates/kinshield/src/detection/scoring.rs` — return OtherUnknown fallback
- `crates/kinshield/src/detection/mod.rs` — add indicator explanations to DetectionResult
- `crates/kinshield/src/report_missed.rs` — add weekly limit check
- `crates/kinshield/src/tests/detection_tests.rs` — update for new types
- `samples/kinshield-scam-demo/src/main.rs` — update demo with new features

### Files to Create
- `crates/kinshield/src/counter_tables.rs` — persistent counter tables
- `crates/kinshield/src/privacy_budget.rs` — privacy budget accountant
- `crates/kinshield/src/threat_intel.rs` — threat intelligence feed module
- `crates/kinshield/src/privacy_settings.rs` — user privacy settings
- `crates/kinshield/src/system_health.rs` — system health metrics
- `server/internal/aggregation/handler.go` — mock aggregation endpoint
- `server/internal/aggregation/cohort.go` — cohort suppression
- `server/internal/aggregation/dp_noise.go` — DP noise simulation
- `server/internal/aggregation/store.go` — in-memory aggregate store
- `tests/test_data/**/*.json` — comprehensive multi-region test data
- `tests/multi_region_tests.rs` — integration tests with test data
- `docs/PRIVACY_PROMISE.md` — privacy commitment
- `docs/DATA_FLOW.md` — data flow diagram
- `docs/THREAT_MODEL.md` — threat model
- `docs/SCAM_DETECTION_PLAN.md` — implementation plan

## Execution Order
1. p1 → p2 → p3 (foundational: taxonomy, ontology, schema)
2. p4 → p5 (counter tables, contribution limits)
3. p6 → p7 (aggregation improvements)
4. p8 → p9 → p10 (trust levels, privacy, retention)
5. p11 (threat intelligence)
6. p12 (mock server)
7. p13 (test data)
8. p14 (docs)
9. p15 (compile & verify)

Each phase builds on the previous. Compile checks after each phase.
