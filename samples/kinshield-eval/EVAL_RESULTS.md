# KinShield Local Algorithm Evaluation

**Dataset:** kinshield-ota-20260709-004 (SMS eval sets)
**Date:** 2026-07-22
**Mode:** Full pipeline (keyword + URL + PII + e5-small embedding model)

## Overall Metrics

| Metric | Value |
|--------|-------|
| Total samples | 862 |
| Scam samples | 479 |
| Safe samples | 383 |
| True Positives (scam→scam) | 205 |
| True Negatives (safe→safe) | 230 |
| False Positives (safe→scam) | 85 |
| False Negatives (scam→safe) | 165 |
| Suspicious (bucket 3) | 177 |
| Errors | 0 |
| **Accuracy** | **50.46%** |
| **Precision** | **70.69%** |
| **Recall** | **55.41%** |
| **F1 Score** | **62.12%** |
| False Positive Rate | 26.98% |

## Conservative Mode (suspicious → scam)

| Metric | Value |
|--------|-------|
| Recall | 65.55% (314 of 479 scams detected) |
| Precision | 67.24% |
| F1 Score | 66.38% |

## Risk Bucket Distribution

| Bucket | Label | Count | % |
|--------|-------|-------|---|
| 1 | Benign | 341 | 39.6% |
| 2 | Low | 54 | 6.3% |
| 3 | Suspicious | 177 | 20.5% |
| 4 | Likely Scam | 121 | 14.0% |
| 5 | Very Likely Scam | 169 | 19.6% |

## Per-Language Performance

| Lang | Detected | Missed | False Positive | Correct Safe | Recall |
|------|----------|--------|----------------|--------------|--------|
| en | 199 | 109 | 76 | 180 | 64.6% |
| vi | 115 | 56 | 77 | 50 | 67.3% |

## Scam Type Classification (TP only)

| Scam Type | Count |
|-----------|-------|
| e_commerce_fraud | 42 |
| social_media_takeover | 28 |
| family_emergency | 24 |
| bank_impersonation | 23 |
| investment_fraud | 22 |
| delivery_scam | 16 |
| other_unknown | 16 |
| charity_scam | 13 |
| job_scam | 7 |
| romance_scam | 6 |
| lottery_prize | 4 |
| government_impersonation | 2 |
| telco_impersonation | 1 |
| parcel_customs | 1 |

## Confusion Matrix

| | Pred Scam | Pred Susp | Pred Safe |
|---|-----------|-----------|-----------|
| Actual Scam | 205 | 109 | 165 |
| Actual Safe | 85 | 68 | 230 |

## Embedding Model Impact (keyword-only vs keyword+embedding)

| Metric | Keyword Only | With Embedding | Delta |
|--------|-------------|----------------|-------|
| Recall (strict) | 50.14% | 55.41% | +5.3pp |
| Precision | 70.47% | 70.69% | +0.2pp |
| F1 (strict) | 58.59% | 62.12% | +3.5pp |
| Recall (conservative) | 62.84% | 65.55% | +2.7pp |
| F1 (conservative) | 65.22% | 66.38% | +1.2pp |
| Scam families detected | 13 | 14 | +1 (romance_scam) |
| Family emergency detections | 4 | 24 | +20 |
| Charity scam detections | 7 | 13 | +6 |
| Investment fraud detections | 12 | 22 | +10 |
| False positive rate | 23.81% | 26.98% | +3.2pp |

## Analysis

### Strengths
- **High precision (70.7%)** — when the algorithm says "scam" (bucket 4-5), it's right 71% of the time
- **Zero errors** — full pipeline runs without failures
- **14 scam families classified** — broad coverage including romance scams (embedding-only detection)
- **Embedding model adds real value** — +5.3pp recall improvement, detecting 20 more family emergency scams, 10 more investment frauds, 6 more charity scams, and 6 romance scams that keywords alone missed
- **Vietnamese recall (67.3%)** outperforms English (64.6%) in conservative mode
- **177 messages (20.5%)** in suspicious bucket — ideal for user feedback calibration

### Weaknesses
- **55% strict recall** — still missing nearly half of scams at bucket 4-5 threshold
- **27% false positive rate** — 1 in 4 safe messages flagged as scam
- **165 scams classified as safe** — missed detections, likely subtle social engineering
- **Embedding false positives** — the e5 model adds 3.2pp to the false positive rate, as some safe messages have semantic overlap with scam prototypes

### Key Insight
The embedding model meaningfully improves recall (+5.3pp) by detecting semantic patterns that keywords miss (romance grooming, family emergency, charity appeals). The trade-off is a slight increase in false positives. The 0.85 similarity threshold balances this well — lower thresholds cause everything to fire (e5 embeddings cluster in a narrow 0.78+ cone), while higher thresholds miss too many real scams.

### Recommendation
1. **Short-term:** Use conservative mode (bucket ≥3) for 66% recall at 67% precision
2. **Medium-term:** Calibrate similarity thresholds per-indicator using the 177 suspicious samples + user feedback
3. **Long-term:** Expand prototype texts with more examples per indicator to improve embedding discrimination
