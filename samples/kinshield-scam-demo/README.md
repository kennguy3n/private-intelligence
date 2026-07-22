# KinShield — Scam Detection Demo

On-device scam risk detection across SMS, messaging, email, browser, and call channels with Southeast Asia multilingual support and family-construct protection.

## Quick Start

```bash
cargo run -p kinshield-scam-demo
```

## What It Demonstrates

1. **SMS scam detection** — Vietnamese bank impersonation SMS
2. **Messaging scam** — Thai delivery scam with malicious link
3. **Email scam** — Indonesian investment fraud email
4. **Browser URL** — Tagalog fake lottery page text
5. **Call transcript** — Malay tech support scam
6. **Family alerts** — Elderly member receives high-risk SMS, guardian notified
7. **Feedback flow** — Thumb up, thumb down with structured selector
8. **Report missed scam** — User reports undetected phishing
9. **Decision trace** — Privacy-bounded trace for each detection
10. **Aggregation buffer** — Local batching and aggregate histograms
11. **Calibration** — Risk score adjustment from feedback
12. **Audit log + ZK attestation** — Tamper-evident detection log

## Architecture

All detection runs on-device using zk-ai-core's e5-small embedding model.
No message content, embeddings, or raw model internals leave the device.
Only privacy-bounded decision traces are collected for aggregation.

See `../../crates/kinshield/README.md` for full architecture details.
