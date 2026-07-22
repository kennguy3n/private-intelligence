# KinShield — Privacy & Compliance with On-Device AI

A standalone demonstration of **zk-ai**'s privacy and compliance subsystem.
KinShield shows how to protect sensitive data with on-device PII detection,
redaction, policy enforcement, tamper-evident audit logging, zero-knowledge
attestations, and data residency certificates — all running locally.

## Demonstrated Capabilities

| Feature | zk-ai API | Description |
|---------|----------|-------------|
| PII Detection | `detect_pii` | Find names, emails, phones, SSNs, credit cards, addresses |
| PII Redaction | `redact` / `redact_with_report` | Replace PII with `[REDACTED_TYPE]` placeholders |
| PII Scan Pipeline | `pii_scan` | Full PII scan via AI pipeline |
| Sensitivity Classification | `classify_sensitivity` | Public, Internal, Confidential, Restricted |
| Policy Engine | `PolicyEngine` | Block tasks based on document sensitivity |
| Compliance Report | `compliance_report` | Generate report from audit log entries |
| Audit Log | `AuditLog` | Tamper-evident, hash-chained inference log |
| ZK Attestation | `ZkAttestation` | Cryptographic proof of on-device inference |
| Network Monitor | `NetworkMonitor` | Track outbound connections during inference |
| Data Residency | `ResidencyCertificate` | Prove all inference was local (zero network) |
| Model Verification | `verify_file` | SHA-256 integrity check of model files |

## Run

```bash
cargo run -p kinshield
```

The demo creates a temporary directory for the audit log and model cache,
then runs the full privacy/compliance workflow end-to-end.
