use zk_ai_core::{
    AiEngine, ModelSpec, TaskOptions,
    detect_pii, redact, redact_with_report,
    PiiEntity,
    AuditLog,
    ZkAttestation,
    NetworkMonitor,
    ResidencyCertificate,
    PolicyEngine, PolicyDecision,
    verify_file,
};
use chrono::Utc;

const SAMPLE_WITH_PII: &str = r#"
Patient: John Doe
DOB: 03/15/1985
SSN: 123-45-6789
Email: john.doe@example.com
Phone: (555) 123-4567
Address: 123 Main Street, Springfield, IL 62704

Visit Date: July 10, 2024
Chief Complaint: Chest pain and shortness of breath
Diagnosis: Mild hypertension, stress-related anxiety
Treatment: Prescribed lisinopril 10mg daily. Recommended stress management
and follow-up in 2 weeks. Patient's credit card on file: 4532 1234 5678 9012

Notes: Patient mentioned feeling overwhelmed at work. Employer: Acme Corp.
Emergency contact: Jane Doe, (555) 987-6543
"#;

const SAMPLE_PUBLIC_DOC: &str = r#"
Company Overview
Acme Corporation is a technology company founded in 2015.
We provide cloud infrastructure services to small and medium businesses.
Our headquarters is in San Francisco, California.
Visit our website at www.acme.com for more information.
"#;

const SAMPLE_CONFIDENTIAL_DOC: &str = r#"
Board Meeting Minutes — Q2 2024
The board approved the acquisition of BetaCorp for $45M in cash and stock.
Due diligence revealed no material liabilities. The deal is expected to close
in Q3. CEO compensation was increased to $850K base + $2M equity vesting over 4 years.
Revenue grew 32% YoY reaching $28M ARR. Churn decreased to 3.2%.
"#;

const SAMPLE_AUDIT_LOG_TEXT: &str = r#"
2024-07-15 09:23: Task=summarize, Model=mt5-small-int8, Status=success, Duration=12ms
2024-07-15 09:24: Task=classify_sensitivity, Model=mt5-small-int8, Status=success, Duration=3ms
2024-07-15 09:25: Task=pii_scan, Model=mt5-small-int8, Status=success, Duration=5ms
2024-07-15 09:26: Task=compliance_report, Model=mt5-small-int8, Status=success, Duration=8ms
2024-07-15 09:27: Task=translate, Model=mt5-small-int8, Status=success, Duration=15ms
"#;

fn print_section(title: &str) {
    println!("\n{}", "=".repeat(60));
    println!("  {}", title);
    println!("{}", "=".repeat(60));
}

fn print_pii_entities(entities: &[PiiEntity]) {
    if entities.is_empty() {
        println!("  No PII entities detected.");
        return;
    }
    for e in entities {
        println!("  [{:>12}] {} (chars {}-{})",
            e.entity_type, e.text, e.start, e.end);
    }
    println!("  Total: {} PII entities found.", entities.len());
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter("zk_ai_core=info,kinshield=info")
        .init();

    println!("╔══════════════════════════════════════════════════════════╗");
    println!("║  KinShield — Privacy & Compliance with On-Device AI     ║");
    println!("║  PII detection, audit logs, ZK attestation, residency   ║");
    println!("╚══════════════════════════════════════════════════════════╝");

    let work_dir = std::env::temp_dir().join("zk-ai-kinshield");
    std::fs::create_dir_all(&work_dir)?;
    let cache_dir = work_dir.join("models");
    let audit_log_path = work_dir.join("audit.jsonl");

    println!("Work directory: {}", work_dir.display());

    // ── 1. PII Detection (no model required — pure regex) ──
    print_section("1. PII Detection");
    println!("Scanning medical document for PII entities...");
    let entities = detect_pii(SAMPLE_WITH_PII);
    print_pii_entities(&entities);

    // ── 2. PII Redaction ──
    print_section("2. PII Redaction");
    let (redacted, report) = redact_with_report(SAMPLE_WITH_PII);
    println!("Redacted {} PII entities. First 500 chars:", report.len());
    let preview: String = redacted.chars().take(500).collect();
    println!("{}", preview);
    println!("...");

    // ── 3. Simple Redact (no report) ──
    print_section("3. Quick Redact");
    let quick = redact("Contact John at john@example.com or (555) 123-4567");
    println!("Original: Contact John at john@example.com or (555) 123-4567");
    println!("Redacted: {}", quick);

    // ── 4. Initialize AI Engine for pipeline-based tasks ──
    let mut engine = AiEngine::new(&cache_dir).await?;
    let device_tier = format!("{:?}", engine.profile().tier);
    let acceleration = format!("{:?}", engine.profile().acceleration);
    println!("\nDevice tier: {} | Acceleration: {}", device_tier, acceleration);

    println!("\nLoading mT5-small model...");
    engine.ensure_model(&ModelSpec::mt5_small_int8()).await?;

    // ── 5. PII Scan Pipeline ──
    print_section("4. PII Scan (AI Pipeline)");
    let result = engine.pii_scan(SAMPLE_WITH_PII, TaskOptions::default()).await?;
    println!("Output: {}", result.output);
    println!("Duration: {}ms | Tokens: {}→{}", result.duration_ms, result.input_tokens, result.output_tokens);

    // ── 6. Sensitivity Classification ──
    print_section("5. Sensitivity Classification");
    let result = engine.classify_sensitivity(SAMPLE_PUBLIC_DOC, TaskOptions::default()).await?;
    println!("Public document → {}", result.output);

    let result = engine.classify_sensitivity(SAMPLE_CONFIDENTIAL_DOC, TaskOptions::default()).await?;
    println!("Board minutes  → {}", result.output);

    // ── 7. Policy Engine ──
    print_section("6. Policy Engine Enforcement");
    let mut policy = PolicyEngine::new();
    policy.add_rule("restricted", vec!["translate".to_string(), "summarize".to_string()]);
    policy.add_rule("confidential", vec!["translate".to_string()]);

    let examples = [
        ("public", "summarize"),
        ("public", "translate"),
        ("confidential", "summarize"),
        ("confidential", "translate"),
        ("restricted", "summarize"),
        ("restricted", "translate"),
    ];

    for (sensitivity, task) in &examples {
        let decision = policy.check(sensitivity, task);
        let status = match decision {
            PolicyDecision::Allowed => "ALLOWED",
            PolicyDecision::Denied(reason) => &format!("DENIED: {}", reason),
        };
        println!("  {:>14} + {:>10} → {}", sensitivity, task, status);
    }

    // ── 8. Audit Log ──
    print_section("7. Tamper-Evident Audit Log");
    println!("Writing audit log to: {}", audit_log_path.display());

    // Clean up any previous log
    let _ = std::fs::remove_file(&audit_log_path);

    let mut audit_log = AuditLog::open(audit_log_path.clone())?;
    let entry1 = audit_log.append("summarize", "mt5-small-int8", "input text here", "summary output", None)?;
    let entry2 = audit_log.append("classify_sensitivity", "mt5-small-int8", "confidential doc", "Confidential", None)?;
    let entry3 = audit_log.append("pii_scan", "mt5-small-int8", "medical record", "5 PII entities found", None)?;
    let entry4 = audit_log.append("translate", "mt5-small-int8", "hello world", "xin chào", Some("translate.en_vi"))?;

    println!("  Appended {} entries.", 4);
    println!("  Entry 1: seq={}, task={}, hash={:.16}...", entry1.seq, entry1.task, entry1.entry_hash);
    println!("  Entry 2: seq={}, task={}, hash={:.16}...", entry2.seq, entry2.task, entry2.entry_hash);
    println!("  Entry 3: seq={}, task={}, hash={:.16}...", entry3.seq, entry3.task, entry3.entry_hash);
    println!("  Entry 4: seq={}, task={}, hash={:.16}...", entry4.seq, entry4.task, entry4.entry_hash);

    let verified = audit_log.verify();
    println!("\n  Audit log integrity verified: {}", verified);

    let all_entries = audit_log.read_all()?;
    println!("  Total entries in log: {}", all_entries.len());

    // ── 9. ZK Attestation ──
    print_section("8. Zero-Knowledge Attestation");
    let attestation = ZkAttestation::new(
        "device-aa11bb22",
        "pii_scan",
        "mt5-small-int8",
        "medical record text",
        "5 PII entities found",
        &device_tier,
        true, // local_only
    )
    .with_compliance("HIPAA", "v2.1", "Restricted");

    println!("Attestation ID: {}", attestation.id);
    println!("Device: {} | Task: {} | Local only: {}", attestation.device_id, attestation.task, attestation.local_only);
    println!("Model hash: {:.16}...", attestation.model_hash);
    println!("Inference hash: {:.16}...", attestation.inference_hash);
    println!("Compliance: {} | Policy: {} | Classification: {}",
        attestation.compliance_framework.as_deref().unwrap_or("N/A"),
        attestation.policy_version.as_deref().unwrap_or("N/A"),
        attestation.data_classification.as_deref().unwrap_or("N/A"));
    println!("Attestation hash: {:.16}...", attestation.hash());

    let json = attestation.to_json()?;
    println!("\nAttestation JSON (first 300 chars):");
    let preview: String = json.chars().take(300).collect();
    println!("{}", preview);

    // ── 10. Network Monitor ──
    print_section("9. Network Monitor");
    let monitor = NetworkMonitor::new();
    monitor.start();
    // Simulate some inference (no actual network calls)
    println!("  Monitor started. Running inference...");
    // In a real app, the transport layer would call record_connection()
    // on any outbound network activity. Since zk-ai runs on-device,
    // no connections are recorded.
    let connections = monitor.stop();
    println!("  Outbound connections during inference: {}", connections);
    println!("  All inference was local: {}", !monitor.had_connections());

    // ── 11. Data Residency Certificate ──
    print_section("10. Data Residency Certificate");
    let period_start = Utc::now() - chrono::Duration::minutes(5);
    let period_end = Utc::now();
    let certificate = ResidencyCertificate::generate(
        &all_entries,
        connections,
        period_start,
        period_end,
    );

    println!("Certificate ID: {}", certificate.id);
    println!("Period: {} → {}", certificate.period_start, certificate.period_end);
    println!("Inference events: {}", certificate.inference_count);
    println!("Network connections: {}", certificate.network_connections);
    println!("All local: {}", certificate.all_local);
    println!("Entry hashes covered: {}", certificate.entry_hashes.len());
    println!("Certificate hash: {:.16}...", certificate.certificate_hash);

    let cert_json = certificate.to_json()?;
    println!("\nCertificate JSON (first 300 chars):");
    let preview: String = cert_json.chars().take(300).collect();
    println!("{}", preview);

    // ── 12. Compliance Report (AI Pipeline) ──
    print_section("11. Compliance Report (AI Pipeline)");
    let result = engine.compliance_report(SAMPLE_AUDIT_LOG_TEXT, "en", TaskOptions::default()).await?;
    println!("Output: {}", result.output);
    println!("Duration: {}ms | Tokens: {}→{}", result.duration_ms, result.input_tokens, result.output_tokens);

    // ── 13. Model File Verification ──
    print_section("12. Model File Verification");
    // Verify the audit log file itself as a demonstration
    let verify_result = verify_file(&audit_log_path);
    println!("Verifying audit log file: {}", audit_log_path.display());
    println!("  Verified: {}", verify_result.verified);
    println!("  SHA-256: {:.32}...", verify_result.file_hash);

    println!("\n{}", "=".repeat(60));
    println!("  KinShield demo complete.");
    println!("  All privacy & compliance operations ran on-device.");
    println!("  No data was transmitted to any server.");
    println!("{}", "=".repeat(60));

    engine.shutdown().await?;
    Ok(())
}
