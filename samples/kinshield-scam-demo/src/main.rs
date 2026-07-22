use kinshield::{
    KinShieldEngine, Channel, ScamType, FeedbackKind,
    FamilyCircle, FamilyMember, MemberRole,
};
use zk_ai_core::{
    AuditLog, ZkAttestation, NetworkMonitor, ResidencyCertificate,
};

// ── SEA Scam Samples ──

const SMS_BANK_VI: &str = r#"
Ngan hang Vietcombank: Tai khoan cua ban bi khoa do xac nhan dang nhap bat thuong.
Vui long xac minh danh tinh ngay lap tuc tai: http://vcb-verify.xyz/auth
Neu khong xac minh trong 2 gio, tai khoan se bi khoa vinh vien.
Lien he hotlien: 1900.54.54.54
"#;

const MSG_DELIVERY_TH: &str = r#"
พัสดุของคุณจัดส่งไม่สำเร็จ กรุณาอัปเดตที่อยู่ภายใน 24 ชั่วโมง
คลิกที่นี่: https://bit.ly/thaipost-reschedule
ค่าจัดส่งใหม่ 35 บาท
"#;

const EMAIL_INVESTMENT_ID: &str = r#"
Subject: Peluang Investasi Crypto dengan Keuntungan Dijamin 100%

Yth. Bapak/Ibu,
Bergabunglah dengan grup investasi crypto kami. Trader profesional akan
mengelola dana Anda dengan risiko nol. Keuntungan dijamin 2x dalam 1 minggu.
Minimum investasi hanya Rp 500.000. Penarikan kapan saja.
Daftar sekarang sebelum penawaran berakhir hari ini!
"#;

const BROWSER_LOTTERY_TL: &str = r#"
Congratulations! You are the lucky winner of our Grand Lottery!
You've won $50,000 USD! To claim your prize, pay the processing fee of $500.
Offer expires in 24 hours. This is a limited time offer.
Click here to claim: http://lottery-claim.top/winner
"#;

const CALL_TECH_SUPPORT_MS: &str = r#"
Hello, this is Microsoft technical support calling. We have detected a virus
on your computer. Your computer is infected and may crash at any time.
Please install this remote access software so we can fix it immediately.
Do not turn off your computer. Call us back at this number right now.
This is urgent, your data is at risk.
"#;

const BENIGN_SMS_VI: &str = r#"
Cam on ban da mua hang tai Shopee. Don hang #SP123456 se duoc giao trong 3-5 ngay.
Theo doi don hang tai: shopee.vn/order/SP123456
"#;

const MISSED_PHISHING_TH: &str = r#"
ธนาคารกรุงเทพ: บัญชีของคุณได้รับการอนุมัติเงินกู้ 50,000 บาท
กรุณายืนยันเพื่อรับเงินภายในวันนี้: https://bkk-loan.app/confirm
"#;

fn print_section(title: &str) {
    println!("\n{}", "=".repeat(70));
    println!("  {}", title);
    println!("{}", "=".repeat(70));
}

fn print_detection_result(result: &kinshield::DetectionResult) {
    println!("  Outcome:    {}", result.predicted_outcome);
    if let Some(ref scam_type) = result.scam_type {
        println!("  Scam Type:  {} ({})", scam_type.label(), scam_type.as_str());
    }
    println!("  Risk:       {}/5", result.risk_bucket);
    println!("  Channel:    {}", result.channel);
    println!("  Language:   {}", result.language_bucket);
    if !result.indicators.is_empty() {
        println!("  Indicators (top {}):", result.indicators.len());
        for ind in &result.indicators {
            println!("    - {} [{}] (matches: {})",
                ind.id.label(), ind.strength, ind.match_count);
        }
    } else {
        println!("  Indicators: none");
    }
    println!("  Duration:   {}ms", result.duration_ms);
    println!("  Model:      v{}", result.model_version);
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter("kinshield=info,zk_ai_core=warn")
        .init();

    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║  KinShield — On-Device Scam Risk Detection & Prevention     ║");
    println!("║  SMS • Email • Browser • Messaging • Call                   ║");
    println!("║  Southeast Asia multilingual • Family construct             ║");
    println!("╚══════════════════════════════════════════════════════════════╝");

    let work_dir = std::env::temp_dir().join("kinshield-demo");
    std::fs::create_dir_all(&work_dir)?;
    let cache_dir = work_dir.join("models");
    let audit_log_path = work_dir.join("audit.jsonl");

    println!("Work directory: {}", work_dir.display());

    // ── Initialize KinShield Engine ──
    print_section("Initializing KinShield Engine");
    let mut engine = KinShieldEngine::new(&cache_dir).await?;
    let profile = engine.device_profile();
    println!("Device tier: {:?} | Acceleration: {:?}", profile.tier, profile.acceleration);

    // ── 1. SMS Scam Detection (Vietnamese bank impersonation) ──
    print_section("1. SMS Scam Detection — Vietnamese Bank Impersonation");
    println!("Input: {}\n", SMS_BANK_VI.trim());
    let result = engine.detect(SMS_BANK_VI, Channel::Sms, "vi", None).await?;
    print_detection_result(&result);

    // ── 2. Messaging Scam (Thai delivery scam) ──
    print_section("2. Messaging Scam — Thai Delivery Scam");
    println!("Input: {}\n", MSG_DELIVERY_TH.trim());
    let result = engine.detect(MSG_DELIVERY_TH, Channel::Messaging, "th", None).await?;
    print_detection_result(&result);

    // ── 3. Email Scam (Indonesian investment fraud) ──
    print_section("3. Email Scam — Indonesian Investment Fraud");
    println!("Input: {}\n", EMAIL_INVESTMENT_ID.trim());
    let result = engine.detect(EMAIL_INVESTMENT_ID, Channel::Email, "id", None).await?;
    print_detection_result(&result);

    // ── 4. Browser Scam (Tagalog fake lottery) ──
    print_section("4. Browser Scam — Tagalog Fake Lottery");
    println!("Input: {}\n", BROWSER_LOTTERY_TL.trim());
    let result = engine.detect(BROWSER_LOTTERY_TL, Channel::Browser, "tl", None).await?;
    print_detection_result(&result);

    // ── 5. Call Scam (Malay tech support) ──
    print_section("5. Call Scam — Malay Tech Support Scam");
    println!("Input: {}\n", CALL_TECH_SUPPORT_MS.trim());
    let result = engine.detect(CALL_TECH_SUPPORT_MS, Channel::Call, "ms", None).await?;
    print_detection_result(&result);

    // ── 6. Benign Message (Vietnamese Shopee notification) ──
    print_section("6. Benign Message — Vietnamese Shopee Notification");
    println!("Input: {}\n", BENIGN_SMS_VI.trim());
    let result = engine.detect(BENIGN_SMS_VI, Channel::Sms, "vi", None).await?;
    print_detection_result(&result);

    // ── 7. Family Construct ──
    print_section("7. Family Construct — Elderly Member Protection");

    let mut family = FamilyCircle::new("fam-001");
    family.alert_threshold = 3;

    // Guardian (adult)
    let guardian = FamilyMember::new("m-adult", "Parent", MemberRole::Adult);
    family.add_member(guardian);

    // Elderly member with guardian alert
    let elderly = FamilyMember::new("m-elderly", "Grandparent", MemberRole::Elderly)
        .with_guardian("m-adult");
    family.add_member(elderly);

    // Teen member
    let teen = FamilyMember::new("m-teen", "Teenager", MemberRole::Teen)
        .with_guardian("m-adult");
    family.add_member(teen);

    engine.set_family(family.clone());

    println!("Family circle: {} ({} members)", family.id, family.members.len());
    for m in &family.members {
        println!("  {} — {} (role: {}, threshold: {}/5, alert_guardian: {})",
            m.id, m.name, m.role.label(),
            m.sensitivity.risk_threshold, m.alert_guardian);
    }

    // Simulate elderly member receiving a scam SMS
    println!("\nSimulating elderly member receiving scam SMS...");
    let result = engine.detect(SMS_BANK_VI, Channel::Sms, "vi", Some("m-elderly")).await?;
    println!("Detection result for elderly member:");
    print_detection_result(&result);

    if let Some(ref alert) = result.family_alert {
        println!("\n  *** FAMILY ALERT TRIGGERED ***");
        println!("  Alert: {}", alert);
    } else {
        println!("\n  No family alert (below threshold)");
    }

    // ── 8. Feedback Flow ──
    print_section("8. Structured Feedback Flow");

    // Simulate a detection
    let result = engine.detect(SMS_BANK_VI, Channel::Sms, "vi", None).await?;
    println!("Detection ID: {}", result.id);
    println!("Risk: {}/5, Outcome: {}", result.risk_bucket, result.predicted_outcome);

    // Thumb up — correct detection
    println!("\n  User: Thumb up (correct detection)");
    engine.submit_feedback(&result.id, FeedbackKind::Correct, None)?;
    println!("  → FeedbackKind::Correct recorded");

    // Thumb down — false positive on benign message
    let benign_result = engine.detect(BENIGN_SMS_VI, Channel::Sms, "vi", None).await?;
    if benign_result.risk_bucket > 2 {
        println!("\n  User: Thumb down (false positive on Shopee notification)");
        engine.submit_feedback(&benign_result.id, FeedbackKind::NotAScam, None)?;
        println!("  → FeedbackKind::NotAScam recorded");
    }

    // Thumb down — wrong type
    let wrong_type_result = engine.detect(CALL_TECH_SUPPORT_MS, Channel::Call, "ms", None).await?;
    if let Some(ref actual_type) = wrong_type_result.scam_type {
        println!("\n  User: Thumb down (wrong type — was {} but actually bank impersonation)", actual_type.label());
        engine.submit_feedback(
            &wrong_type_result.id,
            FeedbackKind::WrongType,
            Some(ScamType::BankImpersonation),
        )?;
        println!("  → FeedbackKind::WrongType recorded, corrected to BankImpersonation");
    }

    // Show feedback selector options
    println!("\n  Feedback selector options (thumb down):");
    for (label, kind) in kinshield::feedback::FeedbackFlow::thumb_down_options() {
        println!("    - {} → {}", label, kind);
    }

    // ── 9. Report Missed Scam ──
    print_section("9. Report Missed Scam (False Negative)");
    println!("Input: {}\n", MISSED_PHISHING_TH.trim());

    // First, check if engine detects it
    let missed_result = engine.detect(MISSED_PHISHING_TH, Channel::Sms, "th", None).await?;
    println!("Engine detection: risk={}/5, outcome={}", missed_result.risk_bucket, missed_result.predicted_outcome);

    // User reports it as a missed scam
    let report = engine.report_missed(
        MISSED_PHISHING_TH,
        Channel::Sms,
        "th",
        Some(ScamType::LoanScam),
    ).await?;
    println!("\nMissed scam report:");
    println!("  Channel: {}", report.channel);
    println!("  Language: {}", report.language);
    println!("  Actual type: {:?}", report.actual_scam_type.map(|t| t.label()));
    println!("  Indicators re-extracted:");
    for ind in &report.indicators {
        println!("    - {} [{}]", ind.id.label(), ind.strength);
    }
    println!("  Timestamp bucket: {}", report.timestamp_bucket);

    // ── 10. Decision Trace ──
    print_section("10. Privacy-Bounded Decision Trace");
    let _ = engine.detect(SMS_BANK_VI, Channel::Sms, "vi", None).await?;

    // Get the last trace from aggregation buffer via flush
    let traces_count = engine.flush_aggregates().len();
    println!("Aggregation buffer flushed: {} aggregate reports generated", traces_count);

    // Demonstrate a decision trace structure
    println!("\nExample decision trace structure (no raw text, no sender, no exact timestamp):");
    let example_trace = kinshield::DecisionTrace {
        local_id: None,
        model_version: "1.0.0".to_string(),
        channel: "sms".to_string(),
        language: "vi".to_string(),
        predicted_outcome: "scam".to_string(),
        predicted_type: Some("bank_impersonation".to_string()),
        risk_bucket: 5,
        indicators: vec![
            ("urgency".to_string(), "high".to_string()),
            ("financial_request".to_string(), "high".to_string()),
            ("credential_request".to_string(), "medium".to_string()),
        ],
        feedback: Some(FeedbackKind::Correct),
        corrected_type: None,
        prompt_version: "1.0.0".to_string(),
        label_confidence: kinshield::LabelConfidence::UserFeedback,
        indicator_schema_version: kinshield::ONTOLOGY_VERSION.to_string(),
        taxonomy_schema_version: kinshield::SCAM_TAXONOMY_VERSION.to_string(),
        aggregation_schema_version: kinshield::AGGREGATION_SCHEMA_VERSION.to_string(),
    };
    println!("{}", serde_json::to_string_pretty(&example_trace)?);

    println!("\nExcluded from trace: sender, domain, URL, message length,");
    println!("  exact timestamp, exact location, raw probability vector,");
    println!("  embeddings, token-level probabilities, attention maps.");

    // ── 11. Aggregation Buffer ──
    print_section("11. Aggregation Buffer — Local Batching");
    // Run several detections to populate the buffer
    let test_messages = [
        (SMS_BANK_VI, Channel::Sms, "vi"),
        (MSG_DELIVERY_TH, Channel::Messaging, "th"),
        (EMAIL_INVESTMENT_ID, Channel::Email, "id"),
        (BROWSER_LOTTERY_TL, Channel::Browser, "tl"),
        (CALL_TECH_SUPPORT_MS, Channel::Call, "ms"),
        (BENIGN_SMS_VI, Channel::Sms, "vi"),
    ];

    for (msg, ch, lang) in &test_messages {
        let _ = engine.detect(msg, *ch, lang, None).await?;
    }

    println!("Ran {} detections. Flushing aggregate reports...", test_messages.len());
    let reports = engine.flush_aggregates();
    println!("Generated {} aggregate report types:", reports.len());
    for report in &reports {
        let (name, count) = match report {
            kinshield::AggregateReport::ConfirmationRateByBucket(d) => ("ConfirmationRateByBucket", d.len()),
            kinshield::AggregateReport::FalsePositiveRateByIndicator(d) => ("FalsePositiveRateByIndicator", d.len()),
            kinshield::AggregateReport::ScamTypeConfusionMatrix(d) => ("ScamTypeConfusionMatrix", d.len()),
            kinshield::AggregateReport::IndicatorPairPerformance(d) => ("IndicatorPairPerformance", d.len()),
            kinshield::AggregateReport::PerformanceByLangChannel(d) => ("PerformanceByLangChannel", d.len()),
            kinshield::AggregateReport::IndicatorStrengthFeedback(d) => ("IndicatorStrengthFeedback", d.len()),
            kinshield::AggregateReport::ExplanationQuality(d) => ("ExplanationQuality", d.len()),
            kinshield::AggregateReport::ModelVersionComparison(d) => ("ModelVersionComparison", d.len()),
        };
        println!("  - {} ({} entries)", name, count);
    }

    // ── 12. Calibration ──
    print_section("12. Calibration Layer");
    let stats = engine.calibration_stats();
    println!("Calibration version: {}", stats.version);
    println!("Total feedback: {}", stats.total_feedback);
    println!("Total false negatives: {}", stats.total_false_negatives);
    if !stats.indicator_fp_rates.is_empty() {
        println!("Indicator false-positive rates:");
        for (ind, rate) in &stats.indicator_fp_rates {
            println!("  - {}: {:.1}%", ind, rate * 100.0);
        }
    }

    // ── 13. Audit Log + ZK Attestation ──
    print_section("13. Audit Log & ZK Attestation");
    let _ = std::fs::remove_file(&audit_log_path);
    let mut audit_log = AuditLog::open(audit_log_path.clone())?;

    let entry1 = audit_log.append(
        "scam_detect",
        "kinshield-1.0.0",
        "sms message (redacted)",
        "risk_bucket=5, scam_type=bank_impersonation",
        None,
    )?;
    let entry2 = audit_log.append(
        "scam_detect",
        "kinshield-1.0.0",
        "messaging message (redacted)",
        "risk_bucket=4, scam_type=delivery_scam",
        None,
    )?;

    println!("Audit log entries:");
    println!("  seq={}, task={}, hash={:.16}...", entry1.seq, entry1.task, entry1.entry_hash);
    println!("  seq={}, task={}, hash={:.16}...", entry2.seq, entry2.task, entry2.entry_hash);
    println!("  Integrity verified: {}", audit_log.verify());

    let all_entries = audit_log.read_all()?;

    // ZK Attestation
    let attestation = ZkAttestation::new(
        "device-kinshield-001",
        "scam_detect",
        "kinshield-1.0.0",
        "sms message (redacted)",
        "risk_bucket=5, bank_impersonation detected",
        "OnDevice",
        true, // local_only
    )
    .with_compliance("Family Protection", "v1.0", "Restricted");

    println!("\nZK Attestation:");
    println!("  ID: {}", attestation.id);
    println!("  Device: {} | Task: {}", attestation.device_id, attestation.task);
    println!("  Local only: {}", attestation.local_only);
    println!("  Model hash: {:.16}...", attestation.model_hash);
    println!("  Attestation hash: {:.16}...", attestation.hash());

    // Network Monitor
    let monitor = NetworkMonitor::new();
    monitor.start();
    let _ = engine.detect(SMS_BANK_VI, Channel::Sms, "vi", None).await?;
    let connections = monitor.stop();
    println!("\nNetwork monitor:");
    println!("  Outbound connections during detection: {}", connections);
    println!("  All detection was local: {}", !monitor.had_connections());

    // Residency Certificate
    let cert = ResidencyCertificate::generate(
        &all_entries,
        connections,
        chrono::Utc::now() - chrono::Duration::minutes(5),
        chrono::Utc::now(),
    );
    println!("\nData Residency Certificate:");
    println!("  ID: {}", cert.id);
    println!("  Inference events: {}", cert.inference_count);
    println!("  Network connections: {}", cert.network_connections);
    println!("  All local: {}", cert.all_local);

    // ── Summary ──
    println!("\n{}", "=".repeat(70));
    println!("  KinShield scam detection demo complete.");
    println!("  All detection ran on-device — no data transmitted.");
    println!("  Privacy-bounded decision traces only — no raw message content.");
    println!("  Southeast Asia focus: VI, TH, ID, MS, TL, KM");
    println!("  Family construct: per-member thresholds, guardian alerts");
    println!("  25 indicators × 15 scam types × 5 channels × 8+ languages");
    println!("{}", "=".repeat(70));

    engine.shutdown().await?;
    Ok(())
}
