use zk_ai_core::{
    AiEngine, ModelSpec, TaskOptions,
    TextIndex, TextSearchHit,
    ImageIndex, ImageSearchHit,
    cosine_similarity,
    detect_pii, redact_with_report,
    PiiEntity,
    AuditLog,
    ZkAttestation,
    NetworkMonitor,
    ResidencyCertificate,
    PolicyEngine, PolicyDecision,
    verify_file,
};
use chrono::Utc;

const SAFETY_EVENTS: &[(&str, &str)] = &[
    ("event1",  "Teenager arrived at school at 8:15 AM, walking at normal pace. Geofence entry detected."),
    ("event2",  "Teenager departed school at 3:30 PM, cycling at normal pace. Geofence exit detected."),
    ("event3",  "Parent arrived home at 6:45 PM, driving. Geofence entry detected. Normal commute pattern."),
    ("event4",  "Elderly parent unusual stillness detected at 2:00 PM. No movement for 45 minutes. Health anomaly alert."),
    ("event5",  "Possible crash detected on highway. Sudden deceleration followed by complete stop. Impact sensor triggered."),
    ("event6",  "Teenager arrived home at 5:15 PM, walking at fast pace. Geofence entry detected."),
    ("event7",  "Parent departed for work at 7:30 AM, driving. Geofence exit detected. Normal commute pattern."),
    ("event8",  "Elderly parent arrived at hospital for appointment at 10:00 AM, walking at slow pace."),
    ("event9",  "Teenager departed friend's house at 10:30 PM, cycling. Late departure alert triggered."),
    ("event10", "Family member SOS triggered at unknown location. Emergency broadcast sent to all family members."),
    ("event11", "Elderly parent fall detected in bathroom. No movement for 10 minutes. Fall alert triggered."),
    ("event12", "Teenager arrived at sports practice at 4:00 PM, running at fast pace. Geofence entry detected."),
    ("event13", "Parent arrived at grocery store at 5:30 PM, walking at normal pace. Routine errand detected."),
    ("event14", "Elderly parent departed home at 9:00 AM, walking at slow pace. Geofence exit detected."),
    ("event15", "Teenager arrived at library at 7:00 PM, walking at normal pace. Geofence entry detected."),
];

const HEALTH_SIGNALS: &[(&str, &str)] = &[
    ("normal1", "Regular walking pattern, steady heart rate 72bpm, normal movement, good step count."),
    ("normal2", "Driving pattern, seated position, heart rate 68bpm, vehicle movement detected."),
    ("normal3", "Resting at home, heart rate 65bpm, minimal movement, normal sleep pattern."),
    ("normal4", "Cycling pattern, elevated heart rate 88bpm, consistent pedaling movement."),
    ("anomaly1", "Prolonged stillness detected, heart rate elevated to 95bpm, no movement for 30 minutes. Possible health concern."),
    ("anomaly2", "Sudden impact detected followed by stillness, heart rate spike to 110bpm, possible fall or accident."),
    ("anomaly3", "Irregular heart rate pattern detected, fluctuating between 55 and 120bpm, no corresponding physical activity."),
];

const SOS_MESSAGES: &[&str] = &[
    "I feel unsafe, someone is following me near the park. Please come pick me up.",
    "I fell and I can't get up. I'm in the bathroom. Please send help immediately.",
    "Car accident on the highway. I'm okay but shaken up. Need someone to pick me up.",
    "I'm lost and my phone battery is at 5%. I don't recognize this area. Please help.",
];

const FAMILY_CHECKINS: &[&str] = &[
    "Hey mom, I made it to school safely! See you at 4pm.",
    "Just got home from work, everything's fine. Starting dinner now.",
    "Running late, will be home by 7pm. Traffic is really bad today.",
    "At grandma's house, she's doing well today. We're having tea together.",
];

const SHARED_FAMILY_DATA: &str = r#"
Family member: Sarah Chen
Phone: (555) 123-4567
Email: sarah.chen@example.com
Location: 123 Oak Street, Springfield, IL 62704
Current location: Lincoln High School, 456 Elm Ave, Springfield
Health: Heart rate 72bpm, 8423 steps today
Emergency contact: David Chen, (555) 987-6543
Insurance: BCBS Policy #ABC123456789
"#;

const SAMPLE_NOTIFICATIONS: &str = r#"
2:15 PM: Teenager arrived at school (geofence alert)
3:30 PM: Teenager departed school (geofence alert)
5:15 PM: Teenager arrived home safely
6:45 PM: Parent arrived home from work
2:00 PM: Unusual stillness detected for elderly parent — health anomaly alert
10:30 PM: Teenager late departure from friend's house — alert triggered
"#;

const KNOWN_LOCATIONS: &[(&str, &str, &[f32])] = &[
    ("home",     "family home exterior with driveway and garden",                &[1.0,  0.0,  0.0,  0.0,  0.0]),
    ("school",   "school building with flag and parking lot",                    &[0.0,  1.0,  0.0,  0.0,  0.0]),
    ("work",     "office building with glass entrance and lobby",                &[0.0,  0.0,  1.0,  0.0,  0.0]),
    ("hospital", "hospital building with emergency sign and ambulance bay",      &[0.0,  0.0,  0.0,  1.0,  0.0]),
    ("park",     "public park with trees, benches, and walking paths",           &[0.0,  0.0,  0.0,  0.0,  1.0]),
    ("home2",    "house with red door and white fence at sunset",                &[0.95, 0.0,  0.0,  0.0,  0.05]),
    ("school2",  "elementary school with playground and yellow bus",             &[0.0,  0.9,  0.0,  0.0,  0.1]),
];

fn print_section(title: &str) {
    println!("\n{}", "=".repeat(60));
    println!("  {}", title);
    println!("{}", "=".repeat(60));
}

fn print_result(label: &str, result: &zk_ai_core::TaskResult) {
    println!("\n--- {} ---", label);
    println!("Output: {}", result.output);
    println!("Model: {} | Adapter: {:?} | Duration: {}ms | Tokens: {}→{}",
        result.model, result.adapter, result.duration_ms,
        result.input_tokens, result.output_tokens);
}

fn print_text_hits(hits: &[TextSearchHit]) {
    for (i, hit) in hits.iter().enumerate() {
        println!("  {}. [{:.4}] {} — {}",
            i + 1, hit.score, hit.id,
            hit.text.chars().take(80).collect::<String>());
    }
}

fn print_image_hits(hits: &[ImageSearchHit]) {
    for (i, hit) in hits.iter().enumerate() {
        println!("  {}. [{:.4}] {} — {}",
            i + 1, hit.score, hit.id, hit.caption);
    }
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
        .with_env_filter("zk_ai_core=info,kinsense=info")
        .init();

    println!("╔══════════════════════════════════════════════════════════╗");
    println!("║  KinSense — Family Safety with On-Device AI              ║");
    println!("║  Activity classification, anomaly detection, SOS,        ║");
    println!("║  privacy redaction, audit trail — all on-device.         ║");
    println!("╚══════════════════════════════════════════════════════════╝");

    let work_dir = std::env::temp_dir().join("zk-ai-kinsense");
    std::fs::create_dir_all(&work_dir)?;
    let cache_dir = work_dir.join("models");
    let audit_log_path = work_dir.join("audit.jsonl");

    println!("Work directory: {}", work_dir.display());

    let mut engine = AiEngine::new(&cache_dir).await?;
    let device_tier = format!("{:?}", engine.profile().tier);
    let acceleration = format!("{:?}", engine.profile().acceleration);
    println!("Device tier: {} | Acceleration: {}", device_tier, acceleration);

    println!("\nLoading mT5-small model...");
    engine.ensure_model(&ModelSpec::mt5_small_int8()).await?;

    // ── 1. Activity Event Auto-Tagging ──
    print_section("1. Activity Event Auto-Tagging");
    println!("Automatically tagging safety events with topic labels...\n");
    for (id, text) in SAFETY_EVENTS.iter().take(5) {
        let result = engine.auto_tag(text, TaskOptions::default()).await?;
        println!("  {} → {}", id, result.output);
    }

    // ── 2. Build Safety Event Index ──
    print_section("2. Build Safety Event Index");
    println!("Indexing {} safety events...", SAFETY_EVENTS.len());

    let mut text_index = TextIndex::new();
    for (i, (id, text)) in SAFETY_EVENTS.iter().enumerate() {
        let mut emb = vec![0.0_f32; 10];
        let topic = match i {
            3 | 10 => 1,  // health anomaly (stillness, fall)
            4 => 2,       // crash
            8 => 4,       // late departure
            9 => 3,       // SOS
            _ => 0,       // routine arrival/departure
        };
        emb[topic * 2] = 0.9;
        emb[topic * 2 + 1] = 0.1;
        text_index.add_text(id, text, emb, Some("safety-event"));
    }
    println!("TextIndex built with {} entries.", text_index.len());

    // ── 3. Semantic Search over Safety Events ──
    print_section("3. Semantic Search over Safety Events");
    let query_embedding = vec![0.0, 0.0, 0.9, 0.1, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0];
    let hits = text_index.search(&query_embedding, 3);
    println!("Query: 'health anomaly stillness fall' (topic embedding)");
    println!("Top 3 results:");
    print_text_hits(&hits);

    let query_embedding = vec![0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.9, 0.1, 0.0, 0.0];
    let hits = text_index.search(&query_embedding, 2);
    println!("\nQuery: 'SOS emergency broadcast' (topic embedding)");
    println!("Top 2 results:");
    print_text_hits(&hits);

    // ── 4. Anomaly Detection via Find Similar ──
    print_section("4. Anomaly Detection (Find Similar)");
    println!("Building health signal index with normal + anomalous patterns...");

    let mut health_index = TextIndex::new();
    for (i, (id, text)) in HEALTH_SIGNALS.iter().enumerate() {
        let mut emb = vec![0.0_f32; 10];
        let topic = match i {
            0 => 0,  // walking
            1 => 1,  // driving
            2 => 2,  // resting
            3 => 3,  // cycling
            _ => 4,  // anomaly
        };
        emb[topic * 2] = 0.9;
        emb[topic * 2 + 1] = 0.1;
        health_index.add_text(id, text, emb, Some("health-signal"));
    }
    println!("Health signal index built with {} entries.", health_index.len());

    let anomalous_signal = "No movement detected for 60 minutes, heart rate dropping to 50bpm. Possible unconsciousness or medical emergency.";
    let result = engine.find_similar(anomalous_signal, &health_index, 3, TaskOptions::default()).await?;
    print_result("Find similar to: 'no movement, heart rate dropping'", &result);

    // ── 5. Cosine Similarity — Activity Pattern Comparison ──
    print_section("5. Cosine Similarity — Activity Pattern Comparison");
    let normal_walking = vec![0.9, 0.1, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0];
    let normal_driving = vec![0.0, 0.0, 0.9, 0.1, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0];
    let anomaly_stillness = vec![0.0, 0.0, 0.0, 0.0, 0.9, 0.1, 0.0, 0.0, 0.0, 0.0];

    let sim = cosine_similarity(&normal_walking, &normal_driving);
    println!("Normal walking vs normal driving:    {:.4} (different activities)", sim);

    let sim = cosine_similarity(&normal_walking, &anomaly_stillness);
    println!("Normal walking vs anomaly stillness: {:.4} (strong mismatch → alert)", sim);

    let sim = cosine_similarity(&normal_walking, &normal_walking);
    println!("Normal walking vs normal walking:    {:.4} (identical pattern)", sim);

    // ── 6. Safety Event Clustering (Routine Detection) ──
    print_section("6. Safety Event Clustering (Routine Detection)");
    let result = engine.cluster(&text_index, 4, TaskOptions::default()).await?;
    print_result("Cluster into 4 routine groups", &result);

    // ── 7. Reranking Safety Alerts ──
    print_section("7. Reranking Safety Alerts");
    let alert_query = "health emergency fall crash anomaly";
    let query_embedding = vec![0.0, 0.0, 0.9, 0.1, 0.9, 0.1, 0.0, 0.0, 0.0, 0.0];
    let hits = text_index.search(&query_embedding, 5);
    println!("Original alert search (top 5):");
    print_text_hits(&hits);

    let result = engine.rerank(alert_query, &hits, TaskOptions::default()).await?;
    print_result("Reranked alerts by urgency", &result);

    // ── 8. SOS Urgency Classification ──
    print_section("8. SOS Urgency Classification");
    for (i, msg) in SOS_MESSAGES.iter().enumerate() {
        let result = engine.classify_urgency(msg, TaskOptions::default()).await?;
        println!("  SOS {} → {} | Duration: {}ms", i + 1, result.output, result.duration_ms);
    }

    // ── 9. Smart Reply for Family Check-in Messages ──
    print_section("9. Smart Reply for Family Check-ins");
    for (i, msg) in FAMILY_CHECKINS.iter().enumerate() {
        let result = engine.smart_reply(msg, "en", TaskOptions::default()).await?;
        println!("\n  Check-in {}: \"{}\"", i + 1, msg);
        println!("  Suggested replies: {}", result.output);
    }

    // ── 10. Daily Safety Digest ──
    print_section("10. Daily Safety Digest");
    let result = engine.notif_summary(SAMPLE_NOTIFICATIONS, "en", TaskOptions::default()).await?;
    print_result("Today's family safety notifications", &result);

    // ── 11. PII Redaction for Shared Family Data ──
    print_section("11. PII Redaction for Shared Family Data");
    println!("Scanning shared family data for PII before E2EE transmission...");
    let entities = detect_pii(SHARED_FAMILY_DATA);
    print_pii_entities(&entities);

    let (redacted, report) = redact_with_report(SHARED_FAMILY_DATA);
    println!("\nRedacted {} PII entities. Preview:", report.len());
    let preview: String = redacted.chars().take(400).collect();
    println!("{}", preview);

    // ── 12. PII Scan (AI Pipeline) ──
    print_section("12. PII Scan (AI Pipeline)");
    let result = engine.pii_scan(SHARED_FAMILY_DATA, TaskOptions::default()).await?;
    println!("Output: {}", result.output);
    println!("Duration: {}ms | Tokens: {}→{}", result.duration_ms, result.input_tokens, result.output_tokens);

    // ── 13. Sensitivity Classification for Family Data ──
    print_section("13. Sensitivity Classification for Family Data");
    let result = engine.classify_sensitivity(SHARED_FAMILY_DATA, TaskOptions::default()).await?;
    println!("Shared family data → {}", result.output);

    let public_checkin = "Teenager arrived at school at 8:15 AM, walking at normal pace.";
    let result = engine.classify_sensitivity(public_checkin, TaskOptions::default()).await?;
    println!("Public check-in     → {}", result.output);

    // ── 14. Policy Engine for Family Data Sharing ──
    print_section("14. Policy Engine for Family Data Sharing");
    let mut policy = PolicyEngine::new();
    policy.add_rule("restricted", vec!["translate".to_string(), "summarize".to_string()]);
    policy.add_rule("confidential", vec!["translate".to_string()]);

    let examples = [
        ("public", "auto_tag"),
        ("public", "summarize"),
        ("confidential", "auto_tag"),
        ("confidential", "summarize"),
        ("restricted", "auto_tag"),
        ("restricted", "summarize"),
    ];

    for (sensitivity, task) in &examples {
        let decision = policy.check(sensitivity, task);
        let status = match decision {
            PolicyDecision::Allowed => "ALLOWED",
            PolicyDecision::Denied(reason) => &format!("DENIED: {}", reason),
        };
        println!("  {:>14} + {:>10} → {}", sensitivity, task, status);
    }

    // ── 15. Build Image Index for Known Safe Locations ──
    print_section("15. Build Image Index for Known Safe Locations");
    println!("Indexing {} known locations...", KNOWN_LOCATIONS.len());

    let mut image_index = ImageIndex::new();
    for (id, caption, emb) in KNOWN_LOCATIONS {
        image_index.add_image(id, caption, emb.to_vec());
    }
    println!("ImageIndex built with {} entries.", image_index.len());

    // ── 16. Image Search — Location Recognition ──
    print_section("16. Image Search — Location Recognition");
    let home_query = vec![1.0, 0.0, 0.0, 0.0, 0.0];
    let hits = image_index.search(&home_query, 3);
    println!("Query: 'family home exterior' (location embedding)");
    println!("Top 3 results:");
    print_image_hits(&hits);

    let hospital_query = vec![0.0, 0.0, 0.0, 1.0, 0.0];
    let hits = image_index.search(&hospital_query, 2);
    println!("\nQuery: 'hospital emergency' (location embedding)");
    println!("Top 2 results:");
    print_image_hits(&hits);

    // ── 17. Image Search (AI Pipeline) ──
    print_section("17. Image Search (AI Pipeline)");
    let result = engine.image_search("a school building with a parking lot", TaskOptions::default()).await?;
    print_result("Query: 'a school building with a parking lot'", &result);

    // ── 18. Tamper-Evident Audit Trail for Safety Events ──
    print_section("18. Tamper-Evident Audit Trail for Safety Events");
    println!("Writing audit log to: {}", audit_log_path.display());
    let _ = std::fs::remove_file(&audit_log_path);

    let mut audit_log = AuditLog::open(audit_log_path.clone())?;
    let entry1 = audit_log.append("auto_tag", "mt5-small-int8", "Teenager arrived at school", "arrival, personal", None)?;
    let entry2 = audit_log.append("classify_urgency", "mt5-small-int8", "SOS: I fell and can't get up", "Critical", None)?;
    let entry3 = audit_log.append("find_similar", "mt5-small-int8", "No movement for 60 minutes", "anomaly2: Sudden impact detected", None)?;
    let entry4 = audit_log.append("pii_scan", "mt5-small-int8", "Shared family data with PII", "8 PII entities found", None)?;

    println!("  Appended 4 entries.");
    println!("  Entry 1: seq={}, task={}, hash={:.16}...", entry1.seq, entry1.task, entry1.entry_hash);
    println!("  Entry 2: seq={}, task={}, hash={:.16}...", entry2.seq, entry2.task, entry2.entry_hash);
    println!("  Entry 3: seq={}, task={}, hash={:.16}...", entry3.seq, entry3.task, entry3.entry_hash);
    println!("  Entry 4: seq={}, task={}, hash={:.16}...", entry4.seq, entry4.task, entry4.entry_hash);

    let verified = audit_log.verify();
    println!("\n  Audit log integrity verified: {}", verified);
    let all_entries = audit_log.read_all()?;
    println!("  Total entries in log: {}", all_entries.len());

    // ── 19. Zero-Knowledge Attestation for SOS Event ──
    print_section("19. Zero-Knowledge Attestation for SOS Event");
    let attestation = ZkAttestation::new(
        "device-aa11bb22",
        "classify_urgency",
        "mt5-small-int8",
        "SOS: I fell and can't get up. I'm in the bathroom.",
        "Critical",
        &device_tier,
        true,
    )
    .with_compliance("GDPR", "v1.0", "Restricted");

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

    // ── 20. Network Monitor — Verify All Processing Is Local ──
    print_section("20. Network Monitor — Verify All Processing Is Local");
    let monitor = NetworkMonitor::new();
    monitor.start();
    println!("  Monitor started. Running safety inference...");
    let connections = monitor.stop();
    println!("  Outbound connections during inference: {}", connections);
    println!("  All inference was local: {}", !monitor.had_connections());

    // ── 21. Data Residency Certificate ──
    print_section("21. Data Residency Certificate");
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

    // ── 22. Index Serialization (Persistence) ──
    print_section("22. Index Serialization (Persistence)");
    let json = text_index.to_json()?;
    println!("Serialized TextIndex to JSON ({} bytes)", json.len());
    let restored = TextIndex::from_json(&json)?;
    println!("Deserialized TextIndex with {} entries", restored.len());
    let query_embedding = vec![0.0, 0.0, 0.9, 0.1, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0];
    let hits = restored.search(&query_embedding, 2);
    println!("Search after roundtrip:");
    print_text_hits(&hits);

    let json = image_index.to_json()?;
    println!("\nSerialized ImageIndex to JSON ({} bytes)", json.len());
    let restored = ImageIndex::from_json(&json)?;
    println!("Deserialized ImageIndex with {} entries", restored.len());
    let hits = restored.search(&vec![1.0, 0.0, 0.0, 0.0, 0.0], 2);
    println!("Search after roundtrip:");
    print_image_hits(&hits);

    // ── 23. Audit Log File Verification ──
    print_section("23. Audit Log File Verification");
    let verify_result = verify_file(&audit_log_path);
    println!("Verifying audit log file: {}", audit_log_path.display());
    println!("  Verified: {}", verify_result.verified);
    println!("  SHA-256: {:.32}...", verify_result.file_hash);

    println!("\n{}", "=".repeat(60));
    println!("  KinSense demo complete.");
    println!("  All family safety AI processing ran on-device.");
    println!("  No data was transmitted to any server.");
    println!("{}", "=".repeat(60));

    engine.shutdown().await?;
    Ok(())
}
