use zk_ai_core::{AiEngine, ModelSpec, TaskOptions};

const SAMPLE_CONTRACT: &str = r#"
SERVICE AGREEMENT

This Service Agreement ("Agreement") is entered into as of January 15, 2024,
by and between TechCorp Inc. ("Client") and DataFlow Systems LLC ("Provider").

1. SERVICES
Provider shall deliver cloud infrastructure management services including
monitoring, auto-scaling, and incident response (the "Services").

2. TERM
This Agreement shall commence on February 1, 2024 and continue for 24 months
unless terminated earlier per Section 7.

3. PAYMENT
Client shall pay $12,000/month. Invoices are due within 30 days.
Late payments incur 1.5% monthly interest.

4. CONFIDENTIALITY
Both parties agree to protect proprietary information. Breach of this
section shall result in immediate termination.

5. LIABILITY
Provider's total liability shall not exceed 3 months of fees paid.
Provider is not liable for indirect or consequential damages.

6. DATA PROCESSING
All data is processed in accordance with the DPA signed separately.
Client retains all ownership of processed data.

7. TERMINATION
Either party may terminate with 60 days written notice. Client may
terminate immediately for material breach. Upon termination, Provider
shall return or destroy all Client data within 15 days.

8. GOVERNING LAW
This Agreement is governed by the laws of the State of California.
Disputes shall be resolved through binding arbitration in San Francisco.
"#;

const SAMPLE_CONTRACT_V2: &str = r#"
SERVICE AGREEMENT (v2)

This Service Agreement ("Agreement") is entered into as of January 15, 2024,
by and between TechCorp Inc. ("Client") and DataFlow Systems LLC ("Provider").

1. SERVICES
Provider shall deliver cloud infrastructure management services including
monitoring, auto-scaling, incident response, and security auditing (the "Services").

2. TERM
This Agreement shall commence on February 1, 2024 and continue for 36 months
unless terminated earlier per Section 7.

3. PAYMENT
Client shall pay $14,500/month. Invoices are due within 15 days.
Late payments incur 2% monthly interest.

4. CONFIDENTIALITY
Both parties agree to protect proprietary information under SOC 2 Type II
standards. Breach shall result in immediate termination and penalties.

5. LIABILITY
Provider's total liability shall not exceed 6 months of fees paid.
Provider is not liable for indirect or consequential damages unless
caused by gross negligence.

7. TERMINATION
Either party may terminate with 30 days written notice. Client may
terminate immediately for material breach. Upon termination, Provider
shall return or destroy all Client data within 7 days.

8. GOVERNING LAW
This Agreement is governed by the laws of the State of California.
Disputes shall be resolved through binding arbitration in San Francisco.
"#;

const SAMPLE_TICKET: &str = r#"
Ticket #4823: Production database connection pool exhausted

Reported by: ops-monitoring@techcorp.com
Priority: P1
Created: 2024-07-15 09:23 UTC

Description:
The production database connection pool for the user-service has been
exhausted since 09:15 UTC. All new connections are being rejected with
"pool exhausted" errors. The service is returning 503s to ~30% of
requests. This is affecting the EU region primarily.

Customer impact: Login and registration flows are degraded.
Estimated affected users: ~50,000

Previous similar incident: #4102 (2024-05-20) — resolved by increasing
pool size from 50 to 100. Root cause was a connection leak in the
session cleanup code.

Current pool config: max=100, min=10, timeout=30s

Actions taken so far:
- Restarted user-service pods (temporary relief, issue recurs after ~15 min)
- Checked for long-running queries — none found
- Reviewed connection leak detection logs — no leaks detected
"#;

const SAMPLE_MEETING: &str = r#"
Meeting: Architecture Review Board — 2024-07-15

Attendees: Alice (CTO), Bob (Principal Eng), Carol (Security Lead), Dave (Platform Lead)

Alice: Let's review the proposal to migrate from RabbitMQ to Kafka.
Bob: The main driver is throughput. We're hitting RabbitMQ's limits at 50k msg/s. Kafka can handle 500k+.
Carol: Security concern — Kafka doesn't have built-in TLS in the open-source version. We'd need Confluent or self-managed TLS.
Dave: Operationally, Kafka adds complexity. We'd need ZooKeeper or KRaft, monitoring, and on-call rotation updates.
Alice: Cost?
Bob: Open-source Kafka on our existing K8s cluster is ~$0 additional infra cost. Confluent Cloud would be ~$8k/month.
Dave: We also need to factor in migration effort — 3 sprints to rewrite consumers.
Alice: Decision: we'll go with self-managed Kafka on K8s with TLS enabled. Bob to create a migration plan by next week. Carol to define the TLS hardening checklist. Dave to draft the ops runbook.
Bob: I'll also spike KRaft mode to avoid ZooKeeper dependency.
Alice: Approved. Let's review the migration plan in next week's ARB.
"#;

const SAMPLE_COLLAB_ANNOTATIONS: &str = r#"
Alice: The API needs pagination — current design returns all results which won't scale.
Bob: Agreed. Cursor-based pagination is better than offset for large datasets.
Carol: We should also add rate limiting. 100 req/min per API key?
Alice: Good call. Let's standardize on cursor pagination + rate limiting.
Dave: Don't forget to document the error response format for 429s.
Bob: I'll use RFC 7807 problem details for error responses.
Alice: Consensus: cursor pagination, 100 req/min rate limit, RFC 7807 errors.
"#;

const SAMPLE_ACTION_ITEMS: &str = r#"
- [overdue] Bob: Evaluate alternative auth providers by July 5
- [in-progress] Carol: Set up design review checkpoint by July 12
- [done] Dave: Document staging environment recovery procedure
- [overdue] Alice: Schedule stakeholder alignment meeting by July 8
- [pending] Jenny: Update roadmap doc and send by EOD
"#;

const SAMPLE_EMAIL_INTERNAL: &str = r#"
From: hr@techcorp.com
To: all-staff@techcorp.com
Subject: Updated Remote Work Policy

Dear team, please review the updated remote work policy attached.
Key changes: 3 days in-office minimum, flexible core hours 10am-3pm.
Feedback welcome through July 30.
"#;

const SAMPLE_EMAIL_CLIENT: &str = r#"
From: john.smith@acmecorp.com
To: sales@techcorp.com
Subject: Quote Request — Enterprise Plan

Hi, we're evaluating your platform for 500 users. Can you provide
a quote with annual billing? We need SSO, audit logs, and a DPA.
Our procurement deadline is August 15.
"#;

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

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter("zk_ai_core=info,kchat_b2b=info")
        .init();

    println!("╔══════════════════════════════════════════════════════════╗");
    println!("║  KChat B2B — Enterprise Chat with On-Device AI          ║");
    println!("║  All inference runs locally. No data leaves device.     ║");
    println!("╚══════════════════════════════════════════════════════════╝");

    let cache_dir = std::env::temp_dir().join("zk-ai-kchat-b2b-models");
    println!("\nCache directory: {}", cache_dir.display());

    let mut engine = AiEngine::new(&cache_dir).await?;

    let profile = engine.profile();
    println!("Device tier: {:?} | Acceleration: {:?} | CPU cores: {} | Memory: {}MB",
        profile.tier, profile.acceleration, profile.cpu_cores, profile.available_memory_mb);

    println!("\nLoading mT5-small model...");
    engine.ensure_model(&ModelSpec::mt5_small_int8()).await?;

    print_section("1. Contract Analysis");
    let result = engine.contract_analysis(SAMPLE_CONTRACT, "en", TaskOptions::default()).await?;
    print_result("Parties, obligations, risks, termination", &result);

    print_section("2. Compare Documents (v1 vs v2)");
    let result = engine.compare_docs(SAMPLE_CONTRACT, SAMPLE_CONTRACT_V2, "en", TaskOptions::default()).await?;
    print_result("Differences between contract versions", &result);

    print_section("3. Find Clause — 'termination notice period'");
    let result = engine.find_clause(SAMPLE_CONTRACT, "termination notice period", TaskOptions::default()).await?;
    print_result("Relevant clause", &result);

    print_section("4. Extract Dates & Deadlines");
    let result = engine.extract_dates(SAMPLE_CONTRACT, TaskOptions::default()).await?;
    print_result("Dates from contract", &result);

    print_section("5. Ticket Summary");
    let result = engine.ticket_summary(SAMPLE_TICKET, "en", TaskOptions::default()).await?;
    print_result("Support ticket summary", &result);

    print_section("6. Classify Urgency");
    let result = engine.classify_urgency(SAMPLE_TICKET, TaskOptions::default()).await?;
    print_result("Urgency classification", &result);

    print_section("7. Ticket Reply");
    let result = engine.ticket_reply(SAMPLE_TICKET, "en", TaskOptions::default()).await?;
    print_result("Drafted reply to support ticket", &result);

    print_section("8. Email Categorization");
    let result = engine.email_categorize(SAMPLE_EMAIL_INTERNAL, TaskOptions::default()).await?;
    print_result("Internal HR email", &result);

    let result = engine.email_categorize(SAMPLE_EMAIL_CLIENT, TaskOptions::default()).await?;
    print_result("Client quote request email", &result);

    print_section("9. Sentiment Analysis");
    let result = engine.sentiment("The new deployment pipeline is working great — we shipped 3 releases this week with zero rollback!", TaskOptions::default()).await?;
    print_result("Positive feedback", &result);

    let result = engine.sentiment("The API keeps timing out during peak hours. This is unacceptable for production.", TaskOptions::default()).await?;
    print_result("Negative feedback", &result);

    print_section("10. Meeting Minutes");
    let result = engine.meeting_minutes(SAMPLE_MEETING, "en", TaskOptions::default()).await?;
    print_result("Formal meeting minutes", &result);

    print_section("11. Extract Decisions");
    let result = engine.extract_decisions(SAMPLE_MEETING, "en", TaskOptions::default()).await?;
    print_result("Decisions from meeting", &result);

    print_section("12. Follow-Up Reminders");
    let result = engine.follow_up(SAMPLE_ACTION_ITEMS, "en", TaskOptions::default()).await?;
    print_result("Overdue action item reminders", &result);

    print_section("13. Collaboration Summary");
    let result = engine.collab_summary(SAMPLE_COLLAB_ANNOTATIONS, "en", TaskOptions::default()).await?;
    print_result("Team annotations → unified summary", &result);

    print_section("14. Auto Abstract");
    let result = engine.auto_abstract(SAMPLE_CONTRACT, "en", TaskOptions::default()).await?;
    print_result("2-sentence document abstract", &result);

    println!("\n{}", "=".repeat(60));
    println!("  KChat B2B demo complete. All AI ran on-device.");
    println!("{}", "=".repeat(60));

    engine.shutdown().await?;
    Ok(())
}
