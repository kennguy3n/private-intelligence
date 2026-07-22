use zk_ai_core::{AiEngine, ModelSpec, TaskOptions};
use zk_ai_core::pipeline::daily_digest::DailyDigestInput;

const SAMPLE_EMAIL_THREAD: &str = r#"
From: alice@example.com
To: bob@example.com
Subject: Q3 Planning — Budget Approval Needed

Hi Bob,

I've attached the Q3 budget proposal. We need your sign-off by Friday
so we can start the hiring process. The key areas are:
1. Two new engineering hires (backend + ML)
2. Infrastructure migration to Kubernetes
3. Customer research study ($15k)

Let me know if you have questions.

From: bob@example.com
To: alice@example.com
Subject: Re: Q3 Planning — Budget Approval Needed

Thanks Alice. The proposal looks solid. I have a few concerns:
- The ML hire might overlap with the platform team's roadmap
- Can we phase the K8s migration over two quarters?
- The research study seems underfunded — recommend $25k

Can we discuss Thursday?

From: alice@example.com
To: bob@example.com
Subject: Re: Q3 Planning — Budget Approval Needed

Good points. Let's discuss Thursday at 2pm. I'll adjust the research
budget and add a note about phasing the migration.
"#;

const SAMPLE_CHAT: &str = r#"
[10:02] Sarah: did everyone see the product roadmap?
[10:03] Mike: yes, looks ambitious. can we really ship 3 features by Q3?
[10:05] Jenny: the ML feature is the risky one. we need more data
[10:07] Sarah: agreed. let's descope the recommendation engine to v2
[10:08] Mike: +1. focus on the dashboard and export features first
[10:10] Jenny: I'll update the roadmap doc and send it out by EOD
[10:11] Sarah: thanks Jenny. let's review in next standup
"#;

const SAMPLE_MEETING: &str = r#"
Meeting: Sprint Retrospective — 2024-07-15

Attendees: Alice (PM), Bob (Eng Lead), Carol (Designer), Dave (QA)

Alice: Welcome to the sprint retro. Let's start with what went well.
Bob: The API refactor was completed on time. We reduced p99 latency by 40%.
Carol: The new design system components were well received by stakeholders.
Dave: Test coverage went up to 85%. We caught two critical bugs before release.

Alice: What didn't go well?
Bob: The third-party auth integration took longer than expected. API docs were outdated.
Carol: We had some back-and-forth on the color palette that could have been avoided with earlier stakeholder alignment.
Dave: The staging environment was down for 3 hours on Tuesday, blocking QA.

Alice: Action items?
Bob: I'll create a ticket to evaluate alternative auth providers by next Friday.
Carol: I'll set up a design review checkpoint earlier in the process.
Dave: I'll document the staging environment recovery procedure.
Alice: I'll schedule a stakeholder alignment meeting for the next sprint planning.
"#;

const SAMPLE_NOTIFICATIONS: &str = r#"
- 3 new emails from your manager regarding Q3 planning
- Build #4521 failed on the main branch (timeout in integration tests)
- Sarah mentioned you in the #product-roadmap channel
- Your PR #234 was approved by Mike
- Calendar reminder: 1:1 with Bob at 3pm today
- 2 new comments on your design document
- System: disk space is at 85% capacity
"#;

const SAMPLE_MESSAGE: &str = "Hey, can we push the deadline for the API migration to next week? The team is overloaded with the Q3 planning and I don't want to rush it.";

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
        .with_env_filter("zk_ai_core=info,kchat_b2c=info")
        .init();

    println!("╔══════════════════════════════════════════════════════════╗");
    println!("║  KChat B2C — Consumer Chat with On-Device AI            ║");
    println!("║  All inference runs locally. No network calls.          ║");
    println!("╚══════════════════════════════════════════════════════════╝");

    let cache_dir = std::env::temp_dir().join("zk-ai-kchat-b2c-models");
    println!("\nCache directory: {}", cache_dir.display());

    let mut engine = AiEngine::new(&cache_dir).await?;

    let profile = engine.profile();
    println!("Device tier: {:?} | Acceleration: {:?} | CPU cores: {} | Memory: {}MB",
        profile.tier, profile.acceleration, profile.cpu_cores, profile.available_memory_mb);

    println!("\nLoading mT5-small model...");
    engine.ensure_model(&ModelSpec::mt5_small_int8()).await?;

    print_section("1. Email Summary");
    let result = engine.email_summary(SAMPLE_EMAIL_THREAD, "en", TaskOptions::default()).await?;
    print_result("Email thread → 3 bullet points", &result);

    print_section("2. Smart Reply");
    let result = engine.smart_reply(SAMPLE_MESSAGE, "en", TaskOptions::default()).await?;
    print_result("Message → 3 reply options", &result);

    print_section("3. Classify Tone");
    let result = engine.classify_tone("URGENT: production is down, all users affected!", TaskOptions::default()).await?;
    print_result("Tone classification", &result);

    let result = engine.classify_tone("FYI: I updated the wiki page with the new process.", TaskOptions::default()).await?;
    print_result("Tone classification", &result);

    print_section("4. Chat Summary");
    let result = engine.chat_summary(SAMPLE_CHAT, "en", TaskOptions::default()).await?;
    print_result("Group chat → key bullets", &result);

    print_section("5. Notification Digest");
    let result = engine.notif_summary(SAMPLE_NOTIFICATIONS, "en", TaskOptions::default()).await?;
    print_result("Notifications → 2-3 sentence digest", &result);

    print_section("6. Meeting Summary");
    let result = engine.meeting_summary(SAMPLE_MEETING, "en", TaskOptions::default()).await?;
    print_result("Meeting transcript → summary", &result);

    print_section("7. Action Items");
    let result = engine.action_items(SAMPLE_MEETING, "en", TaskOptions::default()).await?;
    print_result("Meeting transcript → action items", &result);

    print_section("8. Pre-Send Check");
    let result = engine.pre_send_check(
        "hey team just wanted to let u know the deploy went fine lol",
        "en",
        TaskOptions::default(),
    ).await?;
    print_result("Pre-send grammar + tone check", &result);

    print_section("9. Daily Digest");
    let digest_input = DailyDigestInput {
        emails: SAMPLE_EMAIL_THREAD.to_string(),
        meetings: SAMPLE_MEETING.to_string(),
        notifications: SAMPLE_NOTIFICATIONS.to_string(),
    };
    let result = engine.daily_digest(&digest_input, "en", TaskOptions::default()).await?;
    print_result("End-of-day digest", &result);

    println!("\n{}", "=".repeat(60));
    println!("  KChat B2C demo complete. All AI ran on-device.");
    println!("{}", "=".repeat(60));

    engine.shutdown().await?;
    Ok(())
}
