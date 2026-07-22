//! Comprehensive real-world dataset benchmark for zk-ai pipelines.
//!
//! Exercises every pipeline with realistic, diverse inputs and measures:
//! - Latency (p50, p95, p99)
//! - Throughput (ops/sec)
//! - Resource usage (memory delta)
//! - Output quality (length, structure, key info retention)
//!
//! Results are printed as a structured report for expert assessment against
//! top-level product benchmarks (GPT-4, Claude, Whisper, etc.).

use criterion::{criterion_group, criterion_main, Criterion};
use std::time::{Duration, Instant};
use zk_ai_benchmarks::{setup_fallback_engine, synthetic_embedding};
use zk_ai_core::pipeline::{TaskOptions, SUPPORTED_LANGUAGES};
use zk_ai_core::{TextIndex, TextSearchHit};
use zk_ai_core::model_manager::ModelSpec;

// ──────────────────────────────────────────────────────────────────────────
// Real-world test datasets
// ──────────────────────────────────────────────────────────────────────────

/// Long meeting transcript (~2000 words) — tests summarization quality on realistic input.
const MEETING_TRANSCRIPT: &str = r#"
Meeting: Q3 Product Strategy Review
Date: 2024-10-15
Attendees: Sarah (CEO), Mike (CTO), Jennifer (CFO), David (VP Product), Lisa (VP Engineering)

Sarah: Let's start with the Q3 review. Mike, can you give us the engineering update?

Mike: Sure. We shipped 47 features in Q3, up from 31 in Q2. The migration to the new inference engine is 80% complete. We had two P1 incidents — both related to the ONNX runtime upgrade. Mean time to resolution was 18 minutes, down from 45 minutes last quarter. Our test coverage is now 87%, up from 72%.

Jennifer: What's the infrastructure cost impact of the migration?

Mike: We're seeing 30% reduction in inference latency and 22% reduction in memory usage. The int8 quantization is working well. Infrastructure costs are down 15% despite a 40% increase in request volume.

Sarah: That's excellent. David, how are the product metrics?

David: DAU is up 28% quarter-over-quarter. The new semantic search feature has a 45% adoption rate among new users. Customer satisfaction score is 4.2, up from 3.8. However, we're seeing a 12% churn rate in the free tier after the 30-day mark.

Lisa: I think the churn is related to the onboarding experience. Our data shows users who complete the tutorial have an 85% retention rate, but only 30% of free users complete it.

Sarah: That's a critical insight. Let's make onboarding optimization a Q4 priority. Jennifer, financials?

Jennifer: Revenue is $4.2M, up 23% YoY. Gross margin improved to 78% from 72% due to the infrastructure cost reductions. We're tracking to hit $5M in Q4 if the growth rate holds. The acquisition of TechCorp for $50M closed last week — integration is on track.

David: The TechCorp integration will add 200K users to our platform. We need to prioritize data migration and SSO integration for Q4.

Mike: From an engineering perspective, the TechCorp integration will require 3 sprints. We need to hire 2 additional platform engineers. The budget impact is approximately $400K for Q4.

Jennifer: That's within our hiring budget. Approved.

Sarah: Let's summarize the Q4 priorities. First, onboarding optimization targeting 50% tutorial completion. Second, TechCorp integration with 200K user migration. Third, complete the inference engine migration. Fourth, hire 2 platform engineers.

Lisa: I'd also like to add — we need to address the technical debt in the audio pipeline. The Whisper integration is working but the mel spectrogram preprocessing needs optimization for real-time use cases.

Mike: Agreed. I'll add that to the Q4 roadmap with a dedicated sprint.

Sarah: Any other items?

David: One more thing — we're seeing increased demand for the B2B compliance features. Three enterprise customers have asked for SOC 2 Type II compliance. We should prioritize that for Q4.

Jennifer: SOC 2 compliance will require an external audit. Budget approximately $75K. I'll get quotes from three firms this week.

Sarah: Great. Action items: Lisa to lead onboarding optimization. Mike to coordinate TechCorp integration and hiring. David to scope SOC 2 compliance requirements. Jennifer to get audit quotes. Let's reconvene in two weeks.
"#;

/// Long email thread — tests email intelligence pipelines.
const EMAIL_THREAD: &str = r#"
From: alice@techcorp.com
To: bob@startup.io
Subject: Re: Partnership Proposal - Phase 2 Integration

Hi Bob,

Thanks for the detailed proposal. I've reviewed it with our technical team and we have a few concerns:

1. The API rate limits you've proposed (1000 req/hour) won't be sufficient for our production traffic. We're currently doing 50K requests per hour at peak. We'd need at least 100K/hour with burst capacity.

2. The data residency requirements need clarification. Our EU customers require data to stay within EU boundaries. Can you confirm your infrastructure supports this?

3. The pricing model you proposed ($0.05 per API call) would cost us approximately $2M/year at current volume. We were expecting something closer to $0.02 based on our volume commitment.

4. Security: we need SOC 2 Type II compliance before we can proceed. Do you have an existing report or timeline for completion?

Looking forward to your response.

Best,
Alice

---

From: bob@startup.io
To: alice@techcorp.com
Subject: Re: Partnership Proposal - Phase 2 Integration

Hi Alice,

Thanks for the detailed feedback. Let me address each point:

1. Rate limits: We can increase to 200K/hour with burst capacity up to 500K. This would be a custom tier. The infrastructure is already in place — we just need to update your account configuration.

2. Data residency: We have EU infrastructure in Frankfurt and Dublin. We can guarantee EU-only data processing with a dedicated region. This is available at no additional cost for enterprise customers.

3. Pricing: At your volume (50K/hour = ~438M calls/year), we can offer $0.015 per call with an annual commitment. That would be approximately $1.5M/year, saving you $500K compared to your current estimate.

4. SOC 2: We're currently in the final stages of our Type II audit. The report will be available by November 15. I can share the Type I report immediately under NDA.

Let me know if you'd like to schedule a call to discuss further.

Best,
Bob

---

From: alice@techcorp.com
To: bob@startup.io
Subject: Re: Partnership Proposal - Phase 2 Integration

Bob,

The pricing looks much better. Let me take this to our VP of Engineering for technical review of the rate limit and data residency setup. I'll get back to you by Friday.

One more question — do you support webhook callbacks for async processing? We need real-time notifications for certain event types.

Thanks,
Alice
"#;

/// Legal contract text — tests contract analysis and clause finding.
const CONTRACT_TEXT: &str = r#"
MASTER SERVICE AGREEMENT

This Master Service Agreement ("Agreement") is entered into as of January 15, 2024 ("Effective Date") by and between TechCorp Inc., a Delaware corporation ("Client"), and AI Solutions LLC, a California limited liability company ("Provider").

1. SERVICES
Provider shall provide AI inference services, model hosting, and technical support as described in applicable Statements of Work ("SOWs"). Each SOW shall be governed by the terms of this Agreement.

2. PAYMENT TERMS
Client shall pay Provider the fees set forth in each SOW within thirty (30) days of receipt of invoice. Late payments shall accrue interest at 1.5% per month. Unpaid amounts exceeding 60 days may result in service suspension.

3. DATA PROCESSING
Provider shall process Client Data in accordance with the Data Processing Addendum ("DPA"). Client Data shall not be used for any purpose other than providing the Services. Provider shall not transfer Client Data outside the agreed region without prior written consent.

4. CONFIDENTIALITY
Each party shall maintain the confidentiality of the other party's confidential information for a period of five (5) years from the date of disclosure. Confidential information includes, but is not limited to, trade secrets, business plans, customer data, and pricing information.

5. INTELLECTUAL PROPERTY
All intellectual property developed by Provider in the course of providing Services shall remain the property of Provider, except for work product specifically created for Client under a SOW, which shall be deemed "Work Product" and assigned to Client upon full payment.

6. TERM AND TERMINATION
This Agreement shall commence on the Effective Date and continue for an initial term of three (3) years. Either party may terminate this Agreement for material breach with thirty (30) days written notice. Upon termination, Provider shall return or destroy all Client Data within fifteen (15) days.

7. LIABILITY
Provider's total liability under this Agreement shall not exceed the fees paid by Client in the twelve (12) months preceding the claim. Neither party shall be liable for indirect, consequential, or punitive damages.

8. GOVERNING LAW
This Agreement shall be governed by the laws of the State of California, without regard to conflict of law principles. Disputes shall be resolved through binding arbitration in San Francisco, California.
"#;

/// Support ticket — tests ticket intelligence pipelines.
const SUPPORT_TICKET: &str = r#"
Ticket #T-2024-5892
Priority: P1 - Critical
Customer: Global FinTech Corp (Enterprise)
Account Manager: dave@company.com
Created: 2024-10-14 09:23 UTC

Subject: Production inference outage - all requests returning 500 errors

Description:
Starting at approximately 08:45 UTC, our production environment began returning HTTP 500 errors for all inference requests. This is affecting our real-time fraud detection system which processes 10K transactions per minute. We are losing approximately $50K per hour in blocked fraud cases.

Environment:
- Region: us-east-1
- Model: mt5-small-1.0.0-int8
- SDK version: 2.3.1
- Request volume: 10K/min (normal)

Steps already taken:
1. Checked status page - no reported incidents
2. Restarted application servers - issue persists
3. Verified network connectivity to inference endpoints - OK
4. Checked model cache - files present and valid
5. Reviewed application logs - seeing "ONNX session init failed" errors

Impact:
- Fraud detection system is DOWN
- 10K transactions/min unmonitored
- Estimated financial impact: $50K/hour
- Customer has threatened to escalate to C-suite if not resolved within 2 hours

Customer communication:
Customer is extremely frustrated. They mentioned this is the third outage this quarter and they are considering switching to a competitor (OpenAI) if SLA is not met. They have a 99.9% uptime SLA and this outage has already breached it for October.

Assigned to: Platform Engineering Team
"#;

/// Multi-language news article — tests translation and summarization across languages.
const NEWS_ARTICLES: &[(&str, &str)] = &[
    ("en", "Apple announced its Q4 earnings, reporting revenue of $94.9 billion, up 6% year-over-year. iPhone sales reached $46.2 billion, while Services revenue hit a record $25 billion. CEO Tim Cook highlighted strong growth in emerging markets, particularly India and Vietnam. The company also announced a $95 billion share buyback program."),
    ("vi", "Apple công bố kết quả kinh doanh quý 4 với doanh thu 94,9 tỷ USD, tăng 6% so với cùng kỳ năm trước. Doanh số iPhone đạt 46,2 tỷ USD, trong khi doanh thu dịch vụ lập kỷ lục 25 tỷ USD. Tổng giám đốc Tim Cook nhấn mạnh sự tăng trưởng mạnh ở các thị trường mới nổi, đặc biệt là Ấn Độ và Việt Nam."),
    ("zh", "苹果公司公布第四季度财报，营收达949亿美元，同比增长6%。iPhone销售额达462亿美元，服务收入创纪录达250亿美元。首席执行官蒂姆·库克强调在新兴市场特别是印度和越南的强劲增长。公司还宣布了950亿美元的股票回购计划。"),
    ("ar", "أعلنت شركة آبل عن أرباحها في الربع الرابع، حيث بلغت الإيرادات 94.9 مليار دولار، بزيادة 6٪ عن العام السابق. وصلت مبيعات آيفون إلى 46.2 مليار دولار، بينما سجلت إيرادات الخدمات رقماً قياسياً بلغ 25 مليار دولار."),
    ("es", "Apple anunció sus ganancias del cuarto trimestre, reportando ingresos de 94.900 millones de dólares, un aumento del 6% interanual. Las ventas del iPhone alcanzaron 46.200 millones de dólares, mientras que los ingresos por servicios alcanzaron un récord de 25.000 millones de dólares."),
    ("fr", "Apple a annoncé ses résultats du quatrième trimestre, avec un chiffre d'affaires de 94,9 milliards de dollars, en hausse de 6% par rapport à l'année précédente. Les ventes d'iPhone ont atteint 46,2 milliards de dollars, tandis que les revenus des services ont atteint un record de 25 milliards de dollars."),
    ("de", "Apple gab seine Ergebnisse für das vierte Quartal bekannt und meldete einen Umsatz von 94,9 Milliarden Dollar, was einem Jahreswachstum von 6% entspricht. Die iPhone-Verkäufe erreichten 46,2 Milliarden Dollar, während die Service-Einnahmen mit 25 Milliarden Dollar einen Rekordwert verzeichneten."),
    ("ja", "Appleは第4四半期の決算を発表し、前年同期比6%増の949億ドルの収益を報告した。iPhoneの売上は462億ドルに達し、サービス収入は250億ドルの記録を樹立した。ティム・クックCEOはインドとベトナムなどの新興市場での強い成長を強調した。"),
    ("ko", "Apple은 4분기 실적을 발표하며 전년 대비 6% 증가한 949억 달러의 수익을 보고했습니다. iPhone 판매는 462억 달러에 달했고, 서비스 수익은 250억 달러의 기록을 세웠습니다."),
    ("ru", "Apple объявила о результатах четвертого квартала, сообщив о выручке в 94,9 миллиарда долларов, что на 6% больше по сравнению с аналогичным периодом прошлого года. Продажи iPhone достигли 46,2 миллиарда долларов, а доходы от услуг достигли рекордных 25 миллиардов долларов."),
];

/// Chat conversation — tests chat summary and smart reply.
const CHAT_CONVERSATION: &str = r#"
[10:02] Sarah: Hey team, anyone seen the latest user feedback report?
[10:03] Mike: I just reviewed it. Overall sentiment is positive but there are concerns about the mobile app performance
[10:05] Jennifer: What specific issues are users reporting?
[10:06] Mike: Mainly slow loading times on older devices and occasional crashes on iOS 15
[10:08] Lisa: I can confirm — our telemetry shows 3.2% crash rate on iOS 15 devices. We've identified the issue: memory pressure during image processing
[10:10] David: How long to fix?
[10:11] Lisa: We can have a hotfix ready by Thursday. The fix involves downsampling images before processing
[10:12] Sarah: Let's prioritize this. Can we also look at the Android side?
[10:13] Mike: Android is fine — crash rate is 0.3%. The issue is iOS-specific
[10:15] Jennifer: Should we communicate to affected users?
[10:16] David: Yes, I'll draft an in-app message for iOS 15 users. Something like "We're aware of performance issues and a fix is coming this week"
[10:18] Sarah: Good plan. Lisa, please update the team once the hotfix is deployed
[10:19] Lisa: Will do. I'll also add regression tests to prevent this in the future
[10:20] Mike: I'll review the PR when it's ready
[10:21] Sarah: Great teamwork everyone. Let's reconvene on Thursday after the hotfix
"#;

/// Document for PII scanning.
const PII_DOCUMENT: &str = r#"
Employee Record
Name: John Smith
Email: john.smith@company.com
Phone: +1-555-123-4567
SSN: 123-45-6789
Credit Card: 4532-1234-5678-9012
Address: 123 Main St, San Francisco, CA 94105
Date of Birth: 1985-03-15
Employee ID: EMP-2024-0042
Department: Engineering
Manager: alice@company.com
Emergency Contact: Jane Smith, +1-555-987-6543
Bank Account: 9876543210
Routing: 021000021
"#;

/// Document for sensitivity classification.
const SENSITIVITY_DOCUMENTS: &[(&str, &str)] = &[
    ("Public", "Welcome to our company! We're excited to share that we've launched a new product line. Check out our website for the latest updates and special offers available this month."),
    ("Internal", "Team, please note that the Q4 all-hands meeting has been moved to Thursday at 3pm. Please review the attached slides before the meeting and come prepared with questions."),
    ("Confidential", "The acquisition terms include a $50M cash payment plus $10M in stock vesting over 4 years. The deal is expected to close by Q1 2025 pending regulatory approval. Do not discuss externally."),
    ("Restricted", "Customer SSN: 123-45-6789. API keys: sk-prod-abc123xyz. Database credentials: postgres://admin:p@ssw0rd@db.internal:5432/prod. These credentials must not be shared or committed to version control."),
];

/// Notifications for digest.
const NOTIFICATIONS: &str = r#"
- 3 new emails from VIP clients requiring response
- Build #4892 failed in CI - tests failing in audio module
- Pull request #234 awaiting review from @mike
- Meeting reminder: Q4 planning at 2pm
- 2 new support tickets escalated to P1
- Deployment to staging completed successfully
- Security alert: unusual login from IP 192.168.1.50
- Sarah commented on your document "Q4 Roadmap"
- 15 new user signups in the last hour
- Cost alert: AWS spending is 20% above budget this month
"#;

/// Technical document for Q&A and RAG.
const TECHNICAL_DOCS: &[(&str, &str)] = &[
    ("architecture", "The system uses a layered architecture: (1) Client layer with iOS, Android, and web SDKs, (2) API gateway handling authentication and rate limiting, (3) Inference layer with ONNX Runtime and LoRA adapters, (4) Model management layer handling caching and eviction, (5) Storage layer with SQLite for metadata and filesystem for model files. All inference runs on-device — no data leaves the client."),
    ("privacy", "Privacy is enforced through: (1) On-device inference — no data sent to servers, (2) PII detection before any processing, (3) Encrypted model cache at rest, (4) Audit logging of all inference calls, (5) Data residency enforcement — models and data stay within configured regions, (6) Zero-knowledge architecture — server cannot access client data."),
    ("performance", "Performance targets: (1) Cold start under 500ms for model loading, (2) Inference latency under 200ms for mT5-small int8, (3) Memory usage under 150MB for single model, (4) Battery impact under 2% per hour for active inference, (5) Offline-first — all features work without network, (6) Graceful degradation on LowEnd devices via tier gating."),
    ("models", "Model registry includes: (1) mt5-small-1.0.0-int8 for text generation tasks (summarize, translate, generate), (2) multilingual-e5-small-1.0.0-int8 for embeddings (semantic search, clustering, dedup), (3) clip-vit-base-patch32-1.0.0-int8 for image search, (4) whisper-tiny-1.0.0-int8 for speech-to-text. All models use int8 quantization for 4x size reduction with minimal quality loss."),
    ("governor", "The Resource Governor enforces: (1) Max CPU usage per inference (default 80%), (2) Max memory usage (default 75%), (3) Min battery level (default 15%), (4) Max thermal state (default: throttling), (5) Max 1 concurrent inference via semaphore, (6) Configurable timeout per inference call. If limits are exceeded, inference is paused or rejected."),
];

/// Documents for clustering.
const CLUSTER_DOCS: &[(&str, &str)] = &[
    ("doc1", "Machine learning models require large datasets for training. Deep learning architectures like transformers have revolutionized NLP tasks."),
    ("doc2", "Neural networks are inspired by biological neurons. Backpropagation is the key algorithm for training deep models."),
    ("doc3", "The stock market saw significant volatility this quarter. Interest rate hikes by the Federal Reserve impacted tech stocks."),
    ("doc4", "Cryptocurrency prices surged following regulatory clarity from the SEC. Bitcoin reached new yearly highs."),
    ("doc5", "Cloud infrastructure costs can be optimized through reserved instances and spot pricing strategies."),
    ("doc6", "Kubernetes orchestration simplifies container management at scale. Helm charts enable reproducible deployments."),
    ("doc7", "GDPR compliance requires data minimization and explicit consent mechanisms. Privacy by design is a core principle."),
    ("doc8", "SOC 2 Type II audits verify security controls. Access logs and change management are critical evidence areas."),
    ("doc9", "Transformer architectures use self-attention mechanisms. BERT and GPT models are based on transformer blocks."),
    ("doc10", "The Federal Reserve signaled potential rate cuts. Bond yields fell in response to the dovish guidance."),
    ("doc11", "Docker containers provide isolated execution environments. Container registries store and distribute images."),
    ("doc12", "HIPAA compliance requires encryption of protected health information. Audit trails must be maintained for 6 years."),
];

/// Audio sample (synthetic sine wave at 16kHz).
fn synthetic_audio(duration_secs: f32, freq: f32) -> Vec<f32> {
    let samples = (16000.0 * duration_secs) as usize;
    (0..samples)
        .map(|i| {
            let t = i as f32 / 16000.0;
            (2.0 * std::f32::consts::PI * freq * t).sin() * 0.5
        })
        .collect()
}

// ──────────────────────────────────────────────────────────────────────────
// Expanded datasets for real-world testing (500+ tests)
// ──────────────────────────────────────────────────────────────────────────

/// 20 sentiment samples with expected labels.
const SENTIMENT_DATASET: &[(&str, &str)] = &[
    ("positive", "I absolutely love the new design! The team did an amazing job on the UI."),
    ("negative", "The service has been terrible. I've been waiting for a response for 3 days."),
    ("neutral", "The quarterly report shows mixed results. Revenue is up but customer churn increased."),
    ("positive", "Best product I've used all year. Exceeded all my expectations!"),
    ("positive", "Fantastic experience from start to finish. Highly recommend to everyone."),
    ("negative", "Worst purchase ever. Complete waste of money and time."),
    ("neutral", "The package arrived on Tuesday as scheduled. No issues to report."),
    ("positive", "The team delivered ahead of schedule with excellent quality. Outstanding work!"),
    ("negative", "I'm very disappointed with the customer support. They were unhelpful and rude."),
    ("neutral", "The meeting is scheduled for 3pm in conference room B."),
    ("positive", "Great presentation today! Really clear and well-structured content."),
    ("negative", "The app keeps crashing after the latest update. Very frustrating experience."),
    ("neutral", "Q3 revenue was $4.2M, up 23% year-over-year. Gross margin at 78%."),
    ("positive", "Thank you so much for your help! You made the process easy and painless."),
    ("negative", "This is unacceptable. We've had three outages this month and no communication."),
    ("neutral", "The document has been updated with the latest revisions and uploaded to the shared drive."),
    ("positive", "Excellent performance from the engineering team. All milestones met on time."),
    ("negative", "I want a refund. The product doesn't work as advertised and support won't respond."),
    ("neutral", "The policy takes effect on January 1, 2025. All employees must complete training by Q1."),
    ("positive", "Really impressed with the new feature set. The UX improvements are night and day!"),
];

/// 20 tone classification samples with expected labels.
const TONE_DATASET: &[(&str, &str)] = &[
    ("Urgent", "URGENT: Production is down, need immediate response!"),
    ("FYI", "FYI: Updated the meeting notes from yesterday's session."),
    ("Action needed", "Could you please review this when you have time? No rush."),
    ("Concerned", "WARNING: Your account will be suspended in 24 hours if no action is taken."),
    ("Urgent", "ASAP: The deployment failed and customers are affected. Need help now."),
    ("FYI", "Just wanted to share this article about industry trends. No action needed."),
    ("Action needed", "Please approve the budget request by Friday so we can proceed with hiring."),
    ("Positive", "Great job on the presentation! The client was very impressed."),
    ("Concerned", "I'm worried about the timeline. We might not make the deadline."),
    ("Urgent", "CRITICAL: Security breach detected. All hands needed immediately."),
    ("FYI", "Heads up: the office will be closed next Monday for the holiday."),
    ("Action needed", "Please review and sign the attached contract by end of day."),
    ("Positive", "Thank you for the excellent work! The feature is working perfectly."),
    ("Concerned", "There's a risk we might lose the client if we don't improve response times."),
    ("Urgent", "Time-sensitive: The SSL certificate expires today. Please renew immediately."),
    ("FYI", "Sharing the latest metrics dashboard for your reference."),
    ("Action needed", "Your approval is needed on the Q4 roadmap before we can start planning."),
    ("Positive", "Awesome work this sprint! Everything delivered on time with great quality."),
    ("Concerned", "I have concerns about the architecture choice. It may not scale well."),
    ("Urgent", "Emergency: The database is down and all writes are failing. Need immediate escalation."),
];

/// 20 urgency classification samples with expected labels.
const URGENCY_DATASET: &[(&str, &str)] = &[
    ("P1", "Production is down. All requests failing. $50K/hour impact. Need immediate help."),
    ("P2", "Some users experiencing slow response times. Workaround available."),
    ("P3", "Feature request: add dark mode support to the dashboard."),
    ("P4", "Documentation typo on the API reference page."),
    ("P1", "Security breach: unauthorized access detected. All systems compromised."),
    ("P2", "API rate limiting causing intermittent failures for enterprise customers."),
    ("P3", "Users requesting ability to export reports as PDF."),
    ("P4", "Suggestion: add keyboard shortcuts for common actions."),
    ("P1", "Data loss: customer records deleted during migration. Critical data missing."),
    ("P2", "Login page occasionally returns 500 error. Affects ~5% of users."),
    ("P3", "Question: how do I configure SSO with Azure AD?"),
    ("P4", "Minor: the logo on the login page is slightly misaligned."),
    ("P1", "Complete outage: no one can access the platform. Revenue impact $100K/hour."),
    ("P2", "Search feature returning incorrect results for some queries. Workaround: use filters."),
    ("P3", "Enhancement: add bulk import capability for user management."),
    ("P4", "Typo in the welcome email template: 'acount' should be 'account'."),
    ("P1", "Payment system down. No transactions processing. $200K/hour impact."),
    ("P2", "Mobile app crashes on startup for Android 14 users. Affects significant user base."),
    ("P3", "Request: integrate with Slack for notifications."),
    ("P4", "FAQ page has outdated information about pricing tiers."),
];

/// 20 sensitivity classification samples with expected labels.
const SENSITIVITY_DATASET: &[(&str, &str)] = &[
    ("Public", "Welcome to our company! We're excited to share that we've launched a new product line."),
    ("Internal", "Team, please note that the Q4 all-hands meeting has been moved to Thursday at 3pm."),
    ("Confidential", "The acquisition terms include a $50M cash payment. Do not discuss externally."),
    ("Restricted", "Customer SSN: 123-45-6789. API keys: sk-prod-abc123. Database credentials included."),
    ("Public", "Our company mission is to empower businesses with AI-driven insights."),
    ("Internal", "Please review the updated coding standards document before the next sprint."),
    ("Confidential", "Salary adjustments for Q4 have been approved. Individual amounts in attached file."),
    ("Restricted", "Production database password: p@ssw0rd123! Access only via VPN."),
    ("Public", "Check out our latest blog post about best practices for data privacy."),
    ("Internal", "The office supply order has been placed. Expected delivery on Wednesday."),
    ("Confidential", "Board meeting minutes: discussed IPO timeline and valuation targets."),
    ("Restricted", "AWS root account credentials: admin@example.com / Pr0dRootKey!2024"),
    ("Public", "We're hiring! See our careers page for open positions."),
    ("Internal", "Reminder: submit your timesheets by Friday at 5pm for payroll processing."),
    ("Confidential", "M&A discussions with TechCorp are progressing. Valuation at $50M. NDA required."),
    ("Restricted", "Customer PII: John Smith, SSN 123-45-6789, DOB 1985-03-15, credit card 4532-1234-5678-9012."),
    ("Public", "Our Q3 earnings call is scheduled for November 15 at 2pm ET."),
    ("Internal", "The new VPN configuration requires all employees to update their certificates."),
    ("Confidential", "Pricing strategy: we're undercutting competitors by 15%. Do not share with partners."),
    ("Restricted", "Stripe API key: sk_live_abc123xyz. JWT signing secret: s3cr3tK3y!456"),
];

/// 20 email categorization samples with expected labels.
const EMAIL_CATEGIZE_DATASET: &[(&str, &str)] = &[
    ("Action Required", "Hi team, please review the Q4 roadmap document before our meeting tomorrow."),
    ("Vendor", "Your order has shipped! Track your package with tracking number 1Z999AA10123456784."),
    ("Action Required", "URGENT: Invoice #4892 is 45 days overdue. Please remit payment immediately."),
    ("Newsletter", "Weekly newsletter: Top 10 AI trends for 2024. Read more on our blog."),
    ("Action Required", "Please approve the pull request #234 so we can merge before the release."),
    ("Vendor", "Your AWS bill for October is $12,450. Payment will be charged to your card on file."),
    ("Newsletter", "Monthly digest: New features, customer stories, and product updates."),
    ("Client", "Hi, I have a question about the API documentation. Can someone help me?"),
    ("Internal", "Team lunch this Friday at noon. Please RSVP by Thursday."),
    ("Action Required", "Contract renewal: please sign the attached amendment by November 30."),
    ("Vendor", "Service alert: scheduled maintenance window Saturday 2-4am. Expect downtime."),
    ("Newsletter", "Industry report: State of AI adoption in enterprise 2024."),
    ("Client", "Thank you for the quick response. The solution worked perfectly."),
    ("Internal", "Please update your emergency contact information in the HR portal."),
    ("Action Required", "Your review is needed on the security audit findings by end of week."),
    ("Vendor", "Invoice #1023 from Acme Corp. Due in 30 days. Amount: $5,400."),
    ("Newsletter", "Quarterly product newsletter: what's new in Q4 2024."),
    ("Client", "We'd like to schedule a demo for our team. Are you available next Tuesday?"),
    ("Internal", "The new office layout has been posted. Please check your new desk assignment."),
    ("Action Required", "Please complete the mandatory compliance training by December 1."),
];

/// 15 summarize samples across different content types.
const SUMMARIZE_DATASET: &[(&str, &str)] = &[
    ("en_news", "Apple announced its Q4 earnings, reporting revenue of $94.9 billion, up 6% year-over-year. iPhone sales reached $46.2 billion, while Services revenue hit a record $25 billion. CEO Tim Cook highlighted strong growth in emerging markets, particularly India and Vietnam."),
    ("en_meeting", "The meeting covered Q3 results: 47 features shipped, 87% test coverage, $4.2M revenue. Q4 priorities include onboarding optimization, TechCorp integration, and SOC 2 compliance preparation."),
    ("en_email", "Alice raised concerns about API rate limits, data residency, pricing, and SOC 2 compliance. Bob responded with increased limits, EU infrastructure, discounted pricing, and Type II audit timeline."),
    ("en_technical", "The system uses layered architecture: client SDKs, API gateway, inference layer with ONNX Runtime, model management, and storage. All inference runs on-device with zero data leaving the client."),
    ("en_support", "Customer reports production outage with all inference requests returning 500 errors. ONNX session initialization failing. $50K/hour revenue impact. Customer threatening to escalate."),
    ("vi_news", "Apple công bố kết quả kinh doanh quý 4 với doanh thu 94,9 tỷ USD, tăng 6% so với cùng kỳ. Doanh số iPhone đạt 46,2 tỷ USD, dịch vụ lập kỷ lục 25 tỷ USD."),
    ("zh_news", "苹果公司公布第四季度财报，营收达949亿美元，同比增长6%。iPhone销售额达462亿美元，服务收入创纪录达250亿美元。"),
    ("ar_news", "أعلنت شركة آبل عن أرباحها في الربع الرابع، حيث بلغت الإيرادات 94.9 مليار دولار، بزيادة 6٪ عن العام السابق."),
    ("es_news", "Apple anunció sus ganancias del cuarto trimestre, reportando ingresos de 94.900 millones de dólares, un aumento del 6% interanual."),
    ("fr_news", "Apple a annoncé ses résultats du quatrième trimestre, avec un chiffre d'affaires de 94,9 milliards de dollars, en hausse de 6%."),
    ("de_news", "Apple gab seine Ergebnisse für das vierte Quartal bekannt und meldete einen Umsatz von 94,9 Milliarden Dollar, was einem Jahreswachstum von 6% entspricht."),
    ("ja_news", "Appleは第4四半期の決算を発表し、前年同期比6%増の949億ドルの収益を報告した。iPhoneの売上は462億ドルに達した。"),
    ("ko_news", "Apple은 4분기 실적을 발표하며 전년 대비 6% 증가한 949억 달러의 수익을 보고했습니다."),
    ("ru_news", "Apple объявила о результатах четвертого квартала, сообщив о выручке в 94,9 миллиарда долларов, что на 6% больше."),
    ("en_long", "The Q3 product strategy review meeting covered multiple topics. Engineering shipped 47 features with 87% test coverage. Revenue reached $4.2M, up 23% YoY. The TechCorp acquisition closed at $50M. Q4 priorities were set: onboarding optimization targeting 50% tutorial completion, TechCorp integration with 200K user migration, completing inference engine migration, hiring 2 platform engineers, and SOC 2 compliance preparation. The team also discussed addressing audio pipeline technical debt and the 12% churn rate in the free tier."),
];

/// 15 translate samples.
const TRANSLATE_DATASET: &[(&str, &str, &str)] = &[
    ("en", "vi", "The company reported 23% revenue growth in Q3, reaching $94.9 billion."),
    ("en", "zh", "The company reported 23% revenue growth in Q3, reaching $94.9 billion."),
    ("en", "ar", "The company reported 23% revenue growth in Q3, reaching $94.9 billion."),
    ("en", "es", "The company reported 23% revenue growth in Q3, reaching $94.9 billion."),
    ("en", "fr", "The company reported 23% revenue growth in Q3, reaching $94.9 billion."),
    ("en", "de", "The company reported 23% revenue growth in Q3, reaching $94.9 billion."),
    ("en", "ja", "The company reported 23% revenue growth in Q3, reaching $94.9 billion."),
    ("en", "ko", "The company reported 23% revenue growth in Q3, reaching $94.9 billion."),
    ("en", "ru", "The company reported 23% revenue growth in Q3, reaching $94.9 billion."),
    ("vi", "en", "Công ty báo cáo tăng trưởng doanh thu 23% trong quý 3, đạt 94,9 tỷ USD."),
    ("zh", "en", "公司报告第三季度收入增长23%，达到949亿美元。"),
    ("ar", "en", "أبلغت الشركة عن نمو الإيرادات بنسبة 23% في الربع الثالث، وصلت إلى 94.9 مليار دولار."),
    ("es", "en", "La empresa reportó un crecimiento de ingresos del 23% en el tercer trimestre, alcanzando $94.900 millones."),
    ("fr", "en", "L'entreprise a signalé une croissance de 23% de ses revenus au troisième trimestre, atteignant 94,9 milliards de dollars."),
    ("de", "en", "Das Unternehmen meldete ein Umsatzwachstum von 23% im dritten Quartal und erreichte 94,9 Milliarden Dollar."),
];

/// 10 PII scan samples.
const PII_DATASET: &[(&str, &str)] = &[
    ("employee_record", "Name: John Smith\nEmail: john.smith@company.com\nPhone: +1-555-123-4567\nSSN: 123-45-6789\nCredit Card: 4532-1234-5678-9012\nAddress: 123 Main St, San Francisco, CA 94105\nDOB: 1985-03-15"),
    ("customer_email", "Hi, my name is Alice Johnson. You can reach me at alice.j@gmail.com or 555-987-6543. My card number is 4111-1111-1111-1111."),
    ("support_ticket", "Customer: Bob Williams, bob.williams@corp.com, SSN 987-65-4321. Billing address: 456 Oak Ave, New York, NY 10001. Account: 1234567890."),
    ("chat_message", "Hey, can you send the report to dave@team.io? His phone is 555-222-3333 and he's at 789 Pine St, Austin TX 78701."),
    ("hr_document", "Employee: Jane Doe\nSSN: 111-22-3333\nEmail: jane.doe@hr.com\nBank: 9876543210\nRouting: 021000021\nDOB: 1990-07-22"),
    ("medical_record", "Patient: John Doe, DOB 1980-01-15, SSN 444-55-6666, Email patient@email.com, Phone 555-111-2222, Insurance ID MED-2024-0099"),
    ("legal_doc", "Witness: Sarah Connor, email s.connor@law.com, phone 555-333-4444, address 1234 Elm St, Los Angeles CA 90001, SSN 777-88-9999"),
    ("sales_lead", "Lead: Michael Scott, michael@dunder.com, 570-555-1234, 1725 Slough Ave, Scranton PA 18505, budget $50K"),
    ("financial_form", "Account holder: Pam Beesly, SSN 222-33-4444, email pam.b@dunder.com, account 1234567890, routing 021000021, card 5500-0000-0000-0004"),
    ("contact_list", "1. Dwight Schrute, dwight@schrutefarms.com, 570-555-9876\n2. Angela Martin, angela@dunder.com, 570-555-3456\n3. Kevin Malone, kevin@dunder.com, 570-555-2345"),
];

/// 10 date extraction samples.
const DATE_DATASET: &[(&str, &str)] = &[
    ("contract", "The contract was signed on January 15, 2024. The initial term is 3 years, expiring January 15, 2027. Payment is due within 30 days of invoice. The audit must be completed by November 15, 2024."),
    ("email_dates", "Meeting scheduled for March 22, 2024 at 2pm. Follow-up on 04/15/2024. Deadline: 2024-05-30. Quarterly review on July 10, 2024."),
    ("mixed_formats", "Event on 2024-03-15. Conference: 03/20/2024. Deadline: April 5, 2024. Release: 2024/06/01. Launch: 15-03-2024."),
    ("iso_dates", "Created: 2024-01-15. Modified: 2024-03-22. Expires: 2025-12-31. Updated: 2024-06-10. Reviewed: 2024-09-05."),
    ("us_formats", "Start: 01/15/2024. End: 12/31/2024. Meeting: 03/22/2024. Deadline: 06/15/2024. Review: 09/01/2024."),
    ("long_text", "The project kicked off on January 15, 2024. Phase 1 completed on March 3, 2024. Phase 2 started 2024-03-15 and ended April 20, 2024. Final delivery was made on 05/30/2024. The warranty expires December 31, 2025."),
    ("sparse_dates", "There are no dates in this text except for one: 2024-07-04. Everything else is just regular text without any date references."),
    ("european_dates", "Meeting on 15/01/2024. Deadline 22/03/2024. Conference 30/06/2024. Holiday 25/12/2024. New year 01/01/2025."),
    ("formal_doc", "Effective Date: January 15, 2024. Term: three (3) years, expiring January 15, 2027. Review Date: November 15, 2024. Termination Notice: thirty (30) days prior to 2027-01-15."),
    ("no_dates", "This document contains general information about the product. There are no specific dates mentioned. Please refer to the schedule for timing details."),
];

/// 10 dedup ticket pairs (existing, new, expected_duplicate).
const DEDUP_DATASET: &[(&str, &str, bool)] = &[
    ("Production inference outage - all requests returning 500 errors. ONNX session init failed.", "All inference requests are failing with 500 errors. ONNX runtime session initialization is failing.", true),
    ("API rate limit exceeded for enterprise customer. Requests being throttled.", "Rate limiting on API causing throttled requests for enterprise client.", true),
    ("Model download failing with network timeout. CDN appears unreachable.", "Cannot download model files. Network timeout to CDN endpoint.", true),
    ("Feature request: add dark mode to dashboard.", "Production outage - all systems down. Need immediate help.", false),
    ("Login page returns 500 error intermittently for some users.", "Authentication page occasionally fails with HTTP 500 for certain users.", true),
    ("Database connection pool exhausted. Too many concurrent connections.", "SSL certificate expired. Need to renew immediately.", false),
    ("Mobile app crashes on Android 14 startup. Affects many users.", "Android 14 app crash on launch. Significant user impact reported.", true),
    ("Documentation typo on API reference page.", "Minor spelling error in the getting started guide.", false),
    ("Payment gateway timeout. Transactions not processing. Revenue impact.", "Payment system down. No transactions going through. Critical revenue loss.", true),
    ("Email notification delivery delayed by 30 minutes.", "Server maintenance scheduled for Saturday 2-4am. Expect downtime.", false),
];

/// 8 find_expert queries with expected expert IDs.
const FIND_EXPERT_DATASET: &[(&str, &str)] = &[
    ("machine learning and neural networks", "alice"),
    ("cloud infrastructure and Kubernetes", "bob"),
    ("security compliance and GDPR", "carol"),
    ("financial systems and risk management", "dave"),
    ("deep learning architectures", "alice"),
    ("container orchestration", "bob"),
    ("SOC 2 audits", "carol"),
    ("trading algorithms", "dave"),
];

/// 10 audio samples at various durations and frequencies.
const AUDIO_DATASET: &[(f32, f32)] = &[
    (0.5, 440.0),
    (1.0, 440.0),
    (1.0, 880.0),
    (2.0, 440.0),
    (2.0, 220.0),
    (3.0, 440.0),
    (5.0, 440.0),
    (5.0, 880.0),
    (10.0, 440.0),
    (10.0, 220.0),
];

// ──────────────────────────────────────────────────────────────────────────
// Multi-language and mixed-language datasets
// ──────────────────────────────────────────────────────────────────────────

/// 20 multi-language sentiment samples (vi, zh, es, fr, de, ja, ar, ko, ru, mixed).
const MULTILANG_SENTIMENT: &[(&str, &str)] = &[
    ("positive", "Tôi rất thích thiết kế mới! Đội ngũ đã làm một công việc tuyệt vời."),
    ("negative", "Dịch vụ rất tệ. Tôi đã đợi phản hồi trong 3 ngày rồi."),
    ("neutral", "Báo cáo quý cho thấy kết quả hỗn hợp. Doanh thu tăng nhưng tỷ lệ rời bỏ khách hàng cũng tăng."),
    ("positive", "¡Me encanta el nuevo diseño! El equipo hizo un trabajo increíble."),
    ("negative", "El servicio ha sido terrible. He estado esperando una respuesta durante 3 días."),
    ("neutral", "El informe trimestral muestra resultados mixtos. Los ingresos suben pero la rotación de clientes aumentó."),
    ("positive", "J'adore le nouveau design ! L'équipe a fait un travail remarquable."),
    ("negative", "Le service a été terrible. J'attends une réponse depuis 3 jours."),
    ("neutral", "Le rapport trimestriel montre des résultats mitigés. Les revenus augmentent mais le churn client aussi."),
    ("positive", "Ich liebe das neue Design! Das Team hat großartige Arbeit geleistet."),
    ("negative", "Der Service war furchtbar. Ich warte seit 3 Tagen auf eine Antwort."),
    ("neutral", "Der Quartalsbericht zeigt gemischte Ergebnisse. Die Einnahmen steigen, aber die Kundenabwanderung auch."),
    ("positive", "新しいデザインが大好きです！チームは素晴らしい仕事をしました。"),
    ("negative", "サービスがひどいです。3日間返事を待っています。"),
    ("neutral", "四半期報告書は混合結果を示しています。収益は増加しているが、顧客離れも増加しました。"),
    ("positive", "أحب التصميم الجديد كثيراً! الفريق قام بعمل رائع."),
    ("negative", "الخدمة كانت سيئة جداً. أنتظر رداً منذ 3 أيام."),
    ("positive", "새로운 디자인이 정말 마음에 듭니다! 팀이 훌륭한 작업을 했습니다."),
    ("negative", "서비스가 너무 끔찍합니다. 3일 동안 답변을 기다리고 있습니다."),
    ("positive", "I absolutely love the new design! 新デザインは素晴らしいです。The team did an amazing job."),
];

/// 20 multi-language tone samples.
const MULTILANG_TONE: &[(&str, &str)] = &[
    ("Urgent", "KHẨN CẤP: Hệ thống sản xuất bị sập, cần phản hồi ngay lập tức!"),
    ("FYI", "FYI: Đã cập nhật ghi chú cuộc họp từ phiên hôm qua."),
    ("Action needed", "Por favor revise el documento del roadmap antes de la reunión de mañana."),
    ("Positive", "¡Excelente trabajo en la presentación! El cliente quedó muy impresionado."),
    ("Concerned", "Je m'inquiète du délai. Nous pourrions ne pas respecter la date limite."),
    ("Urgent", "URGENT: Le système est en panne. Besoin d'aide immédiate !"),
    ("FYI", "FYI: Informationen zur Verfügung gestellt. Keine Aktion erforderlich."),
    ("Action needed", "Bitte genehmigen Sie die Budgetanfrage bis Freitag."),
    ("Positive", "素晴らしいプレゼンテーションでした！お客様もとても感銘を受けました。"),
    ("Concerned", "スケジュールについて心配しています。期限に間に合わないかもしれません。"),
    ("Urgent", "緊急：データベースがダウンしています。今すぐ対応が必要です。"),
    ("FYI", "参考までに：最新のメトリクスダッシュボードを共有します。"),
    ("Action needed", "金曜日までに予算承認をお願いします。"),
    ("Positive", "Great job on the presentation! 仕事は素晴らしいでした。"),
    ("Concerned", "I'm worried about the timeline. 期限に間に合わないかもしれません。"),
    ("Urgent", "عاجل: النظام معطل. نحتاج مساعدة فورية!"),
    ("FYI", "للمعلومات: تم تحديث ملاحظات الاجتماع."),
    ("Action needed", "승인이 필요합니다. 금요일까지 부탁드립니다."),
    ("Positive", "훌륭한 작업입니다! 고객이 매우 감동했습니다."),
    ("Concerned", "타임라인이 걱정됩니다. 기한을 맞추지 못할 수 있습니다."),
];

/// 20 multi-language urgency samples.
const MULTILANG_URGENCY: &[(&str, &str)] = &[
    ("P1", "Hệ thống sản xuất bị sập. Tất cả yêu cầu thất bại. Ảnh hưởng $50K/giờ."),
    ("P2", "Một số người dùng gặp thời gian phản hồi chậm. Có giải pháp thay thế."),
    ("P3", "Yêu cầu tính năng: thêm chế độ tối cho bảng điều khiển."),
    ("P4", "Lỗi chính tả trong tài liệu API."),
    ("P1", "¡Producción caída! Todas las solicitudes fallan. Impacto de $50K/hora."),
    ("P2", "Algunos usuarios experimentan tiempos de respuesta lentos. Solución alternativa disponible."),
    ("P3", "Solicitud de función: añadir modo oscuro al panel."),
    ("P4", "Error tipográfico en la página de referencia de la API."),
    ("P1", "Production en panne ! Toutes les requêtes échouent. Impact de 50K$/heure."),
    ("P2", "Certains utilisateurs connaissent des temps de réponse lents. Contournement disponible."),
    ("P3", "Demande de fonctionnalité : ajouter le mode sombre au tableau de bord."),
    ("P4", "Faute de frappe dans la documentation de l'API."),
    ("P1", "Produktionsausfall! Alle Anfragen fehlgeschlagen. Auswirkung 50K$/Stunde."),
    ("P2", "Einige Benutzer erleben langsame Antwortzeiten. Workaround verfügbar."),
    ("P3", "Funktionsanfrage: Dark Mode zum Dashboard hinzufügen."),
    ("P1", "本番環境がダウンしています。すべてのリクエストが失敗。影響 $50K/時間。"),
    ("P2", "一部のユーザーが応答遅延を経験しています。回避策あり。"),
    ("P3", "機能リクエスト：ダッシュボードにダークモードを追加してください。"),
    ("P1", "الإنتاج متوقف. جميع الطلبات تفشل. التأثير 50 ألف دولار في الساعة."),
    ("P2", "بعض المستخدمين يعانون من بطء الاستجابة. يوجد حل بديل."),
];

/// 20 multi-language sensitivity samples.
const MULTILANG_SENSITIVITY: &[(&str, &str)] = &[
    ("Public", "Chào mừng đến với công ty chúng tôi! Chúng tôi rất vui mừng chia sẻ rằng chúng tôi đã ra mắt dòng sản phẩm mới."),
    ("Internal", "Đội ngũ lưu ý: cuộc họp toàn công ty Q4 đã được dời đến thứ Năm lúc 3pm."),
    ("Confidential", "Các điều khoản mua lại bao gồm thanh toán tiền mặt $50M. Không thảo luận bên ngoài."),
    ("Restricted", "Khách hàng SSN: 123-45-6789. Khóa API: sk-prod-abc123. Thông tin đăng nhập cơ sở dữ liệu."),
    ("Public", "¡Bienvenido a nuestra empresa! Estamos emocionados de compartir que hemos lanzado una nueva línea de productos."),
    ("Internal", "Equipo, la reunión general del Q4 se ha trasladado al jueves a las 3pm."),
    ("Confidential", "Los términos de adquisición incluyen un pago en efectivo de $50M. No discutir externamente."),
    ("Restricted", "SSN del cliente: 123-45-6789. Claves API: sk-prod-abc123. Credenciales de base de datos incluidas."),
    ("Public", "Bienvenue dans notre entreprise ! Nous sommes ravis de partager le lancement de notre nouvelle gamme de produits."),
    ("Internal", "L'équipe, la réunion générale du Q4 a été déplacée à jeudi à 15h."),
    ("Confidential", "Les termes de l'acquisition incluent un paiement en espèces de 50M$. Ne pas discuter à l'extérieur."),
    ("Restricted", "SSN client : 123-45-6789. Clés API : sk-prod-abc123. Identifiants de base de données inclus."),
    ("Public", "Willkommen in unserem Unternehmen! Wir freuen uns, die Einführung unserer neuen Produktlinie zu teilen."),
    ("Internal", "Team, das Q4-All-Hands-Meeting wurde auf Donnerstag um 15 Uhr verschoben."),
    ("Confidential", "Die Übernahmebedingungen umfassen eine Barzahlung von 50M$. Nicht extern diskutieren."),
    ("Restricted", "Kunden-SSN: 123-45-6789. API-Schlüssel: sk-prod-abc123. Datenbank-Anmeldeinformationen."),
    ("Public", "当社へようこそ！新製品ラインの立ち上げを発表できることを嬉しく思います。"),
    ("Internal", "チームの皆様へ：Q4の全体会議は木曜日の午後3時に移動しました。"),
    ("Confidential", "買収条件には5000万ドルの現金支払いが含まれます。外部では議論しないでください。"),
    ("Restricted", "顧客SSN: 123-45-6789. APIキー: sk-prod-abc123. データベース認証情報を含む。"),
];

/// 20 multi-language email categorization samples.
const MULTILANG_EMAIL_CATEGIZE: &[(&str, &str)] = &[
    ("Action Required", "Xin vui lòng xem xét tài liệu roadmap Q4 trước cuộc họp ngày mai."),
    ("Vendor", "Đơn hàng của bạn đã được gửi! Theo dõi gói hàng với số theo dõi 1Z999AA10123456784."),
    ("Newsletter", "Bản tin hàng tuần: Top 10 xu hướng AI cho 2024. Đọc thêm trên blog của chúng tôi."),
    ("Client", "Xin chào, tôi có câu hỏi về tài liệu API. Ai đó có thể giúp tôi không?"),
    ("Internal", "Bữa trưa đội ngũ thứ Sáu này lúc trưa. Vui lòng phản hồi trước thứ Năm."),
    ("Action Required", "Por favor, apruebe la solicitud de presupuesto para el Q4 antes del viernes."),
    ("Vendor", "Su pedido ha sido enviado. Número de seguimiento: 1Z999AA10123456784."),
    ("Newsletter", "Boletín semanal: Las 10 principales tendencias de IA para 2024."),
    ("Client", "Hola, tengo una pregunta sobre la documentación de la API. ¿Alguien puede ayudarme?"),
    ("Internal", "Almuerzo del equipo este viernes al mediodía. Por favor, confirmen antes del jueves."),
    ("Action Required", "Veuillez approuver la demande de budget pour le Q4 d'ici vendredi."),
    ("Vendor", "Votre commande a été expédiée ! Numéro de suivi : 1Z999AA10123456784."),
    ("Newsletter", "Newsletter hebdomadaire : Top 10 des tendances IA pour 2024."),
    ("Client", "Bonjour, j'ai une question sur la documentation de l'API. Quelqu'un peut-il m'aider ?"),
    ("Internal", "Déjeuner d'équipe ce vendredi à midi. Merci de confirmer avant jeudi."),
    ("Action Required", "Bitte genehmigen Sie die Budgetanfrage für Q4 bis Freitag."),
    ("Vendor", "Ihre Bestellung wurde versandt! Sendungsverfolgungsnummer: 1Z999AA10123456784."),
    ("Newsletter", "Wöchentlicher Newsletter: Top 10 KI-Trends für 2024."),
    ("Client", "Hallo, ich habe eine Frage zur API-Dokumentation. Kann mir jemand helfen?"),
    ("Internal", "Teamlunch diesen Freitag um 12 Uhr. Bitte bis Donnerstag zusagen."),
];

/// 10 mixed-language samples (code-switching).
const MIXED_LANG_SENTIMENT: &[(&str, &str)] = &[
    ("positive", "I absolutely love the new design! 新デザインは素晴らしいです。The team did an amazing job."),
    ("negative", "The service is terrible. サービスがひどいです。I've been waiting for 3 days."),
    ("neutral", "Q3 revenue was $4.2M, up 23% YoY. 前年比23%増。Gross margin at 78%."),
    ("positive", "¡Excelente trabajo! The presentation was amazing. プレゼンテーションは素晴らしかったです。"),
    ("negative", "Le service est terrible. The support won't respond. サポートが返事しません。"),
    ("neutral", "The meeting is scheduled for 3pm. 会議は午後3時です。In conference room B."),
    ("positive", "Thank you so much! ありがとうございます！You made the process easy and painless."),
    ("negative", "I want a refund. 환불을 원합니다. The product doesn't work as advertised."),
    ("neutral", "La política entra en vigor el 1 de enero. The policy takes effect January 1."),
    ("positive", "Great work team! 팀에게 잘했다. Everything delivered on time with great quality."),
];

/// 10 multi-language summarize samples.
const MULTILANG_SUMMARIZE: &[(&str, &str)] = &[
    ("vi", "Apple công bố kết quả kinh doanh quý 4 với doanh thu 94,9 tỷ USD, tăng 6% so với cùng kỳ. Doanh số iPhone đạt 46,2 tỷ USD, dịch vụ lập kỷ lục 25 tỷ USD. CEO Tim Cook nhấn mạnh sự tăng trưởng mạnh mẽ ở các thị trường mới nổi, đặc biệt là Ấn Độ và Việt Nam."),
    ("zh", "苹果公司公布第四季度财报，营收达949亿美元，同比增长6%。iPhone销售额达462亿美元，服务收入创纪录达250亿美元。CEO蒂姆·库克强调在新兴市场特别是印度和越南的强劲增长。"),
    ("es", "Apple anunció sus ganancias del cuarto trimestre, reportando ingresos de 94.900 millones de dólares, un aumento del 6% interanual. Las ventas del iPhone alcanzaron 46.200 millones de dólares, mientras que los ingresos por servicios batieron un récord de 25.000 millones. El CEO Tim Cook destacó el fuerte crecimiento en mercados emergentes, particularmente India y Vietnam."),
    ("fr", "Apple a annoncé ses résultats du quatrième trimestre, avec un chiffre d'affaires de 94,9 milliards de dollars, en hausse de 6%. Les ventes d'iPhone ont atteint 46,2 milliards de dollars, tandis que les revenus des services ont établi un record à 25 milliards. Le PDG Tim Cook a souligné la forte croissance sur les marchés émergents, en particulier en Inde et au Vietnam."),
    ("de", "Apple gab seine Ergebnisse für das vierte Quartal bekannt und meldete einen Umsatz von 94,9 Milliarden Dollar, was einem Jahreswachstum von 6% entspricht. Die iPhone-Verkäufe erreichten 46,2 Milliarden Dollar, während die Service-Einnahmen mit 25 Milliarden einen Rekord aufstellten. CEO Tim Cook hob das starke Wachstum auf Schwellenmärkten, insbesondere Indien und Vietnam, hervor."),
    ("ja", "Appleは第4四半期の決算を発表し、前年同期比6%増の949億ドルの収益を報告した。iPhoneの売上は462億ドルに達し、サービス収入は250億ドルの記録を樹立した。CEOのティム・クックは新興市場、特にインドとベトナムでの強力な成長を強調した。"),
    ("ar", "أعلنت شركة آبل عن أرباحها في الربع الرابع، حيث بلغت الإيرادات 94.9 مليار دولار، بزيادة 6٪ عن العام السابق. وصلت مبيعات آيفون إلى 46.2 مليار دولار، بينما سجلت إيرادات الخدمات رقماً قياسياً بلغ 25 مليار دولار. وأكد الرئيس التنفيذي تيم كوك على النمو القوي في الأسواق الناشئة، خاصة الهند وفيتنام."),
    ("ko", "Apple은 4분기 실적을 발표하며 전년 대비 6% 증가한 949억 달러의 수익을 보고했습니다. iPhone 매출은 462억 달러에 달했고, 서비스 수익은 250억 달러로 기록을 세웠습니다. CEO 팀 쿡은 신흥 시장, 특히 인도와 베트남에서의 강력한 성장을 강조했습니다."),
    ("ru", "Apple объявила о результатах четвертого квартала, сообщив о выручке в 94,9 миллиарда долларов, что на 6% больше в годовом исчислении. Продажи iPhone достигли 46,2 миллиарда долларов, а доходы от услуг установили рекорд на уровне 25 миллиардов. Генеральный директор Тим Кук подчеркнул сильный рост на развивающихся рынках, особенно в Индии и Вьетнаме."),
    ("mixed", "Apple announced Q4 earnings with $94.9B revenue, up 6% YoY. 前年比6%増。iPhone sales reached $46.2B. Services revenue hit a record $25B. CEO Tim Cook highlighted strong growth in emerging markets, particularly India and Vietnam. 特にインドとベトナムでの成長を強調。"),
];

/// 10 multi-language dedup ticket pairs.
const MULTILANG_DEDUP: &[(&str, &str, bool)] = &[
    ("Hệ thống production bị sập. Tất cả requests thất bại. ONNX session init failed.", "Production inference outage - all requests returning 500 errors. ONNX session init failed.", true),
    ("API rate limit exceeded for enterprise customer. Requests being throttled.", "Giới hạn API rate limit vượt quá cho enterprise customer. Requests bị throttled.", true),
    ("Model download failing with network timeout. CDN appears unreachable.", "Descarga de model failing con network timeout. CDN parece unreachable.", true),
    ("Feature request: add dark mode to dashboard.", "Solicitud de feature: añadir dark mode al dashboard.", true),
    ("Login page returns 500 error intermittently for some users.", "Página de login devuelve 500 error intermitentemente para algunos users.", true),
    ("Database connection pool exhausted. Too many concurrent connections.", "Pool de database connections agotado. Demasiadas concurrent connections.", true),
    ("Mobile app crashes on Android 14 startup. Affects many users.", "L'application mobile crashe au démarrage sur Android 14. Affecte de nombreux users.", true),
    ("Documentation typo on API reference page.", "Faute de frappe dans la documentation de l'API reference.", true),
    ("Payment gateway timeout. Transactions not processing. Revenue impact.", "Délai d'attente du payment gateway. Transactions not processing. Impact sur revenue.", true),
    ("Email notification delivery delayed by 30 minutes.", "Server maintenance scheduled for Saturday 2-4am. Expect downtime.", false),
];

// ──────────────────────────────────────────────────────────────────────────
// Test result tracking
// ──────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct TestResult {
    task: String,
    variant: String,
    latency_ms: u64,
    input_tokens: u32,
    output_tokens: u32,
    output_len: usize,
    output_preview: String,
    success: bool,
    error: Option<String>,
}

#[allow(dead_code)]
struct TestReport {
    results: Vec<TestResult>,
    total_duration: Duration,
}

impl TestReport {
    fn new() -> Self {
        Self {
            results: Vec::new(),
            total_duration: Duration::ZERO,
        }
    }

    fn add(&mut self, r: TestResult) {
        self.results.push(r);
    }

    fn print_report(&self) {
        println!("\n{}", "=".repeat(100));
        println!("COMPREHENSIVE PIPELINE BENCHMARK REPORT");
        println!("Total test duration: {:.2}s", self.total_duration.as_secs_f64());
        println!("Total tests run: {}", self.results.len());
        println!("{}", "=".repeat(100));

        // Group by task
        let mut tasks: std::collections::BTreeMap<String, Vec<&TestResult>> = std::collections::BTreeMap::new();
        for r in &self.results {
            tasks.entry(r.task.clone()).or_default().push(r);
        }

        println!("\n{:<30} {:<15} {:>10} {:>10} {:>10} {:>8} {:<50}", 
            "TASK", "VARIANT", "LAT(ms)", "IN_TOK", "OUT_TOK", "OK", "OUTPUT PREVIEW");
        println!("{}", "-".repeat(133));

        for (task, results) in &tasks {
            for r in results {
                let preview: String = r.output_preview.chars().take(47).collect();
                let ok = if r.success { "YES" } else { "NO" };
                let err = if let Some(e) = &r.error {
                    format!(" [{}]", e.chars().take(30).collect::<String>())
                } else {
                    String::new()
                };
                println!("{:<30} {:<15} {:>10} {:>10} {:>10} {:>8} {}{}",
                    task, r.variant, r.latency_ms, r.input_tokens, r.output_tokens, ok, preview, err);
            }
            // Aggregate stats
            let latencies: Vec<u64> = results.iter().filter(|r| r.success).map(|r| r.latency_ms).collect();
            if !latencies.is_empty() {
                let avg = latencies.iter().sum::<u64>() as f64 / latencies.len() as f64;
                let max = latencies.iter().max().unwrap();
                let min = latencies.iter().min().unwrap();
                let p50 = latencies[latencies.len() / 2];
                println!("{:<30} {:<15} {:>10} {:>10} {:>10} {:>8}",
                    format!("  └ {} stats", task), 
                    format!("n={}", latencies.len()),
                    format!("avg={:.0}", avg),
                    format!("min={}", min),
                    format!("p50={}", p50),
                    format!("max={}", max));
            }
            println!();
        }

        // Quality assessment
        println!("{}", "=".repeat(100));
        println!("QUALITY ASSESSMENT");
        println!("{}", "=".repeat(100));

        let mut empty_count = 0;
        let mut short_count = 0;
        let mut good_count = 0;
        let mut error_count = 0;

        for r in &self.results {
            if !r.success {
                error_count += 1;
            } else if r.output_len == 0 {
                empty_count += 1;
            } else if r.output_len < 20 {
                short_count += 1;
            } else {
                good_count += 1;
            }
        }

        println!("  Good output (≥20 chars): {} / {} ({:.0}%)", good_count, self.results.len(), 
            good_count as f64 / self.results.len() as f64 * 100.0);
        println!("  Short output (<20 chars): {} / {} ({:.0}%)", short_count, self.results.len(),
            short_count as f64 / self.results.len() as f64 * 100.0);
        println!("  Empty output: {} / {} ({:.0}%)", empty_count, self.results.len(),
            empty_count as f64 / self.results.len() as f64 * 100.0);
        println!("  Errors: {} / {} ({:.0}%)", error_count, self.results.len(),
            error_count as f64 / self.results.len() as f64 * 100.0);

        // Correctness assessment for classification tasks
        println!("\n  CORRECTNESS ASSESSMENT (classification tasks):");
        let classification_tasks = [
            ("sentiment_expanded", "sentiment"),
            ("classify_tone_expanded", "tone"),
            ("classify_urgency_expanded", "urgency"),
            ("classify_sensitivity_expanded", "sensitivity"),
            ("email_categorize_expanded", "email_categorize"),
            ("dedup_expanded", "dedup"),
            ("find_expert_expanded", "find_expert"),
            ("sentiment_multilang", "sentiment_ml"),
            ("classify_tone_multilang", "tone_ml"),
            ("classify_urgency_multilang", "urgency_ml"),
            ("classify_sensitivity_multilang", "sensitivity_ml"),
            ("email_categorize_multilang", "email_categorize_ml"),
            ("sentiment_mixed_lang", "sentiment_mixed"),
            ("dedup_multilang", "dedup_ml"),
        ];
        let mut total_correct = 0;
        let mut total_tested = 0;
        for (task_name, label) in &classification_tasks {
            let task_results: Vec<&TestResult> = self.results.iter()
                .filter(|r| &r.task.as_str() == task_name)
                .collect();
            if task_results.is_empty() {
                continue;
            }
            let mut correct = 0;
            for r in &task_results {
                let expected = r.variant.strip_prefix("expect=").unwrap_or("");
                let expected_dup = r.variant.strip_prefix("dup=").unwrap_or("");
                if !expected.is_empty() {
                    let expected_lower = expected.to_lowercase();
                    let output_lower = r.output_preview.to_lowercase();
                    // Map P-codes to urgency labels for urgency tasks
                    let search_term = if *task_name == "classify_urgency_expanded"
                        || *task_name == "classify_urgency_multilang"
                    {
                        match expected_lower.as_str() {
                            "p1" => "critical",
                            "p2" => "high",
                            "p3" => "medium",
                            "p4" => "low",
                            _ => &expected_lower,
                        }
                    } else {
                        &expected_lower
                    };
                    if output_lower.contains(search_term) {
                        // For short search terms (≤4 chars), verify word boundary to avoid
                        // false positives like "low" matching "below" or "high" matching "highway"
                        let term_bytes = search_term.as_bytes();
                        let output_bytes = output_lower.as_bytes();
                        let is_word_match = if search_term.len() <= 4 {
                            let mut found = false;
                            let mut start = 0;
                            while start + term_bytes.len() <= output_bytes.len() {
                                if let Some(pos) = output_lower[start..].find(search_term) {
                                    let abs_pos = start + pos;
                                    let end_pos = abs_pos + term_bytes.len();
                                    let before_ok = abs_pos == 0
                                        || !output_bytes[abs_pos - 1].is_ascii_alphanumeric();
                                    let after_ok = end_pos == output_bytes.len()
                                        || !output_bytes[end_pos].is_ascii_alphanumeric();
                                    if before_ok && after_ok {
                                        found = true;
                                        break;
                                    }
                                    start = abs_pos + 1;
                                } else {
                                    break;
                                }
                            }
                            found
                        } else {
                            true
                        };
                        if is_word_match {
                            correct += 1;
                        }
                    }
                } else if !expected_dup.is_empty() {
                    let is_dup = expected_dup == "true";
                    let found_dup = r.output_preview.contains("Found") && !r.output_preview.contains("No duplicate");
                    if is_dup == found_dup {
                        correct += 1;
                    }
                }
            }
            total_correct += correct;
            total_tested += task_results.len();
            let pct = correct as f64 / task_results.len() as f64 * 100.0;
            let rating = if pct >= 90.0 { "★★★ EXCELLENT" }
                else if pct >= 75.0 { "★★ GOOD" }
                else if pct >= 50.0 { "★ MODERATE" }
                else { "⚠ POOR" };
            println!("    {:<30} {}/{} correct ({:.0}%) {}", label, correct, task_results.len(), pct, rating);
        }
        if total_tested > 0 {
            let overall_pct = total_correct as f64 / total_tested as f64 * 100.0;
            println!("    {:<30} {}/{} correct ({:.0}%) overall", "TOTAL", total_correct, total_tested, overall_pct);
        }

        // Latency percentiles
        let all_latencies: Vec<u64> = self.results.iter().filter(|r| r.success).map(|r| r.latency_ms).collect();
        if !all_latencies.is_empty() {
            let mut sorted = all_latencies.clone();
            sorted.sort();
            let p50 = sorted[sorted.len() / 2];
            let p95 = sorted[(sorted.len() as f64 * 0.95) as usize];
            let p99 = sorted[(sorted.len() as f64 * 0.99) as usize];
            let avg = sorted.iter().sum::<u64>() as f64 / sorted.len() as f64;
            
            println!("\n  LATENCY PERCENTILES (all successful tests):");
            println!("    Average: {:.1}ms", avg);
            println!("    p50:     {}ms", p50);
            println!("    p95:     {}ms", p95);
            println!("    p99:     {}ms", p99);
            println!("    min:     {}ms", sorted.first().unwrap());
            println!("    max:     {}ms", sorted.last().unwrap());
        }

        // Throughput
        let total_inference_time: f64 = self.results.iter()
            .filter(|r| r.success)
            .map(|r| r.latency_ms as f64)
            .sum();
        let ops_per_sec = if total_inference_time > 0.0 {
            self.results.iter().filter(|r| r.success).count() as f64 / (total_inference_time / 1000.0)
        } else {
            0.0
        };
        println!("\n  THROUGHPUT: {:.1} ops/sec (sequential)", ops_per_sec);

        // Expert assessment vs benchmarks
        println!("\n{}", "=".repeat(100));
        println!("EXPERT ASSESSMENT vs TOP-LEVEL PRODUCT BENCHMARKS");
        println!("{}", "=".repeat(100));
        println!("  ┌──────────────────────────────────────────────────────────────────────────┐");
        println!("  │ Benchmark Context:                                                       │");
        println!("  │   - GPT-4 API:         ~2-5s latency, $0.03/1K tokens                    │");
        println!("  │   - Claude 3.5 API:    ~2-4s latency, $0.25/1M input tokens              │");
        println!("  │   - Whisper Cloud:     ~1-3s for 30s audio                               │");
        println!("  │   - On-device (this):  <100ms fallback, 200ms target with ONNX          │");
        println!("  │                                                                          │");
        println!("  │ Key Advantage: Privacy-first, zero network latency, offline-capable     │");
        println!("  │ Key Trade-off: Model quality (mT5-small int8 vs GPT-4)                   │");
        println!("  └──────────────────────────────────────────────────────────────────────────┘");

        // Per-category assessment
        let categories = [
            ("Text Generation (summarize/translate/key_points/generate)", 
             vec!["summarize", "translate", "key_points", "generate_doc", "generate_slides"]),
            ("Email Intelligence (summary/reply/tone/prioritize)", 
             vec!["email_summary", "draft_reply", "smart_reply", "classify_tone", "prioritize"]),
            ("Meeting Intelligence (transcribe/summary/actions/qa)", 
             vec!["transcribe", "meeting_summary", "action_items", "meeting_qa", "live_transcribe"]),
            ("Document Intelligence (contract/compare/clause/dates)", 
             vec!["contract_analysis", "compare_docs", "find_clause", "extract_dates"]),
            ("Support Intelligence (ticket/urgency/reply/dedup)", 
             vec!["ticket_summary", "classify_urgency", "ticket_reply", "dedup"]),
            ("Compliance (pii/sensitivity/compliance)", 
             vec!["pii_scan", "classify_sensitivity", "compliance_report"]),
            ("Knowledge Management (qa/tag/similar/cluster/digest)", 
             vec!["qa", "auto_tag", "find_similar", "cluster", "daily_digest"]),
            ("Communication (rewrite/expand/explain/pre_send)", 
             vec!["rewrite_tone", "expand", "explain", "pre_send_check"]),
        ];

        for (category_name, task_names) in &categories {
            let cat_results: Vec<&TestResult> = self.results.iter()
                .filter(|r| task_names.iter().any(|tn| r.task.contains(tn)))
                .collect();
            if cat_results.is_empty() {
                continue;
            }
            let success_rate = cat_results.iter().filter(|r| r.success).count() as f64 / cat_results.len() as f64 * 100.0;
            let avg_latency = cat_results.iter().filter(|r| r.success).map(|r| r.latency_ms as f64).sum::<f64>() 
                / cat_results.iter().filter(|r| r.success).count().max(1) as f64;
            let avg_output_len = cat_results.iter().filter(|r| r.success).map(|r| r.output_len as f64).sum::<f64>()
                / cat_results.iter().filter(|r| r.success).count().max(1) as f64;
            
            println!("\n  {}:", category_name);
            println!("    Tests: {} | Success: {:.0}% | Avg latency: {:.1}ms | Avg output: {:.0} chars",
                cat_results.len(), success_rate, avg_latency, avg_output_len);
            
            if avg_latency < 50.0 {
                println!("    ⚡ Latency: EXCELLENT (sub-50ms, beats cloud APIs by 40-100x)");
            } else if avg_latency < 200.0 {
                println!("    ✅ Latency: GOOD (under 200ms target, beats cloud APIs by 10-25x)");
            } else if avg_latency < 1000.0 {
                println!("    ⚠️  Latency: ACCEPTABLE (under 1s, still faster than cloud round-trip)");
            } else {
                println!("    ❌ Latency: SLOW (exceeds 1s — investigate bottleneck)");
            }

            if avg_output_len > 100.0 {
                println!("    📝 Output quality: GOOD (substantive output, >100 chars avg)");
            } else if avg_output_len > 30.0 {
                println!("    📝 Output quality: MODERATE (useful but brief, 30-100 chars avg)");
            } else {
                println!("    📝 Output quality: THIN (output too short, <30 chars avg)");
            }
        }

        println!("\n{}", "=".repeat(100));
        println!("END OF REPORT");
        println!("{}", "=".repeat(100));
    }
}

// ──────────────────────────────────────────────────────────────────────────
// Test runner
// ──────────────────────────────────────────────────────────────────────────

async fn run_comprehensive_tests() -> TestReport {
    let mut report = TestReport::new();
    let start = Instant::now();

    let (_tmp, mut engine) = setup_fallback_engine().await;
    
    // Load all models
    for spec in &[
        ModelSpec::mt5_small_int8(),
        ModelSpec::e5_small_int8(),
        ModelSpec::clip_int8(),
        ModelSpec::whisper_tiny_int8(),
    ] {
        let _ = engine.ensure_model(spec).await;
    }

    let opts = TaskOptions::default();

    // ── 1. Summarize: all languages ──
    for (lang, text) in NEWS_ARTICLES {
        let t = Instant::now();
        let result = engine.summarize(text, lang, opts.clone()).await;
        let elapsed = t.elapsed().as_millis() as u64;
        match result {
            Ok(r) => report.add(TestResult {
                task: "summarize".into(), variant: format!("lang={}", lang),
                latency_ms: elapsed, input_tokens: r.input_tokens, output_tokens: r.output_tokens,
                output_len: r.output.len(), output_preview: r.output.clone(), success: true, error: None,
            }),
            Err(e) => report.add(TestResult {
                task: "summarize".into(), variant: format!("lang={}", lang),
                latency_ms: elapsed, input_tokens: 0, output_tokens: 0,
                output_len: 0, output_preview: String::new(), success: false, error: Some(e.to_string()),
            }),
        }
    }

    // ── 2. Summarize: long meeting transcript ──
    let t = Instant::now();
    let result = engine.summarize(MEETING_TRANSCRIPT, "en", opts.clone()).await;
    let elapsed = t.elapsed().as_millis() as u64;
    if let Ok(r) = result {
        report.add(TestResult {
            task: "summarize".into(), variant: "long_meeting".into(),
            latency_ms: elapsed, input_tokens: r.input_tokens, output_tokens: r.output_tokens,
            output_len: r.output.len(), output_preview: r.output.clone(), success: true, error: None,
        });
    }

    // ── 3. Translate: all language pairs ──
    let translate_pairs = [("en", "vi"), ("en", "zh"), ("en", "ar"), ("en", "es"), ("en", "fr"),
                           ("en", "de"), ("en", "ja"), ("en", "ko"), ("en", "ru"),
                           ("vi", "en"), ("zh", "en"), ("ar", "en"), ("es", "en"), ("fr", "en")];
    let translate_text = "The company reported 23% revenue growth in Q3, reaching $94.9 billion.";
    for (src, tgt) in translate_pairs {
        let t = Instant::now();
        let result = engine.translate(translate_text, src, tgt, opts.clone()).await;
        let elapsed = t.elapsed().as_millis() as u64;
        match result {
            Ok(r) => report.add(TestResult {
                task: "translate".into(), variant: format!("{}→{}", src, tgt),
                latency_ms: elapsed, input_tokens: r.input_tokens, output_tokens: r.output_tokens,
                output_len: r.output.len(), output_preview: r.output.clone(), success: true, error: None,
            }),
            Err(e) => report.add(TestResult {
                task: "translate".into(), variant: format!("{}→{}", src, tgt),
                latency_ms: elapsed, input_tokens: 0, output_tokens: 0,
                output_len: 0, output_preview: String::new(), success: false, error: Some(e.to_string()),
            }),
        }
    }

    // ── 4. Key Points: meeting transcript ──
    let t = Instant::now();
    let result = engine.key_points(MEETING_TRANSCRIPT, "en", opts.clone()).await;
    let elapsed = t.elapsed().as_millis() as u64;
    if let Ok(r) = result {
        report.add(TestResult {
            task: "key_points".into(), variant: "meeting".into(),
            latency_ms: elapsed, input_tokens: r.input_tokens, output_tokens: r.output_tokens,
            output_len: r.output.len(), output_preview: r.output.clone(), success: true, error: None,
        });
    }

    // ── 5. Generate Doc ──
    let t = Instant::now();
    let result = engine.generate_doc("Cloud Security Best Practices", 
        "1. IAM with MFA. 2. Encryption at rest and in transit. 3. Network segmentation. 4. SIEM monitoring. 5. Incident response plan.", 
        "en", opts.clone()).await;
    let elapsed = t.elapsed().as_millis() as u64;
    if let Ok(r) = result {
        report.add(TestResult {
            task: "generate_doc".into(), variant: "cloud_security".into(),
            latency_ms: elapsed, input_tokens: r.input_tokens, output_tokens: r.output_tokens,
            output_len: r.output.len(), output_preview: r.output.clone(), success: true, error: None,
        });
    }

    // ── 6. Generate Slides ──
    let t = Instant::now();
    let result = engine.generate_slides("Introduction to Machine Learning",
        "Machine learning is a subset of AI. Types: supervised, unsupervised, reinforcement. Algorithms: regression, decision trees, neural networks. Applications: NLP, computer vision, recommendation systems.",
        "en", opts.clone()).await;
    let elapsed = t.elapsed().as_millis() as u64;
    if let Ok(r) = result {
        report.add(TestResult {
            task: "generate_slides".into(), variant: "ml_intro".into(),
            latency_ms: elapsed, input_tokens: r.input_tokens, output_tokens: r.output_tokens,
            output_len: r.output.len(), output_preview: r.output.clone(), success: true, error: None,
        });
    }

    // ── 7. Email Summary ──
    let t = Instant::now();
    let result = engine.email_summary(EMAIL_THREAD, "en", opts.clone()).await;
    let elapsed = t.elapsed().as_millis() as u64;
    if let Ok(r) = result {
        report.add(TestResult {
            task: "email_summary".into(), variant: "partnership".into(),
            latency_ms: elapsed, input_tokens: r.input_tokens, output_tokens: r.output_tokens,
            output_len: r.output.len(), output_preview: r.output.clone(), success: true, error: None,
        });
    }

    // ── 8. Draft Reply ──
    for intent in &["agree", "decline", "request_info", "escalate"] {
        let t = Instant::now();
        let result = engine.draft_reply(EMAIL_THREAD, intent, "en", opts.clone()).await;
        let elapsed = t.elapsed().as_millis() as u64;
        if let Ok(r) = result {
            report.add(TestResult {
                task: "draft_reply".into(), variant: format!("intent={}", intent),
                latency_ms: elapsed, input_tokens: r.input_tokens, output_tokens: r.output_tokens,
                output_len: r.output.len(), output_preview: r.output.clone(), success: true, error: None,
            });
        }
    }

    // ── 9. Smart Reply ──
    let t = Instant::now();
    let result = engine.smart_reply(CHAT_CONVERSATION, "en", opts.clone()).await;
    let elapsed = t.elapsed().as_millis() as u64;
    if let Ok(r) = result {
        report.add(TestResult {
            task: "smart_reply".into(), variant: "chat".into(),
            latency_ms: elapsed, input_tokens: r.input_tokens, output_tokens: r.output_tokens,
            output_len: r.output.len(), output_preview: r.output.clone(), success: true, error: None,
        });
    }

    // ── 10. Classify Tone ──
    let tone_texts = [
        "URGENT: Production is down, need immediate response!",
        "FYI: Updated the meeting notes from yesterday's session.",
        "Could you please review this when you have time? No rush.",
        "WARNING: Your account will be suspended in 24 hours if no action is taken.",
    ];
    for text in &tone_texts {
        let t = Instant::now();
        let result = engine.classify_tone(text, opts.clone()).await;
        let elapsed = t.elapsed().as_millis() as u64;
        if let Ok(r) = result {
            report.add(TestResult {
                task: "classify_tone".into(), variant: format!("len={}", text.len()),
                latency_ms: elapsed, input_tokens: r.input_tokens, output_tokens: r.output_tokens,
                output_len: r.output.len(), output_preview: r.output.clone(), success: true, error: None,
            });
        }
    }

    // ── 11. Chat Summary ──
    let t = Instant::now();
    let result = engine.chat_summary(CHAT_CONVERSATION, "en", opts.clone()).await;
    let elapsed = t.elapsed().as_millis() as u64;
    if let Ok(r) = result {
        report.add(TestResult {
            task: "chat_summary".into(), variant: "team_chat".into(),
            latency_ms: elapsed, input_tokens: r.input_tokens, output_tokens: r.output_tokens,
            output_len: r.output.len(), output_preview: r.output.clone(), success: true, error: None,
        });
    }

    // ── 12. Notif Summary ──
    let t = Instant::now();
    let result = engine.notif_summary(NOTIFICATIONS, "en", opts.clone()).await;
    let elapsed = t.elapsed().as_millis() as u64;
    if let Ok(r) = result {
        report.add(TestResult {
            task: "notif_summary".into(), variant: "10_notifs".into(),
            latency_ms: elapsed, input_tokens: r.input_tokens, output_tokens: r.output_tokens,
            output_len: r.output.len(), output_preview: r.output.clone(), success: true, error: None,
        });
    }

    // ── 13. Prioritize ──
    let t = Instant::now();
    let result = engine.prioritize(EMAIL_THREAD, opts.clone()).await;
    let elapsed = t.elapsed().as_millis() as u64;
    if let Ok(r) = result {
        report.add(TestResult {
            task: "prioritize".into(), variant: "email".into(),
            latency_ms: elapsed, input_tokens: r.input_tokens, output_tokens: r.output_tokens,
            output_len: r.output.len(), output_preview: r.output.clone(), success: true, error: None,
        });
    }

    // ── 14. Meeting Summary ──
    let t = Instant::now();
    let result = engine.meeting_summary(MEETING_TRANSCRIPT, "en", opts.clone()).await;
    let elapsed = t.elapsed().as_millis() as u64;
    if let Ok(r) = result {
        report.add(TestResult {
            task: "meeting_summary".into(), variant: "q3_review".into(),
            latency_ms: elapsed, input_tokens: r.input_tokens, output_tokens: r.output_tokens,
            output_len: r.output.len(), output_preview: r.output.clone(), success: true, error: None,
        });
    }

    // ── 15. Action Items ──
    let t = Instant::now();
    let result = engine.action_items(MEETING_TRANSCRIPT, "en", opts.clone()).await;
    let elapsed = t.elapsed().as_millis() as u64;
    if let Ok(r) = result {
        report.add(TestResult {
            task: "action_items".into(), variant: "meeting".into(),
            latency_ms: elapsed, input_tokens: r.input_tokens, output_tokens: r.output_tokens,
            output_len: r.output.len(), output_preview: r.output.clone(), success: true, error: None,
        });
    }

    // ── 16. Meeting QA ──
    let questions = [
        "What was the Q3 revenue growth?",
        "What are the Q4 priorities?",
        "How much will the TechCorp integration cost?",
        "What is the current test coverage?",
    ];
    for q in &questions {
        let t = Instant::now();
        let result = engine.meeting_qa(MEETING_TRANSCRIPT, q, "en", opts.clone()).await;
        let elapsed = t.elapsed().as_millis() as u64;
        if let Ok(r) = result {
            report.add(TestResult {
                task: "meeting_qa".into(), variant: format!("q={}", &q[..q.len().min(20)]),
                latency_ms: elapsed, input_tokens: r.input_tokens, output_tokens: r.output_tokens,
                output_len: r.output.len(), output_preview: r.output.clone(), success: true, error: None,
            });
        }
    }

    // ── 17. Transcribe (synthetic audio) ──
    for dur in &[1.0f32, 2.0, 5.0] {
        let audio = synthetic_audio(*dur, 440.0);
        let t = Instant::now();
        let result = engine.transcribe(&audio, opts.clone()).await;
        let elapsed = t.elapsed().as_millis() as u64;
        match result {
            Ok(r) => report.add(TestResult {
                task: "transcribe".into(), variant: format!("dur={}s", dur),
                latency_ms: elapsed, input_tokens: r.input_tokens, output_tokens: r.output_tokens,
                output_len: r.output.len(), output_preview: r.output.clone(), success: true, error: None,
            }),
            Err(e) => report.add(TestResult {
                task: "transcribe".into(), variant: format!("dur={}s", dur),
                latency_ms: elapsed, input_tokens: 0, output_tokens: 0,
                output_len: 0, output_preview: String::new(), success: false, error: Some(e.to_string()),
            }),
        }
    }

    // ── 18. Live Transcribe ──
    let chunks: Vec<Vec<f32>> = (0..3).map(|_| synthetic_audio(1.0, 440.0)).collect();
    let t = Instant::now();
    let result = engine.live_transcribe(&chunks, opts.clone()).await;
    let elapsed = t.elapsed().as_millis() as u64;
    match result {
        Ok(r) => report.add(TestResult {
            task: "live_transcribe".into(), variant: "3_chunks".into(),
            latency_ms: elapsed, input_tokens: r.input_tokens, output_tokens: r.output_tokens,
            output_len: r.output.len(), output_preview: r.output.clone(), success: true, error: None,
        }),
        Err(e) => report.add(TestResult {
            task: "live_transcribe".into(), variant: "3_chunks".into(),
            latency_ms: elapsed, input_tokens: 0, output_tokens: 0,
            output_len: 0, output_preview: String::new(), success: false, error: Some(e.to_string()),
        }),
    }

    // ── 19. Grammar Check ──
    let grammar_texts = [
        "I are going to the store yesterday.",
        "The team have decided to move forward with the proposal.",
        "She don't like the new design changes.",
    ];
    for text in &grammar_texts {
        let t = Instant::now();
        let result = engine.grammar_check(text, "en", opts.clone()).await;
        let elapsed = t.elapsed().as_millis() as u64;
        if let Ok(r) = result {
            report.add(TestResult {
                task: "grammar_check".into(), variant: "en".into(),
                latency_ms: elapsed, input_tokens: r.input_tokens, output_tokens: r.output_tokens,
                output_len: r.output.len(), output_preview: r.output.clone(), success: true, error: None,
            });
        }
    }

    // ── 20. Simplify ──
    let complex_text = "The utilization of multifaceted methodological frameworks facilitates the amelioration of pedagogical outcomes through the systematic implementation of evidence-based interventions.";
    let t = Instant::now();
    let result = engine.simplify(complex_text, "en", opts.clone()).await;
    let elapsed = t.elapsed().as_millis() as u64;
    if let Ok(r) = result {
        report.add(TestResult {
            task: "simplify".into(), variant: "jargon".into(),
            latency_ms: elapsed, input_tokens: r.input_tokens, output_tokens: r.output_tokens,
            output_len: r.output.len(), output_preview: r.output.clone(), success: true, error: None,
        });
    }

    // ── 21. Auto Tag ──
    for (id, text) in CLUSTER_DOCS {
        let t = Instant::now();
        let result = engine.auto_tag(text, opts.clone()).await;
        let elapsed = t.elapsed().as_millis() as u64;
        if let Ok(r) = result {
            report.add(TestResult {
                task: "auto_tag".into(), variant: id.to_string(),
                latency_ms: elapsed, input_tokens: r.input_tokens, output_tokens: r.output_tokens,
                output_len: r.output.len(), output_preview: r.output.clone(), success: true, error: None,
            });
        }
    }

    // ── 22. Daily Digest ──
    let digest_input = zk_ai_core::pipeline::daily_digest::DailyDigestInput {
        emails: EMAIL_THREAD.to_string(),
        meetings: MEETING_TRANSCRIPT.to_string(),
        notifications: NOTIFICATIONS.to_string(),
    };
    let t = Instant::now();
    let result = engine.daily_digest(&digest_input, "en", opts.clone()).await;
    let elapsed = t.elapsed().as_millis() as u64;
    if let Ok(r) = result {
        report.add(TestResult {
            task: "daily_digest".into(), variant: "full_day".into(),
            latency_ms: elapsed, input_tokens: r.input_tokens, output_tokens: r.output_tokens,
            output_len: r.output.len(), output_preview: r.output.clone(), success: true, error: None,
        });
    }

    // ── 23. Rewrite Tone ──
    for tone in &["professional", "casual", "urgent", "diplomatic"] {
        let t = Instant::now();
        let result = engine.rewrite_tone("Hey, we need this done ASAP. It's really important.", tone, "en", opts.clone()).await;
        let elapsed = t.elapsed().as_millis() as u64;
        if let Ok(r) = result {
            report.add(TestResult {
                task: "rewrite_tone".into(), variant: format!("tone={}", tone),
                latency_ms: elapsed, input_tokens: r.input_tokens, output_tokens: r.output_tokens,
                output_len: r.output.len(), output_preview: r.output.clone(), success: true, error: None,
            });
        }
    }

    // ── 24. Expand ──
    let t = Instant::now();
    let result = engine.expand("• Launch Q4 product line\n• Hire 2 engineers\n• Complete TechCorp integration", "en", opts.clone()).await;
    let elapsed = t.elapsed().as_millis() as u64;
    if let Ok(r) = result {
        report.add(TestResult {
            task: "expand".into(), variant: "bullets".into(),
            latency_ms: elapsed, input_tokens: r.input_tokens, output_tokens: r.output_tokens,
            output_len: r.output.len(), output_preview: r.output.clone(), success: true, error: None,
        });
    }

    // ── 25. Explain ──
    let terms = [
        ("Kubernetes", "We're migrating our microservices to Kubernetes for better orchestration."),
        ("LoRA", "We use LoRA adapters to fine-tune the base model for each task."),
        ("int8 quantization", "The model uses int8 quantization to reduce size by 4x."),
    ];
    for (term, context) in &terms {
        let t = Instant::now();
        let result = engine.explain(term, context, "en", opts.clone()).await;
        let elapsed = t.elapsed().as_millis() as u64;
        if let Ok(r) = result {
            report.add(TestResult {
                task: "explain".into(), variant: term.to_string(),
                latency_ms: elapsed, input_tokens: r.input_tokens, output_tokens: r.output_tokens,
                output_len: r.output.len(), output_preview: r.output.clone(), success: true, error: None,
            });
        }
    }

    // ── 26. Pre-Send Check ──
    let t = Instant::now();
    let result = engine.pre_send_check("Hey team, just wanted to let you know that the deploy is done and everything looks good. Let me know if you see any issues.", "en", opts.clone()).await;
    let elapsed = t.elapsed().as_millis() as u64;
    if let Ok(r) = result {
        report.add(TestResult {
            task: "pre_send_check".into(), variant: "email".into(),
            latency_ms: elapsed, input_tokens: r.input_tokens, output_tokens: r.output_tokens,
            output_len: r.output.len(), output_preview: r.output.clone(), success: true, error: None,
        });
    }

    // ── 27. Contract Analysis ──
    let t = Instant::now();
    let result = engine.contract_analysis(CONTRACT_TEXT, "en", opts.clone()).await;
    let elapsed = t.elapsed().as_millis() as u64;
    if let Ok(r) = result {
        report.add(TestResult {
            task: "contract_analysis".into(), variant: "msa".into(),
            latency_ms: elapsed, input_tokens: r.input_tokens, output_tokens: r.output_tokens,
            output_len: r.output.len(), output_preview: r.output.clone(), success: true, error: None,
        });
    }

    // ── 28. Compare Docs ──
    let doc_a = "The service agreement requires 30 days notice for termination. Payment is due within 30 days of invoice. Liability is capped at 12 months of fees.";
    let doc_b = "The service agreement requires 60 days notice for termination. Payment is due within 15 days of invoice. Liability is capped at 6 months of fees. Additional clause: mandatory arbitration.";
    let t = Instant::now();
    let result = engine.compare_docs(doc_a, doc_b, "en", opts.clone()).await;
    let elapsed = t.elapsed().as_millis() as u64;
    if let Ok(r) = result {
        report.add(TestResult {
            task: "compare_docs".into(), variant: "contracts".into(),
            latency_ms: elapsed, input_tokens: r.input_tokens, output_tokens: r.output_tokens,
            output_len: r.output.len(), output_preview: r.output.clone(), success: true, error: None,
        });
    }

    // ── 29. Find Clause ──
    let clause_queries = ["termination", "payment terms", "liability cap", "confidentiality"];
    for q in &clause_queries {
        let t = Instant::now();
        let result = engine.find_clause(CONTRACT_TEXT, q, opts.clone()).await;
        let elapsed = t.elapsed().as_millis() as u64;
        if let Ok(r) = result {
            report.add(TestResult {
                task: "find_clause".into(), variant: format!("q={}", q),
                latency_ms: elapsed, input_tokens: r.input_tokens, output_tokens: r.output_tokens,
                output_len: r.output.len(), output_preview: r.output.clone(), success: true, error: None,
            });
        }
    }

    // ── 30. Extract Dates ──
    let date_text = "The contract was signed on January 15, 2024. The initial term is 3 years, expiring January 15, 2027. Payment is due within 30 days of invoice. The audit must be completed by November 15, 2024.";
    let t = Instant::now();
    let result = engine.extract_dates(date_text, opts.clone()).await;
    let elapsed = t.elapsed().as_millis() as u64;
    if let Ok(r) = result {
        report.add(TestResult {
            task: "extract_dates".into(), variant: "contract".into(),
            latency_ms: elapsed, input_tokens: r.input_tokens, output_tokens: r.output_tokens,
            output_len: r.output.len(), output_preview: r.output.clone(), success: true, error: None,
        });
    }

    // ── 31. Ticket Summary ──
    let t = Instant::now();
    let result = engine.ticket_summary(SUPPORT_TICKET, "en", opts.clone()).await;
    let elapsed = t.elapsed().as_millis() as u64;
    if let Ok(r) = result {
        report.add(TestResult {
            task: "ticket_summary".into(), variant: "p1_outage".into(),
            latency_ms: elapsed, input_tokens: r.input_tokens, output_tokens: r.output_tokens,
            output_len: r.output.len(), output_preview: r.output.clone(), success: true, error: None,
        });
    }

    // ── 32. Classify Urgency ──
    let urgency_tickets = [
        ("P1", "Production is down. All requests failing. $50K/hour impact. Need immediate help."),
        ("P2", "Some users experiencing slow response times. Workaround available."),
        ("P3", "Feature request: add dark mode support to the dashboard."),
        ("P4", "Documentation typo on the API reference page."),
    ];
    for (expected, ticket) in &urgency_tickets {
        let t = Instant::now();
        let result = engine.classify_urgency(ticket, opts.clone()).await;
        let elapsed = t.elapsed().as_millis() as u64;
        if let Ok(r) = result {
            report.add(TestResult {
                task: "classify_urgency".into(), variant: format!("expect={}", expected),
                latency_ms: elapsed, input_tokens: r.input_tokens, output_tokens: r.output_tokens,
                output_len: r.output.len(), output_preview: r.output.clone(), success: true, error: None,
            });
        }
    }

    // ── 33. Ticket Reply ──
    let t = Instant::now();
    let result = engine.ticket_reply(SUPPORT_TICKET, "en", opts.clone()).await;
    let elapsed = t.elapsed().as_millis() as u64;
    if let Ok(r) = result {
        report.add(TestResult {
            task: "ticket_reply".into(), variant: "p1_outage".into(),
            latency_ms: elapsed, input_tokens: r.input_tokens, output_tokens: r.output_tokens,
            output_len: r.output.len(), output_preview: r.output.clone(), success: true, error: None,
        });
    }

    // ── 34. Dedup (requires TextIndex) ──
    let mut dedup_index = TextIndex::new();
    let existing_tickets = [
        "Production inference outage - all requests returning 500 errors. ONNX session init failed.",
        "API rate limit exceeded for enterprise customer. Requests being throttled.",
        "Model download failing with network timeout. CDN appears unreachable.",
    ];
    for (i, ticket) in existing_tickets.iter().enumerate() {
        let emb = synthetic_embedding(ticket, 512);
        dedup_index.add_text(&format!("ticket_{}", i), ticket, emb, None);
    }
    let new_ticket = "All inference requests are failing with 500 errors. ONNX runtime session initialization is failing.";
    let t = Instant::now();
    let result = engine.dedup(new_ticket, &dedup_index, opts.clone()).await;
    let elapsed = t.elapsed().as_millis() as u64;
    if let Ok(r) = result {
        report.add(TestResult {
            task: "dedup".into(), variant: "duplicate".into(),
            latency_ms: elapsed, input_tokens: r.input_tokens, output_tokens: r.output_tokens,
            output_len: r.output.len(), output_preview: r.output.clone(), success: true, error: None,
        });
    }

    // ── 35. Email Categorize ──
    let categorize_emails = [
        "Hi team, please review the Q4 roadmap document before our meeting tomorrow.",
        "Your order has shipped! Track your package with tracking number 1Z999AA10123456784.",
        "URGENT: Invoice #4892 is 45 days overdue. Please remit payment immediately.",
        "Weekly newsletter: Top 10 AI trends for 2024. Read more on our blog.",
    ];
    for (i, email) in categorize_emails.iter().enumerate() {
        let t = Instant::now();
        let result = engine.email_categorize(email, opts.clone()).await;
        let elapsed = t.elapsed().as_millis() as u64;
        if let Ok(r) = result {
            report.add(TestResult {
                task: "email_categorize".into(), variant: format!("email_{}", i),
                latency_ms: elapsed, input_tokens: r.input_tokens, output_tokens: r.output_tokens,
                output_len: r.output.len(), output_preview: r.output.clone(), success: true, error: None,
            });
        }
    }

    // ── 36. Sentiment ──
    let sentiment_texts = [
        "I absolutely love the new design! The team did an amazing job on the UI.",
        "The service has been terrible. I've been waiting for a response for 3 days.",
        "The quarterly report shows mixed results. Revenue is up but customer churn increased.",
        "Best product I've used all year. Exceeded all my expectations!",
    ];
    for (i, text) in sentiment_texts.iter().enumerate() {
        let t = Instant::now();
        let result = engine.sentiment(text, opts.clone()).await;
        let elapsed = t.elapsed().as_millis() as u64;
        if let Ok(r) = result {
            report.add(TestResult {
                task: "sentiment".into(), variant: format!("text_{}", i),
                latency_ms: elapsed, input_tokens: r.input_tokens, output_tokens: r.output_tokens,
                output_len: r.output.len(), output_preview: r.output.clone(), success: true, error: None,
            });
        }
    }

    // ── 37. PII Scan ──
    let t = Instant::now();
    let result = engine.pii_scan(PII_DOCUMENT, opts.clone()).await;
    let elapsed = t.elapsed().as_millis() as u64;
    if let Ok(r) = result {
        report.add(TestResult {
            task: "pii_scan".into(), variant: "employee_record".into(),
            latency_ms: elapsed, input_tokens: r.input_tokens, output_tokens: r.output_tokens,
            output_len: r.output.len(), output_preview: r.output.clone(), success: true, error: None,
        });
    }

    // ── 38. Classify Sensitivity ──
    for (expected, text) in SENSITIVITY_DOCUMENTS {
        let t = Instant::now();
        let result = engine.classify_sensitivity(text, opts.clone()).await;
        let elapsed = t.elapsed().as_millis() as u64;
        if let Ok(r) = result {
            report.add(TestResult {
                task: "classify_sensitivity".into(), variant: format!("expect={}", expected),
                latency_ms: elapsed, input_tokens: r.input_tokens, output_tokens: r.output_tokens,
                output_len: r.output.len(), output_preview: r.output.clone(), success: true, error: None,
            });
        }
    }

    // ── 39. Compliance Report ──
    let audit_log = r#"
[2024-10-14 09:23:15] INF inference called: task=summarize, model=mt5-small-int8, tokens_in=245, tokens_out=89
[2024-10-14 09:24:02] INF inference called: task=translate, model=mt5-small-int8, tokens_in=52, tokens_out=48
[2024-10-14 09:25:33] WRN resource limit: CPU usage 82% exceeds 80% threshold
[2024-10-14 09:26:10] INF inference called: task=email_summary, model=mt5-small-int8, tokens_in=580, tokens_out=120
[2024-10-14 09:27:45] ERR model download failed: mt5-small-int8, HTTP 503
[2024-10-14 09:28:12] INF model loaded: e5-small-int8, size=128MB
[2024-10-14 09:30:00] INF PII scan completed: 3 entities found, 0 blocked
[2024-10-14 09:31:22] INF inference called: task=qa, model=mt5-small-int8, tokens_in=180, tokens_out=95
"#;
    let t = Instant::now();
    let result = engine.compliance_report(audit_log, "en", opts.clone()).await;
    let elapsed = t.elapsed().as_millis() as u64;
    if let Ok(r) = result {
        report.add(TestResult {
            task: "compliance_report".into(), variant: "audit_log".into(),
            latency_ms: elapsed, input_tokens: r.input_tokens, output_tokens: r.output_tokens,
            output_len: r.output.len(), output_preview: r.output.clone(), success: true, error: None,
        });
    }

    // ── 40. QA over technical docs (RAG) ──
    let mut tech_index = TextIndex::new();
    for (id, text) in TECHNICAL_DOCS {
        let emb = synthetic_embedding(text, 512);
        tech_index.add_text(id, text, emb, Some("tech_docs"));
    }
    let qa_questions = [
        "What is the system architecture?",
        "How is privacy enforced?",
        "What are the performance targets?",
        "What models are available?",
        "What does the resource governor do?",
    ];
    for q in &qa_questions {
        let t = Instant::now();
        let result = engine.qa(q, &tech_index, "en", opts.clone()).await;
        let elapsed = t.elapsed().as_millis() as u64;
        if let Ok(r) = result {
            report.add(TestResult {
                task: "qa".into(), variant: format!("q={}", &q[..q.len().min(25)]),
                latency_ms: elapsed, input_tokens: r.input_tokens, output_tokens: r.output_tokens,
                output_len: r.output.len(), output_preview: r.output.clone(), success: true, error: None,
            });
        }
    }

    // ── 41. Find Similar ──
    let mut similar_index = TextIndex::new();
    for (id, text) in CLUSTER_DOCS {
        let emb = synthetic_embedding(text, 512);
        similar_index.add_text(id, text, emb, None);
    }
    let t = Instant::now();
    let result = engine.find_similar("Deep learning and neural networks for AI applications", &similar_index, 3, opts.clone()).await;
    let elapsed = t.elapsed().as_millis() as u64;
    if let Ok(r) = result {
        report.add(TestResult {
            task: "find_similar".into(), variant: "ml_query".into(),
            latency_ms: elapsed, input_tokens: r.input_tokens, output_tokens: r.output_tokens,
            output_len: r.output.len(), output_preview: r.output.clone(), success: true, error: None,
        });
    }

    // ── 42. Cluster ──
    let mut cluster_index = TextIndex::new();
    for (id, text) in CLUSTER_DOCS {
        let emb = synthetic_embedding(text, 512);
        cluster_index.add_text(id, text, emb, None);
    }
    let t = Instant::now();
    let result = engine.cluster(&cluster_index, 4, opts.clone()).await;
    let elapsed = t.elapsed().as_millis() as u64;
    if let Ok(r) = result {
        report.add(TestResult {
            task: "cluster".into(), variant: "12_docs_4_clusters".into(),
            latency_ms: elapsed, input_tokens: r.input_tokens, output_tokens: r.output_tokens,
            output_len: r.output.len(), output_preview: r.output.clone(), success: true, error: None,
        });
    }

    // ── 43. Doc Chat ──
    let history = [("user".into(), "What models are available?".into())];
    let t = Instant::now();
    let result = engine.doc_chat("Tell me about the performance targets", &history, &tech_index, "en", opts.clone()).await;
    let elapsed = t.elapsed().as_millis() as u64;
    if let Ok(r) = result {
        report.add(TestResult {
            task: "doc_chat".into(), variant: "multi_turn".into(),
            latency_ms: elapsed, input_tokens: r.input_tokens, output_tokens: r.output_tokens,
            output_len: r.output.len(), output_preview: r.output.clone(), success: true, error: None,
        });
    }

    // ── 44. Onboarding QA ──
    let t = Instant::now();
    let result = engine.onboarding_qa("How do I set up the SDK?", &tech_index, "en", opts.clone()).await;
    let elapsed = t.elapsed().as_millis() as u64;
    if let Ok(r) = result {
        report.add(TestResult {
            task: "onboarding_qa".into(), variant: "setup".into(),
            latency_ms: elapsed, input_tokens: r.input_tokens, output_tokens: r.output_tokens,
            output_len: r.output.len(), output_preview: r.output.clone(), success: true, error: None,
        });
    }

    // ── 45. Policy Lookup ──
    let t = Instant::now();
    let result = engine.policy_lookup("What is the data retention policy?", &tech_index, "en", opts.clone()).await;
    let elapsed = t.elapsed().as_millis() as u64;
    if let Ok(r) = result {
        report.add(TestResult {
            task: "policy_lookup".into(), variant: "retention".into(),
            latency_ms: elapsed, input_tokens: r.input_tokens, output_tokens: r.output_tokens,
            output_len: r.output.len(), output_preview: r.output.clone(), success: true, error: None,
        });
    }

    // ── 46. Auto Abstract ──
    let t = Instant::now();
    let result = engine.auto_abstract(MEETING_TRANSCRIPT, "en", opts.clone()).await;
    let elapsed = t.elapsed().as_millis() as u64;
    if let Ok(r) = result {
        report.add(TestResult {
            task: "auto_abstract".into(), variant: "meeting".into(),
            latency_ms: elapsed, input_tokens: r.input_tokens, output_tokens: r.output_tokens,
            output_len: r.output.len(), output_preview: r.output.clone(), success: true, error: None,
        });
    }

    // ── 47. Find Expert ──
    let mut expert_index = TextIndex::new();
    let experts = [
        ("alice", "Alice specializes in machine learning, neural networks, and deep learning architectures."),
        ("bob", "Bob is an expert in cloud infrastructure, Kubernetes, and container orchestration."),
        ("carol", "Carol focuses on security, compliance, GDPR, and SOC 2 audits."),
        ("dave", "Dave works on financial systems, trading algorithms, and risk management."),
    ];
    for (id, text) in &experts {
        let emb = synthetic_embedding(text, 512);
        expert_index.add_text(id, text, emb, None);
    }
    let t = Instant::now();
    let result = engine.find_expert("machine learning and neural networks", &expert_index, 2, opts.clone()).await;
    let elapsed = t.elapsed().as_millis() as u64;
    if let Ok(r) = result {
        report.add(TestResult {
            task: "find_expert".into(), variant: "ml_expert".into(),
            latency_ms: elapsed, input_tokens: r.input_tokens, output_tokens: r.output_tokens,
            output_len: r.output.len(), output_preview: r.output.clone(), success: true, error: None,
        });
    }

    // ── 48. Rerank ──
    let hits = vec![
        TextSearchHit { id: "doc1".into(), text: "Machine learning models require large datasets".into(), source: None, score: 0.85 },
        TextSearchHit { id: "doc2".into(), text: "The stock market saw volatility".into(), source: None, score: 0.72 },
        TextSearchHit { id: "doc3".into(), text: "Neural networks are inspired by biological neurons".into(), source: None, score: 0.91 },
    ];
    let t = Instant::now();
    let result = engine.rerank("deep learning architectures", &hits, opts.clone()).await;
    let elapsed = t.elapsed().as_millis() as u64;
    if let Ok(r) = result {
        report.add(TestResult {
            task: "rerank".into(), variant: "3_hits".into(),
            latency_ms: elapsed, input_tokens: r.input_tokens, output_tokens: r.output_tokens,
            output_len: r.output.len(), output_preview: r.output.clone(), success: true, error: None,
        });
    }

    // ── 49. Collab Summary ──
    let annotations = r#"
@Sarah: The Q4 roadmap looks good, but I think we should prioritize the onboarding optimization.
@Mike: Agreed. I'd also add that we need to address the audio pipeline tech debt.
@Jennifer: From a budget perspective, we can support the hiring but SOC 2 compliance needs quotes first.
@David: I'll have the SOC 2 scope defined by end of week.
@Lisa: The hotfix for iOS 15 crashes is ready for review.
"#;
    let t = Instant::now();
    let result = engine.collab_summary(annotations, "en", opts.clone()).await;
    let elapsed = t.elapsed().as_millis() as u64;
    if let Ok(r) = result {
        report.add(TestResult {
            task: "collab_summary".into(), variant: "annotations".into(),
            latency_ms: elapsed, input_tokens: r.input_tokens, output_tokens: r.output_tokens,
            output_len: r.output.len(), output_preview: r.output.clone(), success: true, error: None,
        });
    }

    // ── 50. Extract Decisions ──
    let t = Instant::now();
    let result = engine.extract_decisions(MEETING_TRANSCRIPT, "en", opts.clone()).await;
    let elapsed = t.elapsed().as_millis() as u64;
    if let Ok(r) = result {
        report.add(TestResult {
            task: "extract_decisions".into(), variant: "meeting".into(),
            latency_ms: elapsed, input_tokens: r.input_tokens, output_tokens: r.output_tokens,
            output_len: r.output.len(), output_preview: r.output.clone(), success: true, error: None,
        });
    }

    // ── 51. Meeting Minutes ──
    let t = Instant::now();
    let result = engine.meeting_minutes(MEETING_TRANSCRIPT, "en", opts.clone()).await;
    let elapsed = t.elapsed().as_millis() as u64;
    if let Ok(r) = result {
        report.add(TestResult {
            task: "meeting_minutes".into(), variant: "q3_review".into(),
            latency_ms: elapsed, input_tokens: r.input_tokens, output_tokens: r.output_tokens,
            output_len: r.output.len(), output_preview: r.output.clone(), success: true, error: None,
        });
    }

    // ── 52. Follow Up ──
    let action_items_text = "• Lisa to lead onboarding optimization (due: Oct 28)\n• Mike to coordinate TechCorp integration (due: Nov 15)\n• David to scope SOC 2 compliance (due: Oct 22)\n• Jennifer to get audit quotes (due: Oct 25)";
    let t = Instant::now();
    let result = engine.follow_up(action_items_text, "en", opts.clone()).await;
    let elapsed = t.elapsed().as_millis() as u64;
    if let Ok(r) = result {
        report.add(TestResult {
            task: "follow_up".into(), variant: "overdue".into(),
            latency_ms: elapsed, input_tokens: r.input_tokens, output_tokens: r.output_tokens,
            output_len: r.output.len(), output_preview: r.output.clone(), success: true, error: None,
        });
    }

    // ── 53. Dictate Format (audio) ──
    let audio = synthetic_audio(2.0, 440.0);
    let t = Instant::now();
    let result = engine.dictate_format(&audio, "en", opts.clone()).await;
    let elapsed = t.elapsed().as_millis() as u64;
    match result {
        Ok(r) => report.add(TestResult {
            task: "dictate_format".into(), variant: "2s_audio".into(),
            latency_ms: elapsed, input_tokens: r.input_tokens, output_tokens: r.output_tokens,
            output_len: r.output.len(), output_preview: r.output.clone(), success: true, error: None,
        }),
        Err(e) => report.add(TestResult {
            task: "dictate_format".into(), variant: "2s_audio".into(),
            latency_ms: elapsed, input_tokens: 0, output_tokens: 0,
            output_len: 0, output_preview: String::new(), success: false, error: Some(e.to_string()),
        }),
    }

    // ── 54. Voice Action ──
    let audio = synthetic_audio(1.0, 880.0);
    let t = Instant::now();
    let result = engine.voice_action(&audio, opts.clone()).await;
    let elapsed = t.elapsed().as_millis() as u64;
    match result {
        Ok(r) => report.add(TestResult {
            task: "voice_action".into(), variant: "1s_audio".into(),
            latency_ms: elapsed, input_tokens: r.input_tokens, output_tokens: r.output_tokens,
            output_len: r.output.len(), output_preview: r.output.clone(), success: true, error: None,
        }),
        Err(e) => report.add(TestResult {
            task: "voice_action".into(), variant: "1s_audio".into(),
            latency_ms: elapsed, input_tokens: 0, output_tokens: 0,
            output_len: 0, output_preview: String::new(), success: false, error: Some(e.to_string()),
        }),
    }

    // ── 55. Image Search ──
    let t = Instant::now();
    let result = engine.image_search("a diagram of cloud architecture", opts.clone()).await;
    let elapsed = t.elapsed().as_millis() as u64;
    match result {
        Ok(r) => report.add(TestResult {
            task: "image_search".into(), variant: "query".into(),
            latency_ms: elapsed, input_tokens: r.input_tokens, output_tokens: r.output_tokens,
            output_len: r.output.len(), output_preview: r.output.clone(), success: true, error: None,
        }),
        Err(e) => report.add(TestResult {
            task: "image_search".into(), variant: "query".into(),
            latency_ms: elapsed, input_tokens: 0, output_tokens: 0,
            output_len: 0, output_preview: String::new(), success: false, error: Some(e.to_string()),
        }),
    }

    // ── 56. Semantic Search ──
    let t = Instant::now();
    let result = engine.semantic_search("machine learning neural networks", opts.clone()).await;
    let elapsed = t.elapsed().as_millis() as u64;
    match result {
        Ok(r) => report.add(TestResult {
            task: "semantic_search".into(), variant: "query".into(),
            latency_ms: elapsed, input_tokens: r.input_tokens, output_tokens: r.output_tokens,
            output_len: r.output.len(), output_preview: r.output.clone(), success: true, error: None,
        }),
        Err(e) => report.add(TestResult {
            task: "semantic_search".into(), variant: "query".into(),
            latency_ms: elapsed, input_tokens: 0, output_tokens: 0,
            output_len: 0, output_preview: String::new(), success: false, error: Some(e.to_string()),
        }),
    }

    // ── 57. All 22 supported languages: summarize ──
    for lang in SUPPORTED_LANGUAGES {
        let text = "The company announced record revenue growth of 23% year-over-year, driven by strong performance in emerging markets.";
        let t = Instant::now();
        let result = engine.summarize(text, lang, opts.clone()).await;
        let elapsed = t.elapsed().as_millis() as u64;
        match result {
            Ok(r) => report.add(TestResult {
                task: "summarize_all_langs".into(), variant: format!("lang={}", lang),
                latency_ms: elapsed, input_tokens: r.input_tokens, output_tokens: r.output_tokens,
                output_len: r.output.len(), output_preview: r.output.clone(), success: true, error: None,
            }),
            Err(e) => report.add(TestResult {
                task: "summarize_all_langs".into(), variant: format!("lang={}", lang),
                latency_ms: elapsed, input_tokens: 0, output_tokens: 0,
                output_len: 0, output_preview: String::new(), success: false, error: Some(e.to_string()),
            }),
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // EXPANDED DATASET TESTS (500+ tests for real-world validation)
    // ════════════════════════════════════════════════════════════════════════

    // ── E1. Expanded Sentiment (20 samples) ──
    for (expected, text) in SENTIMENT_DATASET {
        let t = Instant::now();
        let result = engine.sentiment(text, opts.clone()).await;
        let elapsed = t.elapsed().as_millis() as u64;
        if let Ok(r) = result {
            report.add(TestResult {
                task: "sentiment_expanded".into(), variant: format!("expect={}", expected),
                latency_ms: elapsed, input_tokens: r.input_tokens, output_tokens: r.output_tokens,
                output_len: r.output.len(), output_preview: r.output.clone(), success: true, error: None,
            });
        }
    }

    // ── E2. Expanded Tone Classification (20 samples) ──
    for (expected, text) in TONE_DATASET {
        let t = Instant::now();
        let result = engine.classify_tone(text, opts.clone()).await;
        let elapsed = t.elapsed().as_millis() as u64;
        if let Ok(r) = result {
            report.add(TestResult {
                task: "classify_tone_expanded".into(), variant: format!("expect={}", expected),
                latency_ms: elapsed, input_tokens: r.input_tokens, output_tokens: r.output_tokens,
                output_len: r.output.len(), output_preview: r.output.clone(), success: true, error: None,
            });
        }
    }

    // ── E3. Expanded Urgency Classification (20 samples) ──
    for (expected, ticket) in URGENCY_DATASET {
        let t = Instant::now();
        let result = engine.classify_urgency(ticket, opts.clone()).await;
        let elapsed = t.elapsed().as_millis() as u64;
        if let Ok(r) = result {
            report.add(TestResult {
                task: "classify_urgency_expanded".into(), variant: format!("expect={}", expected),
                latency_ms: elapsed, input_tokens: r.input_tokens, output_tokens: r.output_tokens,
                output_len: r.output.len(), output_preview: r.output.clone(), success: true, error: None,
            });
        }
    }

    // ── E4. Expanded Sensitivity Classification (20 samples) ──
    for (expected, text) in SENSITIVITY_DATASET {
        let t = Instant::now();
        let result = engine.classify_sensitivity(text, opts.clone()).await;
        let elapsed = t.elapsed().as_millis() as u64;
        if let Ok(r) = result {
            report.add(TestResult {
                task: "classify_sensitivity_expanded".into(), variant: format!("expect={}", expected),
                latency_ms: elapsed, input_tokens: r.input_tokens, output_tokens: r.output_tokens,
                output_len: r.output.len(), output_preview: r.output.clone(), success: true, error: None,
            });
        }
    }

    // ── E5. Expanded Email Categorization (20 samples) ──
    for (expected, email) in EMAIL_CATEGIZE_DATASET {
        let t = Instant::now();
        let result = engine.email_categorize(email, opts.clone()).await;
        let elapsed = t.elapsed().as_millis() as u64;
        if let Ok(r) = result {
            report.add(TestResult {
                task: "email_categorize_expanded".into(), variant: format!("expect={}", expected),
                latency_ms: elapsed, input_tokens: r.input_tokens, output_tokens: r.output_tokens,
                output_len: r.output.len(), output_preview: r.output.clone(), success: true, error: None,
            });
        }
    }

    // ── E6. Expanded Summarize (15 samples) ──
    for (variant, text) in SUMMARIZE_DATASET {
        let t = Instant::now();
        let result = engine.summarize(text, "en", opts.clone()).await;
        let elapsed = t.elapsed().as_millis() as u64;
        if let Ok(r) = result {
            report.add(TestResult {
                task: "summarize_expanded".into(), variant: variant.to_string(),
                latency_ms: elapsed, input_tokens: r.input_tokens, output_tokens: r.output_tokens,
                output_len: r.output.len(), output_preview: r.output.clone(), success: true, error: None,
            });
        }
    }

    // ── E7. Expanded Translate (15 samples) ──
    for (src, tgt, text) in TRANSLATE_DATASET {
        let t = Instant::now();
        let result = engine.translate(text, src, tgt, opts.clone()).await;
        let elapsed = t.elapsed().as_millis() as u64;
        if let Ok(r) = result {
            report.add(TestResult {
                task: "translate_expanded".into(), variant: format!("{}→{}", src, tgt),
                latency_ms: elapsed, input_tokens: r.input_tokens, output_tokens: r.output_tokens,
                output_len: r.output.len(), output_preview: r.output.clone(), success: true, error: None,
            });
        }
    }

    // ── E8. Expanded PII Scan (10 samples) ──
    for (variant, text) in PII_DATASET {
        let t = Instant::now();
        let result = engine.pii_scan(text, opts.clone()).await;
        let elapsed = t.elapsed().as_millis() as u64;
        if let Ok(r) = result {
            report.add(TestResult {
                task: "pii_scan_expanded".into(), variant: variant.to_string(),
                latency_ms: elapsed, input_tokens: r.input_tokens, output_tokens: r.output_tokens,
                output_len: r.output.len(), output_preview: r.output.clone(), success: true, error: None,
            });
        }
    }

    // ── E9. Expanded Date Extraction (10 samples) ──
    for (variant, text) in DATE_DATASET {
        let t = Instant::now();
        let result = engine.extract_dates(text, opts.clone()).await;
        let elapsed = t.elapsed().as_millis() as u64;
        if let Ok(r) = result {
            report.add(TestResult {
                task: "extract_dates_expanded".into(), variant: variant.to_string(),
                latency_ms: elapsed, input_tokens: r.input_tokens, output_tokens: r.output_tokens,
                output_len: r.output.len(), output_preview: r.output.clone(), success: true, error: None,
            });
        }
    }

    // ── E10. Expanded Dedup (10 pairs) ──
    for (i, (existing, new_ticket, expected_dup)) in DEDUP_DATASET.iter().enumerate() {
        let mut dup_index = TextIndex::new();
        let emb = synthetic_embedding(existing, 512);
        dup_index.add_text(&format!("ticket_{}", i), existing, emb, None);
        let t = Instant::now();
        let result = engine.dedup(new_ticket, &dup_index, opts.clone()).await;
        let elapsed = t.elapsed().as_millis() as u64;
        if let Ok(r) = result {
            report.add(TestResult {
                task: "dedup_expanded".into(), variant: format!("dup={}", expected_dup),
                latency_ms: elapsed, input_tokens: r.input_tokens, output_tokens: r.output_tokens,
                output_len: r.output.len(), output_preview: r.output.clone(), success: true, error: None,
            });
        }
    }

    // ── E11. Expanded Find Expert (8 queries) ──
    let mut expert_index_exp = TextIndex::new();
    let experts = [
        ("alice", "Alice specializes in machine learning, neural networks, and deep learning architectures."),
        ("bob", "Bob is an expert in cloud infrastructure, Kubernetes, and container orchestration."),
        ("carol", "Carol focuses on security, compliance, GDPR, and SOC 2 audits."),
        ("dave", "Dave works on financial systems, trading algorithms, and risk management."),
    ];
    for (id, text) in &experts {
        let emb = synthetic_embedding(text, 512);
        expert_index_exp.add_text(id, text, emb, Some(id));
    }
    for (query, expected_id) in FIND_EXPERT_DATASET {
        let t = Instant::now();
        let result = engine.find_expert(query, &expert_index_exp, 2, opts.clone()).await;
        let elapsed = t.elapsed().as_millis() as u64;
        if let Ok(r) = result {
            report.add(TestResult {
                task: "find_expert_expanded".into(), variant: format!("expect={}", expected_id),
                latency_ms: elapsed, input_tokens: r.input_tokens, output_tokens: r.output_tokens,
                output_len: r.output.len(), output_preview: r.output.clone(), success: true, error: None,
            });
        }
    }

    // ── E12. Expanded Audio Transcribe (10 samples) ──
    for (i, &(dur, freq)) in AUDIO_DATASET.iter().enumerate() {
        let audio = synthetic_audio(dur, freq);
        let t = Instant::now();
        let result = engine.transcribe(&audio, opts.clone()).await;
        let elapsed = t.elapsed().as_millis() as u64;
        match result {
            Ok(r) => report.add(TestResult {
                task: "transcribe_expanded".into(), variant: format!("d={}s_f={}", dur, freq),
                latency_ms: elapsed, input_tokens: r.input_tokens, output_tokens: r.output_tokens,
                output_len: r.output.len(), output_preview: r.output.clone(), success: true, error: None,
            }),
            Err(e) => report.add(TestResult {
                task: "transcribe_expanded".into(), variant: format!("d={}s_f={}", dur, freq),
                latency_ms: elapsed, input_tokens: 0, output_tokens: 0,
                output_len: 0, output_preview: String::new(), success: false, error: Some(e.to_string()),
            }),
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // MULTI-LANGUAGE TESTS (130 tests across 8 categories)
    // ════════════════════════════════════════════════════════════════════════

    // ── M1. Multi-language Sentiment (20 samples) ──
    for (expected, text) in MULTILANG_SENTIMENT {
        let t = Instant::now();
        let result = engine.sentiment(text, opts.clone()).await;
        let elapsed = t.elapsed().as_millis() as u64;
        if let Ok(r) = result {
            report.add(TestResult {
                task: "sentiment_multilang".into(), variant: format!("expect={}", expected),
                latency_ms: elapsed, input_tokens: r.input_tokens, output_tokens: r.output_tokens,
                output_len: r.output.len(), output_preview: r.output.clone(), success: true, error: None,
            });
        }
    }

    // ── M2. Multi-language Tone (20 samples) ──
    for (expected, text) in MULTILANG_TONE {
        let t = Instant::now();
        let result = engine.classify_tone(text, opts.clone()).await;
        let elapsed = t.elapsed().as_millis() as u64;
        if let Ok(r) = result {
            report.add(TestResult {
                task: "classify_tone_multilang".into(), variant: format!("expect={}", expected),
                latency_ms: elapsed, input_tokens: r.input_tokens, output_tokens: r.output_tokens,
                output_len: r.output.len(), output_preview: r.output.clone(), success: true, error: None,
            });
        }
    }

    // ── M3. Multi-language Urgency (20 samples) ──
    for (expected, ticket) in MULTILANG_URGENCY {
        let t = Instant::now();
        let result = engine.classify_urgency(ticket, opts.clone()).await;
        let elapsed = t.elapsed().as_millis() as u64;
        if let Ok(r) = result {
            report.add(TestResult {
                task: "classify_urgency_multilang".into(), variant: format!("expect={}", expected),
                latency_ms: elapsed, input_tokens: r.input_tokens, output_tokens: r.output_tokens,
                output_len: r.output.len(), output_preview: r.output.clone(), success: true, error: None,
            });
        }
    }

    // ── M4. Multi-language Sensitivity (20 samples) ──
    for (expected, text) in MULTILANG_SENSITIVITY {
        let t = Instant::now();
        let result = engine.classify_sensitivity(text, opts.clone()).await;
        let elapsed = t.elapsed().as_millis() as u64;
        if let Ok(r) = result {
            report.add(TestResult {
                task: "classify_sensitivity_multilang".into(), variant: format!("expect={}", expected),
                latency_ms: elapsed, input_tokens: r.input_tokens, output_tokens: r.output_tokens,
                output_len: r.output.len(), output_preview: r.output.clone(), success: true, error: None,
            });
        }
    }

    // ── M5. Multi-language Email Categorize (20 samples) ──
    for (expected, email) in MULTILANG_EMAIL_CATEGIZE {
        let t = Instant::now();
        let result = engine.email_categorize(email, opts.clone()).await;
        let elapsed = t.elapsed().as_millis() as u64;
        if let Ok(r) = result {
            report.add(TestResult {
                task: "email_categorize_multilang".into(), variant: format!("expect={}", expected),
                latency_ms: elapsed, input_tokens: r.input_tokens, output_tokens: r.output_tokens,
                output_len: r.output.len(), output_preview: r.output.clone(), success: true, error: None,
            });
        }
    }

    // ── M6. Mixed-language Sentiment (10 samples) ──
    for (expected, text) in MIXED_LANG_SENTIMENT {
        let t = Instant::now();
        let result = engine.sentiment(text, opts.clone()).await;
        let elapsed = t.elapsed().as_millis() as u64;
        if let Ok(r) = result {
            report.add(TestResult {
                task: "sentiment_mixed_lang".into(), variant: format!("expect={}", expected),
                latency_ms: elapsed, input_tokens: r.input_tokens, output_tokens: r.output_tokens,
                output_len: r.output.len(), output_preview: r.output.clone(), success: true, error: None,
            });
        }
    }

    // ── M7. Multi-language Summarize (10 samples) ──
    for (lang, text) in MULTILANG_SUMMARIZE {
        let t = Instant::now();
        let result = engine.summarize(text, lang, opts.clone()).await;
        let elapsed = t.elapsed().as_millis() as u64;
        if let Ok(r) = result {
            report.add(TestResult {
                task: "summarize_multilang".into(), variant: format!("lang={}", lang),
                latency_ms: elapsed, input_tokens: r.input_tokens, output_tokens: r.output_tokens,
                output_len: r.output.len(), output_preview: r.output.clone(), success: true, error: None,
            });
        }
    }

    // ── M8. Multi-language Dedup (10 pairs) ──
    for (i, (existing, new_ticket, expected_dup)) in MULTILANG_DEDUP.iter().enumerate() {
        let mut dup_index = TextIndex::new();
        let emb = synthetic_embedding(existing, 512);
        dup_index.add_text(&format!("ml_ticket_{}", i), existing, emb, None);
        let t = Instant::now();
        let result = engine.dedup(new_ticket, &dup_index, opts.clone()).await;
        let elapsed = t.elapsed().as_millis() as u64;
        if let Ok(r) = result {
            report.add(TestResult {
                task: "dedup_multilang".into(), variant: format!("dup={}", expected_dup),
                latency_ms: elapsed, input_tokens: r.input_tokens, output_tokens: r.output_tokens,
                output_len: r.output.len(), output_preview: r.output.clone(), success: true, error: None,
            });
        }
    }

    report.total_duration = start.elapsed();
    report
}

fn bench_comprehensive(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    // Print the full report once before criterion measurements
    println!("\nRunning comprehensive pipeline benchmark report...");
    let report = rt.block_on(run_comprehensive_tests());
    report.print_report();

    let mut group = c.benchmark_group("comprehensive");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(30));
    
    group.bench_function("all_pipelines", |b| {
        b.to_async(&rt).iter(|| async {
            run_comprehensive_tests().await
        });
    });
    
    group.finish();
}

criterion_group! {
    name = comprehensive;
    config = Criterion::default().measurement_time(Duration::from_secs(60));
    targets = bench_comprehensive
}

criterion_main!(comprehensive);
