# KChat B2B — Enterprise Chat with On-Device AI

A standalone demonstration of **zk-ai** powering an enterprise chat application with
privacy-first, on-device intelligence for document analysis, support workflows,
compliance, and knowledge management.

## Demonstrated Capabilities

| Feature | zk-ai Pipeline | Description |
|---------|---------------|-------------|
| Contract Analysis | `contract_analysis` | Extract parties, obligations, risks, termination clauses |
| Compare Documents | `compare_docs` | Summarize differences between two document versions |
| Find Clause | `find_clause` | Locate relevant clauses in a legal document |
| Extract Dates | `extract_dates` | Pull dates and deadlines from text |
| Ticket Summary | `ticket_summary` | Summarize a support ticket |
| Classify Urgency | `classify_urgency` | Rate urgency: Critical, High, Medium, Low |
| Ticket Reply | `ticket_reply` | Draft a reply to a support ticket |
| Email Categorize | `email_categorize` | Auto-categorize: Internal, Client, Vendor, Newsletter |
| Sentiment | `sentiment` | Detect Positive, Neutral, or Negative sentiment |
| Meeting Minutes | `meeting_minutes` | Generate formal meeting minutes from transcript |
| Extract Decisions | `extract_decisions` | Pull decisions from meeting transcripts |
| Follow Up | `follow_up` | Generate follow-up reminders for overdue action items |
| Collab Summary | `collab_summary` | Synthesize team annotations into unified summary |
| Auto Abstract | `auto_abstract` | Generate a 2-sentence document abstract |

## Run

```bash
cargo run -p kchat-b2b
```

The demo creates a temporary model cache directory, initializes the `AiEngine`,
and runs each pipeline against enterprise sample data — all locally on your device.
