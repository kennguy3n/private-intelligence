# KChat B2C — Consumer Chat with On-Device AI

A standalone demonstration of **zk-ai** powering a consumer chat application with
privacy-first, on-device intelligence. No network calls, no API keys, no per-token costs.

## Demonstrated Capabilities

| Feature | zk-ai Pipeline | Description |
|---------|---------------|-------------|
| Email Summary | `email_summary` | Summarize an email thread into 3 key bullet points |
| Smart Reply | `smart_reply` | Generate 3 short reply options for a message |
| Classify Tone | `classify_tone` | Detect tone (Urgent, FYI, Action needed) |
| Chat Summary | `chat_summary` | Summarize a group chat conversation |
| Notification Digest | `notif_summary` | Condense notifications into a 2-3 sentence digest |
| Meeting Summary | `meeting_summary` | Summarize a meeting transcript |
| Action Items | `action_items` | Extract action items from a meeting |
| Pre-Send Check | `pre_send_check` | Grammar + tone check before sending |
| Daily Digest | `daily_digest` | End-of-day summary from emails, meetings, notifications |

## Run

```bash
cargo run -p kchat-b2c
```

The demo creates a temporary model cache directory, initializes the `AiEngine`,
and runs each pipeline against sample data — all locally on your device.
