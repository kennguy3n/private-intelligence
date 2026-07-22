//! PII scanning pipeline.
//!
//! Scans documents for personally identifiable information (names, phone
//! numbers, SSN, credit cards, addresses) using e5-small + NER-style
//! detection. No new base model required.

use crate::Result;
use crate::pipeline::{TaskOptions, TaskResult, Task};
use crate::AiEngine;
use crate::model_manager::ModelSpec;
use crate::pipeline::image_index::cosine_similarity;
use crate::pipeline::privacy::pii::detect_pii;

/// PII type templates for k-NN detection (used as fallback when regex finds nothing).
const PII_TEMPLATES: &[(&str, &str)] = &[
    ("Name", "John Smith, Jane Doe, Robert Johnson, Maria Garcia"),
    ("Phone", "+1 555-123-4567, (123) 456-7890, 0901234567"),
    ("SSN", "123-45-6789, Social Security Number 123456789"),
    ("Credit Card", "4532-1234-5678-9010, Visa ending in 1234, 4111111111111111"),
    ("Email", "john@example.com, jane.doe@company.org, user@domain.co.uk"),
    ("Address", "123 Main Street, Springfield, IL 62701, 456 Oak Ave, New York, NY 10001"),
];

/// Run a PII scan task.
///
/// Input: document text.
/// Output: list of PII entities found with types and counts.
pub async fn run(
    engine: &mut AiEngine,
    text: &str,
    _options: TaskOptions,
) -> Result<TaskResult> {
    let spec = ModelSpec::e5_small_int8();
    engine.ensure_model(&spec).await?;

    let start = std::time::Instant::now();

    // Primary: use regex-based detect_pii for exact pattern matching
    let regex_findings = detect_pii(text);

    let mut pii_findings: Vec<(String, String, f32)> = Vec::new();

    for entity in &regex_findings {
        pii_findings.push((entity.entity_type.to_string(), entity.text.clone(), 1.0));
    }

    // Fallback: if regex found nothing, try embedding-based k-NN detection
    if pii_findings.is_empty() {
        let sentences: Vec<&str> = text.split(|c: char| c == '.' || c == '\n' || c == ';')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .collect();

        for sentence in &sentences {
            let emb = engine.run_embedding(sentence).await?;
            for (pii_type, template) in PII_TEMPLATES {
                let template_emb = engine.run_embedding(template).await?;
                let score = cosine_similarity(&emb, &template_emb);
                if score > 0.75 {
                    pii_findings.push((pii_type.to_string(), sentence.to_string(), score));
                }
            }
        }
    }

    // Count by type
    let mut counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for (pii_type, _, _) in &pii_findings {
        *counts.entry(pii_type.clone()).or_insert(0) += 1;
    }

    let output = if pii_findings.is_empty() {
        "No PII detected in the document.".to_string()
    } else {
        let mut lines = vec![format!("Found {} PII instance(s):", pii_findings.len())];
        for (pii_type, count) in &counts {
            lines.push(format!("  - {}: {}", pii_type, count));
        }
        lines.push(String::new());
        for (pii_type, value, score) in pii_findings.iter().take(10) {
            lines.push(format!("  [{}] (score: {:.3}) {}", pii_type, score, value.chars().take(80).collect::<String>()));
        }
        lines.join("\n")
    };

    let duration_ms = start.elapsed().as_millis() as u64;

    Ok(TaskResult {
        output,
        task: Task::PiiScan,
        model: "multilingual-e5-small-int8".to_string(),
        adapter: None,
        duration_ms,
        input_tokens: text.split_whitespace().count() as u32,
        output_tokens: pii_findings.len() as u32,
    })
}
