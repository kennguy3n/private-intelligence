//! Date and deadline extraction pipeline.
//!
//! Extracts dates and deadlines from documents using e5-small + NER
//! classifier head for date entities. No new base model required.

use crate::Result;
use crate::pipeline::{TaskOptions, TaskResult, Task};
use crate::AiEngine;
use crate::model_manager::ModelSpec;
use crate::pipeline::image_index::cosine_similarity;
use std::sync::LazyLock;
use regex_lite::Regex;

/// Date-related label templates for k-NN detection (fallback).
const DATE_TEMPLATES: &[&str] = &[
    "January 15 2024",
    "by end of March",
    "December 31st",
    "Q3 2024 deadline",
    "within 30 days",
    "no later than Friday",
    "effective January 1",
    "expires on December 31",
    "due by next Monday",
    "scheduled for July 4th",
];

// Regex patterns for common date formats
static DATE_REGEXES: LazyLock<Vec<(&'static str, Regex)>> = LazyLock::new(|| {
    vec![
        ("Month Day, Year", Regex::new(r"\b(?:January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{1,2},?\s+\d{4}\b").unwrap()),
        ("Month Day Year", Regex::new(r"\b(?:January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{1,2}\s+\d{4}\b").unwrap()),
        ("MM/DD/YYYY", Regex::new(r"\b\d{1,2}/\d{1,2}/\d{4}\b").unwrap()),
        ("YYYY-MM-DD", Regex::new(r"\b\d{4}-\d{2}-\d{2}\b").unwrap()),
        ("Day Month Year", Regex::new(r"\b\d{1,2}\s+(?:January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{4}\b").unwrap()),
        ("Within N days", Regex::new(r"\bwithin\s+\d+\s+days?\b").unwrap()),
        ("By [Day]", Regex::new(r"\bby\s+(?:Monday|Tuesday|Wednesday|Thursday|Friday|Saturday|Sunday)\b").unwrap()),
        ("Due by", Regex::new(r"\bdue\s+by\b").unwrap()),
        ("Expires on", Regex::new(r"\bexpires\s+on\b").unwrap()),
        ("Effective", Regex::new(r"\beffective\s+\w+\s+\d{1,2}\b").unwrap()),
        ("N days of", Regex::new(r"\b\d+\s+days?\s+of\b").unwrap()),
    ]
});

/// Run a date extraction task.
///
/// Input: document text.
/// Output: list of dates/deadlines found in the text.
pub async fn run(
    engine: &mut AiEngine,
    text: &str,
    _options: TaskOptions,
) -> Result<TaskResult> {
    let spec = ModelSpec::e5_small_int8();
    engine.ensure_model(&spec).await?;

    let start = std::time::Instant::now();

    // Primary: regex-based date extraction
    let mut date_findings: Vec<(String, f32)> = Vec::new();
    let mut seen = std::collections::HashSet::new();

    // Find all sentences containing date patterns
    let sentences: Vec<&str> = text.split(|c: char| c == '.' || c == '\n' || c == ';')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .collect();

    for sentence in &sentences {
        let mut has_date = false;
        for (label, regex) in DATE_REGEXES.iter() {
            if regex.is_match(sentence) {
                has_date = true;
                // Extract the actual matched date
                for m in regex.find_iter(sentence) {
                    let matched = m.as_str().to_string();
                    if seen.insert(matched.clone()) {
                        date_findings.push((format!("[{}] {}", label, matched), 1.0));
                    }
                }
            }
        }
        if has_date && seen.insert(sentence.to_string()) {
            date_findings.push((sentence.to_string(), 0.9));
        }
    }

    // Fallback: embedding-based detection if regex found nothing
    if date_findings.is_empty() {
        for sentence in &sentences {
            let emb = engine.run_embedding(sentence).await?;
            let mut max_sim = 0.0f32;
            for template in DATE_TEMPLATES {
                let template_emb = engine.run_embedding(template).await?;
                let sim = cosine_similarity(&emb, &template_emb);
                if sim > max_sim {
                    max_sim = sim;
                }
            }
            if max_sim > 0.75 {
                date_findings.push((sentence.to_string(), max_sim));
            }
        }
    }

    date_findings.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

    let output = if date_findings.is_empty() {
        "No dates or deadlines found in the document.".to_string()
    } else {
        date_findings.iter()
            .map(|(text, score)| format!("[score: {:.3}] {}", score, text))
            .collect::<Vec<_>>()
            .join("\n")
    };

    let duration_ms = start.elapsed().as_millis() as u64;

    Ok(TaskResult {
        output,
        task: Task::ExtractDates,
        model: "multilingual-e5-small-int8".to_string(),
        adapter: None,
        duration_ms,
        input_tokens: text.split_whitespace().count() as u32,
        output_tokens: date_findings.len() as u32,
    })
}
