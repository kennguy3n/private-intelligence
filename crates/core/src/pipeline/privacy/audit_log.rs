//! Tamper-evident audit log for AI inference.
//!
//! Every AI inference is logged locally: timestamp, task type, model hash,
//! input hash (not content), output hash. Each entry is chained via hash
//! of the previous entry. No network transmission.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use chrono::{DateTime, Utc};

/// A single audit log entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Sequential entry number.
    pub seq: u64,
    /// Timestamp of the inference.
    pub timestamp: DateTime<Utc>,
    /// Task type (e.g., "summarize", "translate").
    pub task: String,
    /// Model used (e.g., "mt5-small-int8").
    pub model: String,
    /// SHA-256 hash of the input text (not the content itself).
    pub input_hash: String,
    /// SHA-256 hash of the output text.
    pub output_hash: String,
    /// LoRA adapter used (if any).
    pub adapter: Option<String>,
    /// Hash of the previous entry (for tamper-evidence).
    pub prev_hash: String,
    /// Hash of this entry (computed from all fields above).
    pub entry_hash: String,
}

/// Append-only audit log.
pub struct AuditLog {
    log_path: PathBuf,
    next_seq: u64,
    last_hash: String,
}

impl AuditLog {
    /// Open or create an audit log at the given path.
    pub fn open(path: PathBuf) -> std::io::Result<Self> {
        let next_seq = if path.exists() {
            let content = std::fs::read_to_string(&path)?;
            let entries: Vec<AuditEntry> = content
                .lines()
                .filter(|l| !l.is_empty())
                .filter_map(|l| serde_json::from_str(l).ok())
                .collect();
            let next = entries.last().map(|e| e.seq + 1).unwrap_or(0);
            let last = entries.last().map(|e| e.entry_hash.clone()).unwrap_or_default();
            (next, last)
        } else {
            (0, String::new())
        };

        Ok(Self {
            log_path: path,
            next_seq: next_seq.0,
            last_hash: next_seq.1,
        })
    }

    /// Append a new entry to the log.
    pub fn append(
        &mut self,
        task: &str,
        model: &str,
        input: &str,
        output: &str,
        adapter: Option<&str>,
    ) -> std::io::Result<AuditEntry> {
        let entry = AuditEntry {
            seq: self.next_seq,
            timestamp: Utc::now(),
            task: task.to_string(),
            model: model.to_string(),
            input_hash: hash_str(input),
            output_hash: hash_str(output),
            adapter: adapter.map(|s| s.to_string()),
            prev_hash: self.last_hash.clone(),
            entry_hash: String::new(), // computed below
        };

        let mut entry = entry;
        entry.entry_hash = hash_entry(&entry);

        // Append to file (one JSON per line)
        let json = serde_json::to_string(&entry)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        let line = format!("{}\n", json);

        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(&self.log_path)?;
        use std::io::Write;
        file.write_all(line.as_bytes())?;

        self.next_seq += 1;
        self.last_hash = entry.entry_hash.clone();

        Ok(entry)
    }

    /// Read all entries from the log.
    pub fn read_all(&self) -> std::io::Result<Vec<AuditEntry>> {
        if !self.log_path.exists() {
            return Ok(Vec::new());
        }
        let content = std::fs::read_to_string(&self.log_path)?;
        let entries: Vec<AuditEntry> = content
            .lines()
            .filter(|l| !l.is_empty())
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect();
        Ok(entries)
    }

    /// Verify the integrity of the log (chain of hashes).
    pub fn verify(&self) -> bool {
        let entries = match self.read_all() {
            Ok(e) => e,
            Err(_) => return false,
        };

        let mut prev_hash = String::new();
        for entry in &entries {
            if entry.prev_hash != prev_hash {
                return false;
            }
            let computed = hash_entry(entry);
            if entry.entry_hash != computed {
                return false;
            }
            prev_hash = entry.entry_hash.clone();
        }
        true
    }
}

fn hash_str(s: &str) -> String {
    hex::encode(Sha256::digest(s.as_bytes()))
}

fn hash_entry(entry: &AuditEntry) -> String {
    let mut hasher = Sha256::new();
    hasher.update(entry.seq.to_le_bytes());
    hasher.update(entry.timestamp.to_rfc3339().as_bytes());
    hasher.update(entry.task.as_bytes());
    hasher.update(entry.model.as_bytes());
    hasher.update(entry.input_hash.as_bytes());
    hasher.update(entry.output_hash.as_bytes());
    if let Some(adapter) = &entry.adapter {
        hasher.update(adapter.as_bytes());
    }
    hasher.update(entry.prev_hash.as_bytes());
    hex::encode(hasher.finalize())
}
