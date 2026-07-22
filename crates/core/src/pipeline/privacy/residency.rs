//! Data residency proof generation.
//!
//! Combines audit log + network monitor to generate a certificate proving
//! that all AI inference was local (no network calls).

use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use super::audit_log::AuditEntry;

/// A data residency certificate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResidencyCertificate {
    /// Certificate ID.
    pub id: String,
    /// Period start.
    pub period_start: DateTime<Utc>,
    /// Period end.
    pub period_end: DateTime<Utc>,
    /// Number of inference events in the period.
    pub inference_count: u64,
    /// Number of outbound network connections during the period.
    pub network_connections: u32,
    /// Whether all inference was local.
    pub all_local: bool,
    /// Hashes of all audit entries covered.
    pub entry_hashes: Vec<String>,
    /// Certificate hash for verification.
    pub certificate_hash: String,
}

impl ResidencyCertificate {
    /// Generate a residency certificate from audit log entries and network count.
    pub fn generate(
        entries: &[AuditEntry],
        network_connections: u32,
        period_start: DateTime<Utc>,
        period_end: DateTime<Utc>,
    ) -> Self {
        let entry_hashes: Vec<String> = entries.iter().map(|e| e.entry_hash.clone()).collect();
        let all_local = network_connections == 0;

        let mut hasher = Sha256::new();
        hasher.update(period_start.to_rfc3339().as_bytes());
        hasher.update(period_end.to_rfc3339().as_bytes());
        hasher.update(entries.len().to_le_bytes());
        hasher.update(network_connections.to_le_bytes());
        for h in &entry_hashes {
            hasher.update(h.as_bytes());
        }

        Self {
            id: uuid::Uuid::new_v4().to_string(),
            period_start,
            period_end,
            inference_count: entries.len() as u64,
            network_connections,
            all_local,
            entry_hashes,
            certificate_hash: hex::encode(hasher.finalize()),
        }
    }

    /// Serialize to JSON.
    pub fn to_json(&self) -> serde_json::Result<String> {
        serde_json::to_string_pretty(self)
    }
}
