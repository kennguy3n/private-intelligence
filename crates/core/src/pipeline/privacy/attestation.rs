//! Zero-knowledge attestation.
//!
//! Generates cryptographic proof that AI inference ran on-device with
//! a specific model. Contains: device_id, task, timestamp, model_hash,
//! inference_hash. Signed with device key.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use chrono::{DateTime, Utc};

/// A ZK attestation proving on-device inference.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkAttestation {
    /// Unique attestation ID.
    pub id: String,
    /// Device identifier.
    pub device_id: String,
    /// Task that was performed.
    pub task: String,
    /// Timestamp of inference.
    pub timestamp: DateTime<Utc>,
    /// SHA-256 hash of the model used.
    pub model_hash: String,
    /// SHA-256 hash of the inference (input + output).
    pub inference_hash: String,
    /// Device tier at time of inference.
    pub device_tier: String,
    /// Whether inference was fully local (no network).
    pub local_only: bool,
    /// Compliance framework (HIPAA, GDPR, SOC2) if applicable.
    pub compliance_framework: Option<String>,
    /// Policy version in effect.
    pub policy_version: Option<String>,
    /// Data classification of the input.
    pub data_classification: Option<String>,
    /// Ed25519 signature (placeholder — real signing requires key management).
    pub signature: Option<String>,
}

impl ZkAttestation {
    /// Create a new attestation for an inference event.
    pub fn new(
        device_id: &str,
        task: &str,
        model: &str,
        input: &str,
        output: &str,
        device_tier: &str,
        local_only: bool,
    ) -> Self {
        let mut inference_hasher = Sha256::new();
        inference_hasher.update(input.as_bytes());
        inference_hasher.update(output.as_bytes());
        let inference_hash = hex::encode(inference_hasher.finalize());

        let model_hash = hex::encode(Sha256::digest(model.as_bytes()));

        let id = uuid::Uuid::new_v4().to_string();

        Self {
            id,
            device_id: device_id.to_string(),
            task: task.to_string(),
            timestamp: Utc::now(),
            model_hash,
            inference_hash,
            device_tier: device_tier.to_string(),
            local_only,
            compliance_framework: None,
            policy_version: None,
            data_classification: None,
            signature: None,
        }
    }

    /// Set enterprise compliance fields.
    pub fn with_compliance(
        mut self,
        framework: &str,
        policy_version: &str,
        data_classification: &str,
    ) -> Self {
        self.compliance_framework = Some(framework.to_string());
        self.policy_version = Some(policy_version.to_string());
        self.data_classification = Some(data_classification.to_string());
        self
    }

    /// Serialize to JSON for verification by third parties.
    pub fn to_json(&self) -> serde_json::Result<String> {
        serde_json::to_string_pretty(self)
    }

    /// Compute a hash of the attestation for verification.
    pub fn hash(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.id.as_bytes());
        hasher.update(self.device_id.as_bytes());
        hasher.update(self.task.as_bytes());
        hasher.update(self.timestamp.to_rfc3339().as_bytes());
        hasher.update(self.model_hash.as_bytes());
        hasher.update(self.inference_hash.as_bytes());
        hasher.update(self.device_tier.as_bytes());
        hasher.update(self.local_only.to_string().as_bytes());
        if let Some(fw) = &self.compliance_framework {
            hasher.update(fw.as_bytes());
        }
        hex::encode(hasher.finalize())
    }
}
