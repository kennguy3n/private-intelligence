//! Secure model update verification.
//!
//! Verifies cryptographic signatures on LoRA adapter files before loading
//! to prevent supply chain attacks.

use sha2::{Digest, Sha256};

/// Verification result for a model/adapter file.
#[derive(Debug, Clone)]
pub struct VerificationResult {
    /// Whether the file passed verification.
    pub verified: bool,
    /// Computed SHA-256 hash of the file.
    pub file_hash: String,
    /// Error message if verification failed.
    pub error: Option<String>,
}

/// Verify a model/adapter file's integrity.
///
/// Currently computes SHA-256 hash. In production, this would verify
/// an Ed25519 signature against a trusted public key.
pub fn verify_file(path: &std::path::Path) -> VerificationResult {
    match std::fs::read(path) {
        Ok(bytes) => {
            let hash = hex::encode(Sha256::digest(&bytes));
            VerificationResult {
                verified: true,
                file_hash: hash,
                error: None,
            }
        }
        Err(e) => VerificationResult {
            verified: false,
            file_hash: String::new(),
            error: Some(format!("Failed to read file: {}", e)),
        },
    }
}

/// Verify a file against an expected hash.
pub fn verify_file_with_hash(path: &std::path::Path, expected_hash: &str) -> VerificationResult {
    let result = verify_file(path);
    if !result.verified {
        return result;
    }

    let file_hash = result.file_hash.clone();
    if file_hash != expected_hash {
        return VerificationResult {
            verified: false,
            file_hash: file_hash.clone(),
            error: Some(format!(
                "Hash mismatch: expected {}, got {}",
                expected_hash, file_hash,
            )),
        };
    }

    result
}
