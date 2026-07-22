//! Secure model update verification.
//!
//! Verifies cryptographic signatures on LoRA adapter files before loading
//! to prevent supply chain attacks. Supports Ed25519 signature verification
//! against a trusted public key, with SHA-256 hash as a fallback.

use sha2::{Digest, Sha256};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};

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

/// Verify a model/adapter file's integrity by computing its SHA-256 hash.
///
/// For Ed25519 signature verification, use [`verify_file_signature`] or
/// [`verify_file_signature_hex`] instead.
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

/// Verify a file's Ed25519 signature against a trusted public key.
///
/// The signature is verified over the raw file bytes using standard
/// Ed25519 (RFC 8032). The SHA-256 hash is also computed and returned
/// in the result for informational purposes.
pub fn verify_file_signature(
    path: &std::path::Path,
    signature: &[u8; 64],
    public_key: &VerifyingKey,
) -> VerificationResult {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            return VerificationResult {
                verified: false,
                file_hash: String::new(),
                error: Some(format!("Failed to read file: {}", e)),
            }
        }
    };

    let hash = hex::encode(Sha256::digest(&bytes));
    let sig = Signature::from_bytes(signature);

    match public_key.verify(&bytes, &sig) {
        Ok(()) => VerificationResult {
            verified: true,
            file_hash: hash,
            error: None,
        },
        Err(e) => VerificationResult {
            verified: false,
            file_hash: hash,
            error: Some(format!("Signature verification failed: {}", e)),
        },
    }
}

/// Verify a file's Ed25519 signature using a hex-encoded public key and signature.
///
/// Convenience wrapper around `verify_file_signature` that accepts hex strings
/// instead of raw bytes.
pub fn verify_file_signature_hex(
    path: &std::path::Path,
    signature_hex: &str,
    public_key_hex: &str,
) -> VerificationResult {
    let sig_bytes = match hex::decode(signature_hex) {
        Ok(b) if b.len() == 64 => {
            let mut arr = [0u8; 64];
            arr.copy_from_slice(&b);
            arr
        }
        Ok(b) => {
            return VerificationResult {
                verified: false,
                file_hash: String::new(),
                error: Some(format!(
                    "Invalid signature length: {} (expected 64)",
                    b.len()
                )),
            }
        }
        Err(e) => {
            return VerificationResult {
                verified: false,
                file_hash: String::new(),
                error: Some(format!("Failed to decode signature hex: {}", e)),
            }
        }
    };

    let pk_bytes = match hex::decode(public_key_hex) {
        Ok(b) if b.len() == 32 => b,
        Ok(b) => {
            return VerificationResult {
                verified: false,
                file_hash: String::new(),
                error: Some(format!(
                    "Invalid public key length: {} (expected 32)",
                    b.len()
                )),
            }
        }
        Err(e) => {
            return VerificationResult {
                verified: false,
                file_hash: String::new(),
                error: Some(format!("Failed to decode public key hex: {}", e)),
            }
        }
    };

    let pk_array: [u8; 32] = pk_bytes.try_into().unwrap();
    let public_key = match VerifyingKey::from_bytes(&pk_array) {
        Ok(pk) => pk,
        Err(e) => {
            return VerificationResult {
                verified: false,
                file_hash: String::new(),
                error: Some(format!("Invalid Ed25519 public key: {}", e)),
            }
        }
    };

    verify_file_signature(path, &sig_bytes, &public_key)
}
