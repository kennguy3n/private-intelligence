//! Signed LoRA adapter marketplace.
//!
//! A marketplace is a directory of signed LoRA adapter packs. Each pack is a
//! directory containing:
//!   - `pack.toml` — pack metadata, author Ed25519 public key, adapter list,
//!     and author signature over the canonical manifest
//!   - `<task>.<language>.safetensors` or `.bin` — adapter weight files
//!
//! Packs are only exposed after signature verification against a trusted-key
//! allowlist and per-file SHA-256 integrity checks.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::inference::LoRAAdapter;
use crate::{Result, ZkAiError};

/// Adapter entry inside a signed pack manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoRAPackAdapter {
    /// Task name (e.g., "summarize", "translate_vi_en").
    pub task: String,
    /// Language or language pair (e.g., "vi", "vi_en").
    pub language: String,
    /// Relative path to the adapter file inside the pack.
    pub file: String,
    /// SHA-256 hash of the adapter file for integrity verification.
    pub sha256: String,
    /// LoRA rank (typically 8-64).
    pub rank: u32,
}

impl LoRAPackAdapter {
    /// Unique adapter identifier (e.g., "summarize.vi").
    pub fn id(&self) -> String {
        format!("{}.{}", self.task, self.language)
    }
}

/// Signed pack manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoRAPackManifest {
    /// Unique pack identifier (e.g., "legal-contracts-v1").
    pub id: String,
    /// Human-readable pack name.
    pub name: String,
    /// Pack author / publisher.
    pub author: String,
    /// Author Ed25519 public key as lowercase hex (64 characters).
    pub public_key: String,
    /// Ed25519 signature over the canonical manifest as lowercase hex
    /// (128 characters).
    pub signature: String,
    /// List of adapters included in this pack.
    pub adapters: Vec<LoRAPackAdapter>,
}

impl LoRAPackManifest {
    /// Build a canonical byte representation of the manifest for signing.
    /// Excludes the `signature` field and is stable across serializer versions.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"id=");
        buf.extend_from_slice(self.id.as_bytes());
        buf.push(b'\n');
        buf.extend_from_slice(b"name=");
        buf.extend_from_slice(self.name.as_bytes());
        buf.push(b'\n');
        buf.extend_from_slice(b"author=");
        buf.extend_from_slice(self.author.as_bytes());
        buf.push(b'\n');
        buf.extend_from_slice(b"public_key=");
        buf.extend_from_slice(self.public_key.as_bytes());
        buf.push(b'\n');
        buf.extend_from_slice(b"adapter_count=");
        buf.extend_from_slice(self.adapters.len().to_string().as_bytes());
        buf.push(b'\n');
        // Adapters are emitted in a deterministic order.
        for adapter in &self.adapters {
            buf.extend_from_slice(b"[adapter]\n");
            buf.extend_from_slice(b"task=");
            buf.extend_from_slice(adapter.task.as_bytes());
            buf.push(b'\n');
            buf.extend_from_slice(b"language=");
            buf.extend_from_slice(adapter.language.as_bytes());
            buf.push(b'\n');
            buf.extend_from_slice(b"file=");
            buf.extend_from_slice(adapter.file.as_bytes());
            buf.push(b'\n');
            buf.extend_from_slice(b"sha256=");
            buf.extend_from_slice(adapter.sha256.as_bytes());
            buf.push(b'\n');
            buf.extend_from_slice(b"rank=");
            buf.extend_from_slice(adapter.rank.to_string().as_bytes());
            buf.push(b'\n');
        }
        buf
    }
}

/// A verified LoRA adapter pack loaded from disk.
#[derive(Debug, Clone)]
pub struct LoRAPack {
    /// Verified manifest.
    pub manifest: LoRAPackManifest,
    /// Root directory containing the manifest and adapter files.
    pub root: PathBuf,
    /// Whether the pack's signature and file hashes were verified.
    pub verified: bool,
}

fn decode_hex(s: &str) -> Result<Vec<u8>> {
    if s.len() % 2 != 0 {
        return Err(ZkAiError::Crypto(format!(
            "hex string length must be even: {s}"
        )));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| {
                ZkAiError::Crypto(format!("invalid hex in '{s}': {e}"))
            })
        })
        .collect()
}

fn verify_sha256(path: &Path, expected: &str) -> Result<()> {
    let bytes = std::fs::read(path).map_err(|e| {
        ZkAiError::LoRA(format!("failed to read adapter file {path:?}: {e}"))
    })?;
    let hash = hex::encode(Sha256::digest(&bytes));
    if hash != expected {
        return Err(ZkAiError::LoRA(format!(
            "SHA-256 mismatch for {path:?}: expected {expected}, got {hash}"
        )));
    }
    Ok(())
}

impl LoRAPack {
    /// Load and verify a pack directory.
    ///
    /// The pack signature is verified against the author's public key. The
    /// author public key must also be present in `trusted_keys` for the pack
    /// to be accepted.
    pub fn load(root: &Path, trusted_keys: &[VerifyingKey]) -> Result<Self> {
        let manifest_path = root.join("pack.toml");
        let manifest_str = std::fs::read_to_string(&manifest_path).map_err(|e| {
            ZkAiError::LoRA(format!("failed to read pack manifest {manifest_path:?}: {e}"))
        })?;
        let manifest: LoRAPackManifest = toml::from_str(&manifest_str).map_err(|e| {
            ZkAiError::LoRA(format!("failed to parse pack manifest: {e}"))
        })?;

        // Decode public key and signature.
        let pk_bytes = decode_hex(&manifest.public_key)?;
        if pk_bytes.len() != 32 {
            return Err(ZkAiError::Crypto(format!(
                "invalid Ed25519 public key length: {} (expected 32)",
                pk_bytes.len()
            )));
        }
        let public_key = VerifyingKey::from_bytes(
            &pk_bytes.try_into().map_err(|_| {
                ZkAiError::Crypto("failed to convert public key bytes".to_string())
            })?,
        )
        .map_err(|e| ZkAiError::Crypto(format!("invalid Ed25519 public key: {e}")))?;

        let sig_bytes = decode_hex(&manifest.signature)?;
        if sig_bytes.len() != 64 {
            return Err(ZkAiError::Crypto(format!(
                "invalid Ed25519 signature length: {} (expected 64)",
                sig_bytes.len()
            )));
        }
        let signature = Signature::from_bytes(
            &sig_bytes.try_into().map_err(|_| {
                ZkAiError::Crypto("failed to convert signature bytes".to_string())
            })?,
        );

        // Reject if the author is not in the trusted-key allowlist.
        if !trusted_keys.iter().any(|k| *k == public_key) {
            return Err(ZkAiError::Crypto(format!(
                "pack {} public key not in trusted allowlist",
                manifest.id
            )));
        }

        // Verify the pack signature.
        let canonical = manifest.canonical_bytes();
        public_key
            .verify(&canonical, &signature)
            .map_err(|e| ZkAiError::Crypto(format!("pack signature verification failed: {e}")))?;

        // Verify each adapter file's integrity.
        for adapter in &manifest.adapters {
            let file_path = root.join(&adapter.file);
            verify_sha256(&file_path, &adapter.sha256)?;
        }

        Ok(Self {
            manifest,
            root: root.to_path_buf(),
            verified: true,
        })
    }

    /// Get a `LoRAAdapter` for a given task and language.
    pub fn get_adapter(&self, task: &str, language: &str) -> Result<LoRAAdapter> {
        let entry = self
            .manifest
            .adapters
            .iter()
            .find(|a| a.task == task && a.language == language)
            .ok_or_else(|| {
                ZkAiError::LoRA(format!(
                    "adapter {task}.{language} not found in pack {}",
                    self.manifest.id
                ))
            })?;
        let path = self.root.join(&entry.file);
        Ok(LoRAAdapter::new(&entry.task, &entry.language, &path, entry.rank))
    }
}

/// Marketplace registry of verified LoRA adapter packs.
#[derive(Debug, Clone, Default)]
pub struct Marketplace {
    /// Trusted author public keys.
    trusted_keys: Vec<VerifyingKey>,
    /// Loaded packs keyed by pack id.
    packs: HashMap<String, LoRAPack>,
}

impl Marketplace {
    /// Create a new marketplace with the given trusted author public keys.
    pub fn new(trusted_keys: Vec<VerifyingKey>) -> Self {
        Self {
            trusted_keys,
            packs: HashMap::new(),
        }
    }

    /// Parse a list of trusted public keys from lowercase hex strings.
    pub fn trusted_from_hex(hex_keys: &[String]) -> Result<Vec<VerifyingKey>> {
        hex_keys
            .iter()
            .map(|s| {
                let bytes = decode_hex(s)?;
                if bytes.len() != 32 {
                    return Err(ZkAiError::Crypto(format!(
                        "invalid trusted public key length: {}",
                        bytes.len()
                    )));
                }
                VerifyingKey::from_bytes(
                    &bytes.try_into().map_err(|_| {
                        ZkAiError::Crypto("failed to convert trusted public key".to_string())
                    })?,
                )
                .map_err(|e| ZkAiError::Crypto(format!("invalid trusted public key: {e}")))
            })
            .collect()
    }

    /// Load all packs from a marketplace directory.
    ///
    /// The directory is scanned one level deep; each subdirectory is treated as
    /// a pack. Invalid or untrusted packs are logged and skipped.
    pub fn load_dir(&mut self, dir: &Path) -> Result<()> {
        if !dir.exists() {
            return Err(ZkAiError::LoRA(format!("marketplace directory not found: {dir:?}")));
        }

        for entry in std::fs::read_dir(dir).map_err(|e| {
            ZkAiError::LoRA(format!("failed to read marketplace directory {dir:?}: {e}"))
        })? {
            let entry = entry.map_err(|e| {
                ZkAiError::LoRA(format!("failed to read marketplace entry: {e}"))
            })?;
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }

            match LoRAPack::load(&path, &self.trusted_keys) {
                Ok(pack) => {
                    tracing::info!(
                        pack_id = %pack.manifest.id,
                        path = ?path,
                        adapters = pack.manifest.adapters.len(),
                        "loaded verified LoRA pack"
                    );
                    self.packs.insert(pack.manifest.id.clone(), pack);
                }
                Err(e) => {
                    tracing::warn!(path = ?path, error = %e, "skipping unverified LoRA pack");
                }
            }
        }
        Ok(())
    }

    /// Add a single pack directory to the marketplace.
    pub fn load_pack(&mut self, root: &Path) -> Result<String> {
        let pack = LoRAPack::load(root, &self.trusted_keys)?;
        let id = pack.manifest.id.clone();
        self.packs.insert(id.clone(), pack);
        Ok(id)
    }

    /// Get a loaded pack by id.
    pub fn pack(&self, id: &str) -> Option<&LoRAPack> {
        self.packs.get(id)
    }

    /// List all loaded pack manifests.
    pub fn list_packs(&self) -> Vec<&LoRAPackManifest> {
        self.packs.values().map(|p| &p.manifest).collect()
    }

    /// List adapters in a pack.
    pub fn list_adapters(&self, pack_id: &str) -> Option<Vec<&LoRAPackAdapter>> {
        self.packs
            .get(pack_id)
            .map(|p| p.manifest.adapters.iter().collect())
    }

    /// Get a `LoRAAdapter` from a specific pack.
    pub fn get_adapter(&self, pack_id: &str, task: &str, language: &str) -> Result<LoRAAdapter> {
        let pack = self.packs.get(pack_id).ok_or_else(|| {
            ZkAiError::LoRA(format!("pack {pack_id} not found in marketplace"))
        })?;
        pack.get_adapter(task, language)
    }

    /// Return all adapters matching a task, across all packs.
    pub fn adapters_for_task(&self, task: &str) -> Vec<(String, LoRAAdapter)> {
        self.packs
            .values()
            .flat_map(|pack| {
                let pack_id = pack.manifest.id.clone();
                pack.manifest.adapters.iter().filter_map(move |a| {
                    if a.task == task {
                        match pack.get_adapter(&a.task, &a.language) {
                            Ok(adapter) => Some((pack_id.clone(), adapter)),
                            Err(e) => {
                                tracing::warn!(
                                    pack = %pack_id,
                                    adapter = %a.id(),
                                    error = %e,
                                    "failed to load adapter from pack"
                                );
                                None
                            }
                        }
                    } else {
                        None
                    }
                })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{SigningKey, Signer};
    use tempfile::TempDir;

    fn generate_signing_key() -> SigningKey {
        let mut bytes = [0u8; 32];
        getrandom::getrandom(&mut bytes).expect("getrandom failed");
        SigningKey::from_bytes(&bytes)
    }

    fn generate_pack(dir: &Path, signing_key: &SigningKey) -> LoRAPackManifest {
        let public_key = hex::encode(signing_key.verifying_key().to_bytes());

        let mut manifest = LoRAPackManifest {
            id: "test-pack".to_string(),
            name: "Test Pack".to_string(),
            author: "test-author".to_string(),
            public_key,
            signature: String::new(),
            adapters: vec![LoRAPackAdapter {
                task: "summarize".to_string(),
                language: "en".to_string(),
                file: "summarize.en.safetensors".to_string(),
                sha256: String::new(),
                rank: 8,
            }],
        };

        // Create adapter file.
        let adapter_path = dir.join(&manifest.adapters[0].file);
        let adapter_bytes = b"fake-adapter-weights";
        std::fs::write(&adapter_path, adapter_bytes).unwrap();
        manifest.adapters[0].sha256 = hex::encode(Sha256::digest(adapter_bytes));

        // Sign canonical manifest.
        let canonical = manifest.canonical_bytes();
        let signature = signing_key.sign(&canonical);
        manifest.signature = hex::encode(signature.to_bytes());

        // Write pack.toml.
        let toml = toml::to_string(&manifest).unwrap();
        std::fs::write(dir.join("pack.toml"), toml).unwrap();

        manifest
    }

    #[test]
    fn test_pack_load_and_verify() {
        let dir = TempDir::new().unwrap();
        let signing_key = generate_signing_key();
        let trusted_keys = vec![signing_key.verifying_key()];

        generate_pack(dir.path(), &signing_key);

        let pack = LoRAPack::load(dir.path(), &trusted_keys).unwrap();
        assert!(pack.verified);
        assert_eq!(pack.manifest.id, "test-pack");

        let adapter = pack.get_adapter("summarize", "en").unwrap();
        assert_eq!(adapter.id(), "summarize.en");
    }

    #[test]
    fn test_pack_rejects_untrusted_key() {
        let dir = TempDir::new().unwrap();
        let signing_key = generate_signing_key();
        let other_key = generate_signing_key().verifying_key();

        generate_pack(dir.path(), &signing_key);

        assert!(LoRAPack::load(dir.path(), &[other_key]).is_err());
    }

    #[test]
    fn test_marketplace_load_dir() {
        let root = TempDir::new().unwrap();
        let pack_dir = root.path().join("packs").join("test");
        std::fs::create_dir_all(&pack_dir).unwrap();

        let signing_key = generate_signing_key();
        generate_pack(&pack_dir, &signing_key);

        let mut marketplace = Marketplace::new(vec![signing_key.verifying_key()]);
        marketplace.load_dir(root.path().join("packs").as_path()).unwrap();

        assert_eq!(marketplace.list_packs().len(), 1);
        let adapter = marketplace.get_adapter("test-pack", "summarize", "en").unwrap();
        assert_eq!(adapter.id(), "summarize.en");
    }

    #[test]
    fn test_pack_rejects_tampered_adapter() {
        let dir = TempDir::new().unwrap();
        let signing_key = generate_signing_key();
        let trusted_keys = vec![signing_key.verifying_key()];

        generate_pack(dir.path(), &signing_key);

        // Tamper with the adapter file after signing
        std::fs::write(
            dir.path().join("summarize.en.safetensors"),
            b"tampered-weights",
        )
        .unwrap();

        let err = LoRAPack::load(dir.path(), &trusted_keys).unwrap_err();
        assert!(
            matches!(err, ZkAiError::LoRA(ref msg) if msg.contains("SHA-256 mismatch")),
            "expected SHA-256 mismatch error, got: {err:?}"
        );
    }

    #[test]
    fn test_pack_rejects_corrupted_signature() {
        let dir = TempDir::new().unwrap();
        let signing_key = generate_signing_key();
        let trusted_keys = vec![signing_key.verifying_key()];

        generate_pack(dir.path(), &signing_key);

        // Corrupt the signature in pack.toml
        let manifest_path = dir.path().join("pack.toml");
        let manifest_str = std::fs::read_to_string(&manifest_path).unwrap();
        // Flip the first hex char of the signature
        let corrupted = manifest_str.replacen("signature = \"", "signature = \"0", 1);
        std::fs::write(&manifest_path, corrupted).unwrap();

        let err = LoRAPack::load(dir.path(), &trusted_keys);
        assert!(err.is_err(), "corrupted signature should be rejected");
    }

    #[test]
    fn test_marketplace_skips_untrusted_in_load_dir() {
        let root = TempDir::new().unwrap();
        let pack_dir = root.path().join("packs").join("untrusted");
        std::fs::create_dir_all(&pack_dir).unwrap();

        // Sign with a key that is NOT in the trusted set
        let untrusted_key = generate_signing_key();
        generate_pack(&pack_dir, &untrusted_key);

        let trusted_key = generate_signing_key();
        let mut marketplace = Marketplace::new(vec![trusted_key.verifying_key()]);
        marketplace.load_dir(root.path().join("packs").as_path()).unwrap();

        // Untrusted pack should be skipped, not loaded
        assert_eq!(marketplace.list_packs().len(), 0);
    }

    #[test]
    fn test_adapters_for_task() {
        let root = TempDir::new().unwrap();
        let pack_dir = root.path().join("packs").join("test");
        std::fs::create_dir_all(&pack_dir).unwrap();

        let signing_key = generate_signing_key();
        generate_pack(&pack_dir, &signing_key);

        let mut marketplace = Marketplace::new(vec![signing_key.verifying_key()]);
        marketplace.load_dir(root.path().join("packs").as_path()).unwrap();

        let adapters = marketplace.adapters_for_task("summarize");
        assert_eq!(adapters.len(), 1);
        assert_eq!(adapters[0].0, "test-pack");
        assert_eq!(adapters[0].1.id(), "summarize.en");

        // Non-existent task returns empty
        assert!(marketplace.adapters_for_task("nonexistent").is_empty());
    }

    #[test]
    fn test_trusted_from_hex() {
        let signing_key = generate_signing_key();
        let pk_hex = hex::encode(signing_key.verifying_key().to_bytes());

        let keys = Marketplace::trusted_from_hex(&[pk_hex.clone()]).unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0], signing_key.verifying_key());

        // Invalid hex should fail
        assert!(Marketplace::trusted_from_hex(&["invalid".to_string()]).is_err());

        // Wrong length should fail
        assert!(Marketplace::trusted_from_hex(&["abcd".to_string()]).is_err());
    }
}
