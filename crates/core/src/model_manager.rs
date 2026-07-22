//! Model lifecycle management: bundled defaults, CDN download,
//! local cache with LRU eviction.
//!
//! Models are stored as mmap-able files on disk. The manager handles:
//! - Bundled models (shipped with the app binary)
//! - On-demand download from CDN with SHA-256 integrity verification
//! - LRU cache eviction when the cache exceeds the tier-based limit
//! - Background download with progress reporting

use std::path::{Path, PathBuf};
use std::io::Write;
use std::collections::HashMap;
use std::sync::Arc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use crate::profiler::{DeviceProfile, DeviceTier};
use crate::{Result, ZkAiError};

/// A progress update for a model download.
#[derive(Debug, Clone)]
pub struct DownloadProgress {
    /// Number of bytes downloaded so far.
    pub downloaded: u64,
    /// Total bytes to download (0 if unknown).
    pub total: u64,
}

impl DownloadProgress {
    /// Progress as a fraction (0.0 to 1.0). Returns 0.0 if total is unknown.
    pub fn fraction(&self) -> f32 {
        if self.total > 0 {
            self.downloaded as f32 / self.total as f32
        } else {
            0.0
        }
    }

    /// Progress as a percentage (0 to 100). Returns 0 if total is unknown.
    pub fn percent(&self) -> u32 {
        (self.fraction() * 100.0) as u32
    }
}

/// Callback trait for receiving download progress updates.
/// Implementations are called periodically during a model download.
pub trait ProgressCallback: Send + Sync {
    fn on_progress(&self, progress: DownloadProgress);
}

/// A simple progress callback that stores the latest progress in an Arc.
pub struct SharedProgressCallback {
    pub progress: Arc<std::sync::Mutex<DownloadProgress>>,
}

impl SharedProgressCallback {
    pub fn new() -> Self {
        Self {
            progress: Arc::new(std::sync::Mutex::new(DownloadProgress { downloaded: 0, total: 0 })),
        }
    }

    pub fn current(&self) -> DownloadProgress {
        self.progress.lock().unwrap().clone()
    }
}

impl Default for SharedProgressCallback {
    fn default() -> Self {
        Self::new()
    }
}

impl ProgressCallback for SharedProgressCallback {
    fn on_progress(&self, progress: DownloadProgress) {
        *self.progress.lock().unwrap() = progress;
    }
}

/// Configuration for the model cache.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelCacheConfig {
    /// Root directory for cached model files.
    pub cache_dir: PathBuf,
    /// Maximum cache size in MB (tier-dependent).
    pub max_cache_mb: u32,
    /// CDN base URL for downloading models.
    pub cdn_base_url: String,
}

impl ModelCacheConfig {
    pub fn from_profile(cache_dir: impl AsRef<Path>, profile: &DeviceProfile) -> Self {
        let max_cache_mb = match profile.tier {
            DeviceTier::HighEnd => 2048,
            DeviceTier::MidRange => 512,
            DeviceTier::LowEnd => 150,
            DeviceTier::Throttled => 150,
        };
        Self {
            cache_dir: cache_dir.as_ref().to_path_buf(),
            max_cache_mb,
            cdn_base_url: "https://cdn.zkai.dev".to_string(),
        }
    }
}

/// Specification for a model to load.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelSpec {
    /// Model name (e.g., "mt5-small", "multilingual-e5-small").
    pub name: String,
    /// Model version (e.g., "1.0.0").
    pub version: String,
    /// Quantization level.
    pub quantization: Quantization,
    /// SHA-256 hash of the model file for integrity verification.
    /// If None, integrity check is skipped (not recommended).
    pub sha256: Option<String>,
}

impl ModelSpec {
    /// Standard mT5-small int8 model.
    pub fn mt5_small_int8() -> Self {
        Self {
            name: "mt5-small".to_string(),
            version: "1.0.0".to_string(),
            quantization: Quantization::Int8,
            sha256: None,
        }
    }

    /// Standard multilingual-e5-small int8 model.
    pub fn e5_small_int8() -> Self {
        Self {
            name: "multilingual-e5-small".to_string(),
            version: "1.0.0".to_string(),
            quantization: Quantization::Int8,
            sha256: None,
        }
    }

    /// CLIP ViT-B/32 int8 model.
    pub fn clip_int8() -> Self {
        Self {
            name: "clip-vit-base-patch32".to_string(),
            version: "1.0.0".to_string(),
            quantization: Quantization::Int8,
            sha256: None,
        }
    }

    /// Whisper-tiny int8 model for speech-to-text.
    /// On-demand only, MidRange+ tier. ~30MB.
    pub fn whisper_tiny_int8() -> Self {
        Self {
            name: "whisper-tiny".to_string(),
            version: "1.0.0".to_string(),
            quantization: Quantization::Int8,
            sha256: None,
        }
    }

    /// mT5-small int4 model for throttled/low-end fallback.
    /// ~25MB, reduced quality but lower memory.
    pub fn mt5_small_int4() -> Self {
        Self {
            name: "mt5-small".to_string(),
            version: "1.0.0".to_string(),
            quantization: Quantization::Int4,
            sha256: None,
        }
    }

    /// e5-small int4 model for throttled/low-end fallback.
    /// ~25MB, reduced quality but lower memory.
    pub fn e5_small_int4() -> Self {
        Self {
            name: "multilingual-e5-small".to_string(),
            version: "1.0.0".to_string(),
            quantization: Quantization::Int4,
            sha256: None,
        }
    }

    /// File name for this model in the cache.
    pub fn filename(&self) -> String {
        format!("{}-{}-{}.onnx", self.name, self.version, self.quantization)
    }

    /// CDN URL for downloading this model.
    pub fn cdn_url(&self, base: &str) -> String {
        format!(
            "{}/models/{}/{}/{}/model.onnx",
            base, self.name, self.version, self.quantization
        )
    }

    /// Local cache path for this model.
    pub fn cache_path(&self, cache_dir: &Path) -> PathBuf {
        cache_dir.join("models").join(self.filename())
    }

    /// Set the SHA-256 hash for this model spec (builder pattern).
    pub fn with_sha256(mut self, hash: impl Into<String>) -> Self {
        self.sha256 = Some(hash.into());
        self
    }

    /// Fetch SHA-256 hashes for all known models from the CDN manifest.
    /// The manifest is a JSON object mapping model filenames to hashes:
    /// `{ "mt5-small-1.0.0-int8.onnx": "abc123...", ... }`
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn fetch_hashes_from_cdn(cdn_base_url: &str) -> Result<HashMap<String, String>> {
        let manifest_url = format!("{}/models/hashes.json", cdn_base_url);
        tracing::info!(url = %manifest_url, "fetching model hash manifest");

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .map_err(|e| ZkAiError::ModelDownload(e.to_string()))?;

        let resp = client
            .get(&manifest_url)
            .send()
            .await
            .map_err(|e| ZkAiError::ModelDownload(e.to_string()))?;

        if !resp.status().is_success() {
            tracing::warn!(
                status = %resp.status(),
                "hash manifest not available; integrity checks will be skipped"
            );
            return Ok(HashMap::new());
        }

        let hashes: HashMap<String, String> = resp
            .json()
            .await
            .map_err(|e| ZkAiError::ModelDownload(format!("parse hash manifest: {e}")))?;

        tracing::info!(models = hashes.len(), "loaded model hash manifest");
        Ok(hashes)
    }

    /// Verify the integrity of a downloaded model file against the expected hash.
    pub fn verify_integrity(&self, bytes: &[u8]) -> Result<()> {
        if let Some(expected_hash) = &self.sha256 {
            let actual_hash = hex::encode(Sha256::digest(bytes));
            if actual_hash != *expected_hash {
                return Err(ZkAiError::ModelIntegrity {
                    expected: expected_hash.clone(),
                    actual: actual_hash,
                });
            }
        }
        Ok(())
    }

    /// Verify a pre-computed SHA-256 hex hash against the expected hash.
    /// Avoids re-reading the file when the hash was computed during streaming.
    pub fn verify_hash(&self, actual_hash: &str) -> Result<()> {
        if let Some(expected_hash) = &self.sha256 {
            if actual_hash != expected_hash {
                return Err(ZkAiError::ModelIntegrity {
                    expected: expected_hash.clone(),
                    actual: actual_hash.to_string(),
                });
            }
        }
        Ok(())
    }

    /// Apply a hash from a manifest map if the filename matches.
    pub fn apply_hash_from_manifest(&mut self, manifest: &HashMap<String, String>) {
        if self.sha256.is_none() {
            if let Some(hash) = manifest.get(&self.filename()) {
                self.sha256 = Some(hash.clone());
            }
        }
    }
}

/// Quantization level for a model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Quantization {
    /// 8-bit integer quantization (default, 4x smaller than fp32).
    Int8,
    /// 4-bit integer quantization (8x smaller, ~5% quality loss).
    Int4,
    /// 16-bit float (2x smaller, no quality loss).
    Fp16,
    /// 32-bit float (full precision, no quantization).
    Fp32,
}

impl std::fmt::Display for Quantization {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Quantization::Int8 => write!(f, "int8"),
            Quantization::Int4 => write!(f, "int4"),
            Quantization::Fp16 => write!(f, "fp16"),
            Quantization::Fp32 => write!(f, "fp32"),
        }
    }
}

/// An entry in the model cache.
#[derive(Debug, Clone)]
pub struct ModelEntry {
    pub spec: ModelSpec,
    pub path: PathBuf,
    pub size_bytes: u64,
    pub last_accessed: std::time::SystemTime,
}

/// Manages model files on disk: bundled, downloaded, cached, evicted.
pub struct ModelManager {
    config: ModelCacheConfig,
    /// Directory containing bundled models (shipped with the app).
    bundled_dir: Option<PathBuf>,
    /// Index of cached models.
    cache_index: HashMap<String, ModelEntry>,
}

impl ModelManager {
    /// Create a new model manager with the given cache directory
    /// and device profile (for tier-based cache limits).
    pub fn new(cache_dir: impl AsRef<Path>, profile: &DeviceProfile) -> Result<Self> {
        let config = ModelCacheConfig::from_profile(cache_dir, profile);
        let cache_dir = config.cache_dir.clone();

        // Ensure cache directory exists
        std::fs::create_dir_all(cache_dir.join("models"))
            .map_err(|e| ZkAiError::Cache(format!("create cache dir: {e}")))?;

        let mut manager = Self {
            config,
            bundled_dir: None,
            cache_index: HashMap::new(),
        };

        // Scan existing cache
        manager.scan_cache()?;

        Ok(manager)
    }

    /// Set the bundled models directory (models shipped with the app).
    pub fn set_bundled_dir(&mut self, dir: impl AsRef<Path>) {
        self.bundled_dir = Some(dir.as_ref().to_path_buf());
    }

    /// Ensure a model is available locally. If it's bundled, returns
    /// the bundled path. If it's cached, returns the cache path.
    /// Otherwise, downloads it from CDN.
    pub async fn ensure_model(&mut self, spec: &ModelSpec) -> Result<PathBuf> {
        self.ensure_model_with_progress(spec, None).await
    }

    /// Ensure a model is available locally, with optional progress callback.
    pub async fn ensure_model_with_progress(
        &mut self,
        spec: &ModelSpec,
        progress: Option<Arc<dyn ProgressCallback>>,
    ) -> Result<PathBuf> {
        // Check bundled first
        if let Some(bundled_dir) = &self.bundled_dir {
            let bundled_path = bundled_dir.join(spec.filename());
            if bundled_path.exists() {
                return Ok(bundled_path);
            }
        }

        // Check cache
        let cache_path = spec.cache_path(&self.config.cache_dir);
        if cache_path.exists() {
            // Update last accessed
            if let Some(entry) = self.cache_index.get_mut(&spec.filename()) {
                entry.last_accessed = std::time::SystemTime::now();
            }
            return Ok(cache_path);
        }

        // Download from CDN
        self.download_model(spec, progress).await?;

        // Evict if over limit
        self.evict_if_needed()?;

        Ok(spec.cache_path(&self.config.cache_dir))
    }

    /// Download a model from CDN to the local cache with streaming and progress.
    async fn download_model(
        &mut self,
        spec: &ModelSpec,
        progress: Option<Arc<dyn ProgressCallback>>,
    ) -> Result<()> {
        let url = spec.cdn_url(&self.config.cdn_base_url);
        let dest = spec.cache_path(&self.config.cache_dir);

        tracing::info!(model = %spec.name, url = %url, "downloading model");

        #[cfg(not(target_arch = "wasm32"))]
        {
            let client = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(300))
                .build()
                .map_err(|e| ZkAiError::ModelDownload(e.to_string()))?;

            let resp = client
                .get(&url)
                .send()
                .await
                .map_err(|e| ZkAiError::ModelDownload(e.to_string()))?;

            if !resp.status().is_success() {
                return Err(ZkAiError::ModelDownload(format!(
                    "HTTP {} for {}",
                    resp.status(),
                    url
                )));
            }

            let total = resp.content_length().unwrap_or(0);
            if let Some(cb) = &progress {
                cb.on_progress(DownloadProgress { downloaded: 0, total });
            }

            // Stream the response body directly to disk, hashing as we go
            use futures::StreamExt;
            let mut file = std::fs::File::create(&dest)
                .map_err(|e| ZkAiError::ModelDownload(format!("create file: {e}")))?;
            let mut body = resp.bytes_stream();
            let mut downloaded: u64 = 0;
            let mut last_report: u64 = 0;
            let mut hasher = Sha256::new();
            const REPORT_INTERVAL: u64 = 64 * 1024; // report every 64KB

            while let Some(chunk_result) = body.next().await {
                let chunk = chunk_result
                    .map_err(|e| ZkAiError::ModelDownload(e.to_string()))?;
                downloaded += chunk.len() as u64;
                hasher.update(&chunk);
                std::io::Write::write_all(&mut file, &chunk)
                    .map_err(|e| ZkAiError::ModelDownload(format!("write chunk: {e}")))?;

                if let Some(cb) = &progress {
                    if downloaded - last_report >= REPORT_INTERVAL || (total > 0 && downloaded == total) {
                        cb.on_progress(DownloadProgress { downloaded, total });
                        last_report = downloaded;
                    }
                }
            }

            if let Some(cb) = &progress {
                cb.on_progress(DownloadProgress { downloaded, total });
            }

            // Flush file to disk
            file.flush()
                .map_err(|e| ZkAiError::ModelDownload(format!("flush file: {e}")))?;
            drop(file);

            // Integrity check using hash computed during download (no re-read needed)
            let hash = hex::encode(hasher.finalize());
            spec.verify_hash(&hash)?;
            let size_bytes = downloaded;

            tracing::info!(
                model = %spec.name,
                size_mb = size_bytes / (1024 * 1024),
                "model downloaded"
            );

            // Update cache index
            self.cache_index.insert(
                spec.filename(),
                ModelEntry {
                    spec: spec.clone(),
                    path: dest.clone(),
                    size_bytes,
                    last_accessed: std::time::SystemTime::now(),
                },
            );
        }

        #[cfg(target_arch = "wasm32")]
        {
            // On WASM, download is handled by the JS layer (fetch API)
            // and the file is placed in the virtual FS by the binding.
            // The core just verifies it exists.
            if !dest.exists() {
                return Err(ZkAiError::ModelDownload(format!(
                    "model not found at {:?} — WASM binding must download first",
                    dest
                )));
            }
        }

        Ok(())
    }

    /// Scan the cache directory and populate the index.
    fn scan_cache(&mut self) -> Result<()> {
        let models_dir = self.config.cache_dir.join("models");
        if !models_dir.exists() {
            return Ok(());
        }

        for entry in std::fs::read_dir(&models_dir)
            .map_err(|e| ZkAiError::Cache(format!("read cache dir: {e}")))?
        {
            let entry = entry.map_err(|e| ZkAiError::Cache(format!("read dir entry: {e}")))?;
            let path = entry.path();
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                if name.ends_with(".onnx") {
                    let metadata = entry.metadata().map_err(|e| ZkAiError::Cache(e.to_string()))?;
                    self.cache_index.insert(
                        name.to_string(),
                        ModelEntry {
                            spec: parse_model_filename(name),
                            path: path.clone(),
                            size_bytes: metadata.len(),
                            last_accessed: metadata
                                .accessed()
                                .unwrap_or(std::time::SystemTime::now()),
                        },
                    );
                }
            }
        }

        Ok(())
    }

    /// Evict least-recently-used models if cache exceeds the limit.
    fn evict_if_needed(&mut self) -> Result<()> {
        let max_bytes = (self.config.max_cache_mb as u64) * 1024 * 1024;
        let total: u64 = self.cache_index.values().map(|e| e.size_bytes).sum();

        if total <= max_bytes {
            return Ok(());
        }

        // Sort by last accessed (ascending = oldest first)
        let mut entries: Vec<(String, u64, std::time::SystemTime)> = self
            .cache_index
            .iter()
            .map(|(k, v)| (k.clone(), v.size_bytes, v.last_accessed))
            .collect();
        entries.sort_by_key(|(_, _, t)| *t);

        let mut current = total;
        for (name, size, _) in &entries {
            if current <= max_bytes {
                break;
            }
            let path = self.config.cache_dir.join("models").join(name);
            tracing::info!(model = %name, size_mb = size / (1024 * 1024), "evicting cached model");
            let _ = std::fs::remove_file(&path);
            self.cache_index.remove(name);
            current -= size;
        }

        Ok(())
    }

    /// Pre-download a model (for settings UI "download for offline use").
    pub async fn preload(&mut self, spec: &ModelSpec) -> Result<()> {
        self.ensure_model(spec).await?;
        Ok(())
    }

    /// Pre-download a model with progress reporting.
    pub async fn preload_with_progress(
        &mut self,
        spec: &ModelSpec,
        progress: Arc<dyn ProgressCallback>,
    ) -> Result<()> {
        self.ensure_model_with_progress(spec, Some(progress)).await?;
        Ok(())
    }

    /// Check if a model is available locally (bundled or cached).
    pub fn is_available(&self, spec: &ModelSpec) -> bool {
        if let Some(bundled_dir) = &self.bundled_dir {
            if bundled_dir.join(spec.filename()).exists() {
                return true;
            }
        }
        spec.cache_path(&self.config.cache_dir).exists()
    }

    /// Get the current cache size in bytes.
    pub fn cache_size_bytes(&self) -> u64 {
        self.cache_index.values().map(|e| e.size_bytes).sum()
    }

    /// Get the maximum cache size in bytes.
    pub fn max_cache_bytes(&self) -> u64 {
        (self.config.max_cache_mb as u64) * 1024 * 1024
    }

    /// Get the cache directory path (for resolving adapter paths etc.).
    pub fn cache_dir(&self) -> &Path {
        &self.config.cache_dir
    }

    /// List all cached models.
    pub fn cached_models(&self) -> Vec<&ModelEntry> {
        self.cache_index.values().collect()
    }

    /// Clear the entire cache.
    pub fn clear_cache(&mut self) -> Result<()> {
        for entry in self.cache_index.values() {
            let _ = std::fs::remove_file(&entry.path);
        }
        self.cache_index.clear();
        Ok(())
    }
}

/// Parse a model filename (e.g., "mt5-small-1.0.0-int8.onnx") into a ModelSpec.
/// Falls back to a generic spec if the filename doesn't match the expected pattern.
fn parse_model_filename(filename: &str) -> ModelSpec {
    let stem = filename.strip_suffix(".onnx").unwrap_or(filename);
    let parts: Vec<&str> = stem.rsplitn(3, '-').collect();
    // parts is reversed: [quantization, version, name...]
    if parts.len() == 3 {
        let quantization = match parts[0] {
            "int8" => Quantization::Int8,
            "int4" => Quantization::Int4,
            "fp16" => Quantization::Fp16,
            "fp32" => Quantization::Fp32,
            _ => Quantization::Int8,
        };
        ModelSpec {
            name: parts[2].to_string(),
            version: parts[1].to_string(),
            quantization,
            sha256: None,
        }
    } else {
        ModelSpec {
            name: stem.to_string(),
            version: "unknown".to_string(),
            quantization: Quantization::Int8,
            sha256: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profiler::{DeviceProfile, DeviceTier, Acceleration, ThermalState};

    fn test_profile() -> DeviceProfile {
        DeviceProfile {
            tier: DeviceTier::HighEnd,
            acceleration: Acceleration::Metal,
            total_memory_mb: 16384,
            available_memory_mb: 16384,
            cpu_cores: 10,
            has_npu: true,
            npu_tops: Some(15),
            battery_level: Some(80),
            thermal_state: ThermalState::Nominal,
            platform: "macos".to_string(),
            arch: "aarch64".to_string(),
        }
    }

    #[test]
    fn test_cache_config_from_profile() {
        let profile = test_profile();
        let config = ModelCacheConfig::from_profile("/tmp/zk-ai-test", &profile);
        assert_eq!(config.max_cache_mb, 2048); // HighEnd
    }

    #[test]
    fn test_cache_config_low_end() {
        let profile = DeviceProfile {
            tier: DeviceTier::LowEnd,
            ..test_profile()
        };
        let config = ModelCacheConfig::from_profile("/tmp/zk-ai-test", &profile);
        assert_eq!(config.max_cache_mb, 150);
    }

    #[test]
    fn test_model_spec_filename() {
        let spec = ModelSpec::mt5_small_int8();
        assert_eq!(spec.filename(), "mt5-small-1.0.0-int8.onnx");
    }

    #[test]
    fn test_model_spec_cdn_url() {
        let spec = ModelSpec::mt5_small_int8();
        let url = spec.cdn_url("https://cdn.zkai.dev");
        assert_eq!(
            url,
            "https://cdn.zkai.dev/models/mt5-small/1.0.0/int8/model.onnx"
        );
    }

    #[test]
    fn test_model_manager_creation() {
        let tmp = tempfile::tempdir().unwrap();
        let profile = test_profile();
        let manager = ModelManager::new(tmp.path(), &profile).unwrap();
        assert_eq!(manager.cache_size_bytes(), 0);
    }

    #[test]
    fn test_model_manager_is_available_false() {
        let tmp = tempfile::tempdir().unwrap();
        let profile = test_profile();
        let manager = ModelManager::new(tmp.path(), &profile).unwrap();
        assert!(!manager.is_available(&ModelSpec::mt5_small_int8()));
    }

    #[test]
    fn test_download_progress_fraction() {
        let p = DownloadProgress { downloaded: 50, total: 200 };
        assert!((p.fraction() - 0.25).abs() < 1e-6);
        assert_eq!(p.percent(), 25);
    }

    #[test]
    fn test_download_progress_unknown_total() {
        let p = DownloadProgress { downloaded: 100, total: 0 };
        assert_eq!(p.fraction(), 0.0);
        assert_eq!(p.percent(), 0);
    }

    #[test]
    fn test_shared_progress_callback() {
        let cb = SharedProgressCallback::new();
        assert_eq!(cb.current().downloaded, 0);
        cb.on_progress(DownloadProgress { downloaded: 42, total: 100 });
        assert_eq!(cb.current().downloaded, 42);
        assert_eq!(cb.current().percent(), 42);
    }

    #[test]
    fn test_model_spec_with_sha256() {
        let spec = ModelSpec::mt5_small_int8()
            .with_sha256("abc123def456");
        assert_eq!(spec.sha256.as_deref(), Some("abc123def456"));
    }

    #[test]
    fn test_model_spec_verify_integrity_ok() {
        let data = b"test data";
        let hash = hex::encode(Sha256::digest(data));
        let spec = ModelSpec::mt5_small_int8().with_sha256(&hash);
        assert!(spec.verify_integrity(data).is_ok());
    }

    #[test]
    fn test_model_spec_verify_integrity_mismatch() {
        let spec = ModelSpec::mt5_small_int8()
            .with_sha256("0000000000000000000000000000000000000000000000000000000000000000");
        assert!(spec.verify_integrity(b"test data").is_err());
    }

    #[test]
    fn test_model_spec_verify_integrity_no_hash() {
        let spec = ModelSpec::mt5_small_int8();
        // No hash set — should pass (no check)
        assert!(spec.verify_integrity(b"test data").is_ok());
    }

    #[test]
    fn test_model_spec_apply_hash_from_manifest() {
        let mut spec = ModelSpec::mt5_small_int8();
        let mut manifest = HashMap::new();
        manifest.insert(
            "mt5-small-1.0.0-int8.onnx".to_string(),
            "deadbeef".to_string(),
        );
        spec.apply_hash_from_manifest(&manifest);
        assert_eq!(spec.sha256.as_deref(), Some("deadbeef"));
    }

    #[test]
    fn test_model_spec_apply_hash_from_manifest_no_match() {
        let mut spec = ModelSpec::mt5_small_int8();
        let manifest = HashMap::new();
        spec.apply_hash_from_manifest(&manifest);
        assert!(spec.sha256.is_none());
    }
}
