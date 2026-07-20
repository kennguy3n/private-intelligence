//! zk-ai-core: the cross-platform on-device AI inference engine.
//!
//! This crate is the single source of truth for all AI inference logic.
//! Platform bindings (WASM, UniFFI, N-API, cgo) are thin wrappers that
//! expose the same API surface through their respective FFI mechanisms.
//!
//! # Architecture
//!
//! - [`profiler`] — detects device capabilities (GPU, NPU, memory, battery)
//!   and assigns a [`DeviceTier`] that governs model selection and resource limits.
//! - [`model_manager`] — manages model lifecycle: bundled defaults, CDN
//!   download, local cache with LRU eviction.
//! - [`inference`] — inference session lifecycle, LoRA adapter hot-swap,
//!   quantization config, decoding strategies.
//! - [`governor`] — resource governor that prevents inference from
//!   degrading the device experience (CPU, GPU, RAM, battery, thermal).
//! - [`pipeline`] — task-specific pipelines (summarize, translate,
//!   key_points, generate_doc, generate_slides, image_search).
//! - [`swarm`] — swarm inference coordinator for distributed AI across
//!   devices in a group (via KChat MLS/XMPP).
//!
//! # Privacy
//!
//! All inference runs on-client. The server never sees plaintext unless
//! the caller explicitly opts into server-side offload for
//! managed-encrypted content. Strict zero-knowledge folders must run
//! inference client-side only.

pub mod error;
pub mod profiler;
pub mod model_manager;
pub mod inference;
pub mod governor;
pub mod pipeline;
pub mod swarm;
pub mod tokenizer;
pub mod simple_rng;

pub use error::{ZkAiError, Result};
pub use profiler::{DeviceProfile, DeviceTier, Acceleration, ThermalState, DeviceProfiler};
pub use model_manager::{ModelManager, ModelEntry, ModelSpec, ModelCacheConfig, DownloadProgress, ProgressCallback, SharedProgressCallback};
pub use inference::{InferenceSession, InferenceConfig, InferenceOutput, DecodeStrategy, Quantization, LoRAAdapter};
pub use governor::{ResourceGovernor, GovernorConfig};
pub use pipeline::{Task, TaskResult, TaskOptions};
pub use pipeline::image_index::{ImageIndex, ImageEntry, ImageSearchHit, cosine_similarity};
pub use pipeline::text_index::{TextIndex, TextEntry, TextSearchHit};
pub use tokenizer::{AiTokenizer, EncodedInput};
pub use swarm::{SwarmCoordinator, DeviceCapability, InferenceRequest, InferenceResult, SwarmTransport, capability_from_profile};

use std::path::PathBuf;
use std::sync::Arc;

/// The top-level engine that ties together all subsystems.
///
/// Consumers create an [`AiEngine`] once at app startup, then call
/// task methods (`summarize`, `translate`, etc.) as needed. The engine
/// manages the inference session, model loading, and resource governance
/// internally.
pub struct AiEngine {
    profile: DeviceProfile,
    model_manager: ModelManager,
    governor: ResourceGovernor,
    session: Option<InferenceSession>,
}

impl AiEngine {
    /// Create a new engine. Runs device profiling and initializes
    /// the model manager with the given cache directory.
    pub async fn new(cache_dir: impl AsRef<std::path::Path>) -> Result<Self> {
        let profile = DeviceProfiler::detect().await?;
        let model_manager = ModelManager::new(cache_dir, &profile)?;
        let governor = ResourceGovernor::new(GovernorConfig::from_tier(&profile.tier));
        tracing::info!(
            tier = ?profile.tier,
            acceleration = ?profile.acceleration,
            memory_mb = profile.available_memory_mb,
            "zk-ai engine initialized"
        );
        Ok(Self {
            profile,
            model_manager,
            governor,
            session: None,
        })
    }

    /// Returns the detected device profile.
    pub fn profile(&self) -> &DeviceProfile {
        &self.profile
    }

    /// Returns the model manager (for pre-downloading models, checking
    /// cache status, etc.).
    pub fn model_manager(&self) -> &ModelManager {
        &self.model_manager
    }

    /// Ensure a base model is loaded and ready for inference.
    /// If a different model is currently loaded, it will be unloaded first.
    pub async fn ensure_model(&mut self, spec: &ModelSpec) -> Result<()> {
        let needed_filename = spec.filename();
        if let Some(session) = &self.session {
            if session.model_filename() == needed_filename {
                return Ok(());
            }
            // Wrong model loaded — unload it first
            tracing::info!(
                current = session.model_filename(),
                needed = needed_filename,
                "switching models"
            );
            if let Some(mut old) = self.session.take() {
                old.unload().await?;
            }
        }

        let model_path = self.model_manager.ensure_model(spec).await?;
        let config = InferenceConfig::from_profile(&self.profile);
        let session = InferenceSession::load(&model_path, config).await?;
        self.session = Some(session);
        Ok(())
    }

    /// Run a summarization task.
    pub async fn summarize(
        &mut self,
        text: &str,
        language: &str,
        options: TaskOptions,
    ) -> Result<TaskResult> {
        pipeline::summarize::run(self, text, language, options).await
    }

    /// Run a key-point extraction task.
    pub async fn key_points(
        &mut self,
        text: &str,
        language: &str,
        options: TaskOptions,
    ) -> Result<TaskResult> {
        pipeline::key_points::run(self, text, language, options).await
    }

    /// Run a translation task.
    pub async fn translate(
        &mut self,
        text: &str,
        source_lang: &str,
        target_lang: &str,
        options: TaskOptions,
    ) -> Result<TaskResult> {
        pipeline::translate::run(self, text, source_lang, target_lang, options).await
    }

    /// Run a document generation task.
    pub async fn generate_doc(
        &mut self,
        topic: &str,
        outline: &str,
        language: &str,
        options: TaskOptions,
    ) -> Result<TaskResult> {
        pipeline::generate_doc::run(self, topic, outline, language, options).await
    }

    /// Run a slide content generation task.
    pub async fn generate_slides(
        &mut self,
        topic: &str,
        source_content: &str,
        language: &str,
        options: TaskOptions,
    ) -> Result<TaskResult> {
        pipeline::generate_slides::run(self, topic, source_content, language, options).await
    }

    /// Run an image search task (requires CLIP model).
    pub async fn image_search(
        &mut self,
        query: &str,
        options: TaskOptions,
    ) -> Result<TaskResult> {
        pipeline::image_search::run(self, query, options).await
    }

    /// Run a semantic search task (requires e5-small model).
    pub async fn semantic_search(
        &mut self,
        query: &str,
        options: TaskOptions,
    ) -> Result<TaskResult> {
        pipeline::semantic_search::run(self, query, options).await
    }

    /// Access the underlying inference session (for advanced use).
    pub fn session(&mut self) -> Option<&mut InferenceSession> {
        self.session.as_mut()
    }

    /// Access the resource governor.
    pub fn governor(&self) -> &ResourceGovernor {
        &self.governor
    }

    /// Access the resource governor (mutable).
    pub fn governor_mut(&mut self) -> &mut ResourceGovernor {
        &mut self.governor
    }

    /// Run inference with governor enforcement, adapter lifecycle, and timeout.
    ///
    /// This is the canonical inference path — all pipelines should use this
    /// instead of calling `session.infer()` directly, to ensure the governor
    /// is always enforced.
    ///
    /// - Checks resources (battery, thermal, paused state)
    /// - Acquires the semaphore permit (max 1 concurrent inference)
    /// - Attaches the LoRA adapter (if provided)
    /// - Runs inference with the configured timeout
    /// - Detaches the adapter (always, even on error)
    /// - Returns `InferenceOutput` with text and token counts
    pub async fn run_inference(
        &mut self,
        prompt: &str,
        adapter: Option<LoRAAdapter>,
    ) -> Result<InferenceOutput> {
        self.governor.check_resources()?;
        let timeout = self.governor.timeout();
        let _permit = self.governor.acquire().await?;

        let session = self.session()
            .ok_or_else(|| ZkAiError::ModelLoad("no inference session loaded".to_string()))?;

        if let Some(adapter) = adapter {
            if let Err(e) = session.attach_adapter(adapter).await {
                tracing::warn!(error = %e, "adapter attach failed, continuing without adapter");
            }
        }

        let result = tokio::time::timeout(timeout, session.infer_detailed(prompt)).await;

        if self.session.is_some() {
            let _ = self.session.as_mut().unwrap().detach_adapter().await;
        }
        drop(_permit);

        match result {
            Ok(Ok(output)) => Ok(output),
            Ok(Err(e)) => Err(e),
            Err(_) => Err(ZkAiError::Timeout(timeout)),
        }
    }

    /// Run streaming inference with governor enforcement and adapter lifecycle.
    ///
    /// Returns a channel receiver that yields decoded text chunks as they
    /// are generated. The governor permit is held during generation and
    /// released once all tokens have been produced.
    pub async fn run_inference_stream(
        &mut self,
        prompt: &str,
        adapter: Option<LoRAAdapter>,
    ) -> Result<tokio::sync::mpsc::Receiver<String>> {
        self.governor.check_resources()?;
        let timeout = self.governor.timeout();
        let _permit = self.governor.acquire().await?;

        let session = self.session()
            .ok_or_else(|| ZkAiError::ModelLoad("no inference session loaded".to_string()))?;

        if let Some(adapter) = adapter {
            if let Err(e) = session.attach_adapter(adapter).await {
                tracing::warn!(error = %e, "adapter attach failed, continuing without adapter");
            }
        }

        let result = tokio::time::timeout(timeout, session.infer_stream(prompt)).await;

        // All tokens are generated before infer_stream returns, so we can
        // safely detach the adapter and release the permit now.
        if self.session.is_some() {
            let _ = self.session.as_mut().unwrap().detach_adapter().await;
        }
        drop(_permit);

        match result {
            Ok(Ok(rx)) => Ok(rx),
            Ok(Err(e)) => Err(e),
            Err(_) => Err(ZkAiError::Timeout(timeout)),
        }
    }

    /// Run embedding extraction with governor enforcement.
    ///
    /// Returns an L2-normalized embedding vector for the input text,
    /// suitable for cosine similarity comparison against an image index.
    pub async fn run_embedding(&mut self, prompt: &str) -> Result<Vec<f32>> {
        self.governor.check_resources()?;
        let timeout = self.governor.timeout();
        let _permit = self.governor.acquire().await?;

        let session = self.session()
            .ok_or_else(|| ZkAiError::ModelLoad("no inference session loaded".to_string()))?;

        let result = tokio::time::timeout(timeout, session.infer_embedding(prompt)).await;

        drop(_permit);

        match result {
            Ok(Ok(emb)) => Ok(emb),
            Ok(Err(e)) => Err(e),
            Err(_) => Err(ZkAiError::Timeout(timeout)),
        }
    }

    /// Resolve a LoRA adapter path relative to the model cache directory.
    ///
    /// Adapters are stored as `adapters/<task>.<lang>.bin` under the cache dir.
    /// If the path is already absolute, it's returned as-is.
    pub fn resolve_adapter_path(&self, relative: &str) -> PathBuf {
        let p = std::path::Path::new(relative);
        if p.is_absolute() {
            return p.to_path_buf();
        }
        self.model_manager.cache_dir().join(relative)
    }

    /// Re-profile the device (e.g., after thermal state change).
    pub async fn reprofile(&mut self) -> Result<()> {
        self.profile = DeviceProfiler::detect().await?;
        self.governor.update_config(GovernorConfig::from_tier(&self.profile.tier));
        tracing::info!(tier = ?self.profile.tier, "device re-profiled");
        Ok(())
    }

    /// Pre-download a model with progress reporting.
    /// Useful for settings UI "download for offline use".
    pub async fn preload_with_progress(
        &mut self,
        spec: &ModelSpec,
        progress: Arc<dyn ProgressCallback>,
    ) -> Result<()> {
        self.model_manager.preload_with_progress(spec, progress).await
    }

    /// Shutdown the engine, releasing all resources.
    pub async fn shutdown(&mut self) -> Result<()> {
        if let Some(mut session) = self.session.take() {
            session.unload().await?;
        }
        Ok(())
    }
}
