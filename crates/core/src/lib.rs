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
//!   key_points, generate_doc, generate_slides, image_search, email_summary,
//!   draft_reply, smart_reply, classify_tone, chat_summary, notif_summary,
//!   prioritize, transcribe, meeting_summary, action_items, voice_action,
//!   live_transcribe, meeting_qa, grammar_check, simplify, local_file_index,
//!   qa, auto_tag, find_similar, daily_digest, doc_chat, cluster,
//!   rewrite_tone, expand, explain, pre_send_check, dictate_format,
//!   contract_analysis, compare_docs, find_clause, extract_dates,
//!   ticket_summary, classify_urgency, ticket_reply, dedup, email_categorize,
//!   sentiment, pii_scan, classify_sensitivity, compliance_report,
//!   onboarding_qa, policy_lookup, auto_abstract, find_expert, rerank,
//!   collab_summary, extract_decisions, meeting_minutes, follow_up, rag, privacy).
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
pub mod marketplace;
pub mod tokenizer;
pub mod simple_rng;

pub use error::{ZkAiError, Result};
pub use profiler::{DeviceProfile, DeviceTier, Acceleration, ThermalState, DeviceProfiler};
pub use model_manager::{ModelManager, ModelEntry, ModelSpec, ModelCacheConfig, DownloadProgress, ProgressCallback, SharedProgressCallback};
pub use inference::{InferenceSession, InferenceConfig, InferenceOutput, DecodeStrategy, Quantization, LoRAAdapter};
pub use governor::{ResourceGovernor, GovernorConfig};
pub use marketplace::{Marketplace, LoRAPack, LoRAPackManifest, LoRAPackAdapter};
pub use pipeline::{Task, TaskResult, TaskOptions};
pub use pipeline::image_index::{ImageIndex, ImageEntry, ImageSearchHit, cosine_similarity};
pub use pipeline::text_index::{TextIndex, TextEntry, TextSearchHit};
pub use pipeline::privacy::audit_log::{AuditLog, AuditEntry};
pub use pipeline::privacy::policy::{PolicyEngine, PolicyDecision};
pub use pipeline::privacy::pii::{PiiEntity, detect_pii};
pub use pipeline::privacy::filter::{redact, redact_with_report};
pub use pipeline::privacy::attestation::ZkAttestation;
pub use pipeline::privacy::network_monitor::NetworkMonitor;
pub use pipeline::privacy::residency::ResidencyCertificate;
pub use pipeline::privacy::model_verify::{verify_file, verify_file_with_hash, verify_file_signature, verify_file_signature_hex, VerificationResult};
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
    marketplace: Option<Marketplace>,
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
            marketplace: None,
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

    // ── B2C Category 1: Email & Messaging Intelligence ──

    /// Summarize an email thread into 3 key bullet points.
    pub async fn email_summary(&mut self, thread: &str, language: &str, options: TaskOptions) -> Result<TaskResult> {
        pipeline::email_summary::run(self, thread, language, options).await
    }

    /// Draft a reply to an email based on intent (agree, decline, etc.).
    pub async fn draft_reply(&mut self, email: &str, intent: &str, language: &str, options: TaskOptions) -> Result<TaskResult> {
        pipeline::draft_reply::run(self, email, intent, language, options).await
    }

    /// Generate 3 short smart reply options for a message.
    pub async fn smart_reply(&mut self, messages: &str, language: &str, options: TaskOptions) -> Result<TaskResult> {
        pipeline::smart_reply::run(self, messages, language, options).await
    }

    /// Classify the tone of a message (Urgent, FYI, Action needed, etc.).
    pub async fn classify_tone(&mut self, text: &str, options: TaskOptions) -> Result<TaskResult> {
        pipeline::classify_tone::run(self, text, options).await
    }

    /// Summarize a group chat into key bullets.
    pub async fn chat_summary(&mut self, chat: &str, language: &str, options: TaskOptions) -> Result<TaskResult> {
        pipeline::chat_summary::run(self, chat, language, options).await
    }

    /// Summarize notifications into a 2-3 sentence digest.
    pub async fn notif_summary(&mut self, notifications: &str, language: &str, options: TaskOptions) -> Result<TaskResult> {
        pipeline::notif_summary::run(self, notifications, language, options).await
    }

    /// Auto-prioritize an email (Needs response, FYI, Deferred).
    pub async fn prioritize(&mut self, email: &str, options: TaskOptions) -> Result<TaskResult> {
        pipeline::prioritize::run(self, email, options).await
    }

    // ── B2C Category 2: Meeting & Voice Intelligence ──

    /// Transcribe audio to text (MidRange+ only, requires Whisper-tiny).
    pub async fn transcribe(&mut self, audio: &[f32], options: TaskOptions) -> Result<TaskResult> {
        pipeline::transcribe::run(self, audio, options).await
    }

    /// Summarize a meeting transcript.
    pub async fn meeting_summary(&mut self, transcript: &str, language: &str, options: TaskOptions) -> Result<TaskResult> {
        pipeline::meeting_summary::run(self, transcript, language, options).await
    }

    /// Extract action items from a meeting transcript.
    pub async fn action_items(&mut self, transcript: &str, language: &str, options: TaskOptions) -> Result<TaskResult> {
        pipeline::action_items::run(self, transcript, language, options).await
    }

    /// Voice-to-action: transcribe + classify intent (MidRange+ only).
    pub async fn voice_action(&mut self, audio: &[f32], options: TaskOptions) -> Result<TaskResult> {
        pipeline::voice_action::run(self, audio, options).await
    }

    /// Live transcription of streaming audio chunks (MidRange+ only).
    pub async fn live_transcribe(&mut self, chunks: &[Vec<f32>], options: TaskOptions) -> Result<TaskResult> {
        pipeline::live_transcribe::run(self, chunks, options).await
    }

    /// Q&A over meeting transcripts using RAG.
    pub async fn meeting_qa(&mut self, transcript: &str, question: &str, language: &str, options: TaskOptions) -> Result<TaskResult> {
        pipeline::meeting_qa::run(self, transcript, question, language, options).await
    }

    // ── B2C Category 3: Document Productivity ──

    /// Check grammar and spelling.
    pub async fn grammar_check(&mut self, text: &str, language: &str, options: TaskOptions) -> Result<TaskResult> {
        pipeline::grammar_check::run(self, text, language, options).await
    }

    /// Simplify text to plain language (~8th grade level).
    pub async fn simplify(&mut self, text: &str, language: &str, options: TaskOptions) -> Result<TaskResult> {
        pipeline::simplify::run(self, text, language, options).await
    }

    // ── B2C Category 4: Personal Knowledge & Search ──

    /// Index a directory of files for semantic search.
    pub async fn local_file_index(&mut self, dir: &std::path::Path) -> Result<TextIndex> {
        pipeline::local_file_index::index_directory(self, dir).await
    }

    /// Answer questions over a local document index (RAG).
    pub async fn qa(&mut self, question: &str, index: &TextIndex, language: &str, options: TaskOptions) -> Result<TaskResult> {
        pipeline::qa::run(self, question, index, language, options).await
    }

    /// Auto-tag a document with topic labels.
    pub async fn auto_tag(&mut self, text: &str, options: TaskOptions) -> Result<TaskResult> {
        pipeline::auto_tag::run(self, text, options).await
    }

    /// Find similar documents in a TextIndex.
    pub async fn find_similar(&mut self, text: &str, index: &TextIndex, top_k: usize, options: TaskOptions) -> Result<TaskResult> {
        pipeline::find_similar::run(self, text, index, top_k, options).await
    }

    /// Generate an end-of-day digest from emails, meetings, and notifications.
    pub async fn daily_digest(&mut self, input: &pipeline::daily_digest::DailyDigestInput, language: &str, options: TaskOptions) -> Result<TaskResult> {
        pipeline::daily_digest::run(self, input, language, options).await
    }

    /// Multi-turn document chat.
    pub async fn doc_chat(&mut self, message: &str, history: &[(String, String)], index: &TextIndex, language: &str, options: TaskOptions) -> Result<TaskResult> {
        pipeline::doc_chat::run(self, message, history, index, language, options).await
    }

    /// Cluster documents by topic.
    pub async fn cluster(&mut self, index: &TextIndex, num_clusters: usize, options: TaskOptions) -> Result<TaskResult> {
        pipeline::cluster::run(self, index, num_clusters, options).await
    }

    // ── B2C Category 5: Communication Assistance ──

    /// Rewrite text in a different tone.
    pub async fn rewrite_tone(&mut self, text: &str, target_tone: &str, language: &str, options: TaskOptions) -> Result<TaskResult> {
        pipeline::rewrite_tone::run(self, text, target_tone, language, options).await
    }

    /// Expand bullet points into full prose.
    pub async fn expand(&mut self, bullets: &str, language: &str, options: TaskOptions) -> Result<TaskResult> {
        pipeline::expand::run(self, bullets, language, options).await
    }

    /// Explain jargon in plain language.
    pub async fn explain(&mut self, term: &str, context: &str, language: &str, options: TaskOptions) -> Result<TaskResult> {
        pipeline::explain::run(self, term, context, language, options).await
    }

    /// Pre-send check: grammar + tone + suggested rewrite.
    pub async fn pre_send_check(&mut self, text: &str, language: &str, options: TaskOptions) -> Result<TaskResult> {
        pipeline::pre_send_check::run(self, text, language, options).await
    }

    /// Dictate and format: transcribe audio + format into structured notes (MidRange+).
    pub async fn dictate_format(&mut self, audio: &[f32], language: &str, options: TaskOptions) -> Result<TaskResult> {
        pipeline::dictate_format::run(self, audio, language, options).await
    }

    // ── B2B Category 1: Document Intelligence ──

    /// Analyze a contract (parties, obligations, deadlines, risks, termination).
    pub async fn contract_analysis(&mut self, contract: &str, language: &str, options: TaskOptions) -> Result<TaskResult> {
        pipeline::contract_analysis::run(self, contract, language, options).await
    }

    /// Compare two documents and summarize differences.
    pub async fn compare_docs(&mut self, doc_a: &str, doc_b: &str, language: &str, options: TaskOptions) -> Result<TaskResult> {
        pipeline::compare_docs::run(self, doc_a, doc_b, language, options).await
    }

    /// Find relevant clauses in a legal document.
    pub async fn find_clause(&mut self, contract: &str, query: &str, options: TaskOptions) -> Result<TaskResult> {
        pipeline::find_clause::run(self, contract, query, options).await
    }

    /// Extract dates and deadlines from a document.
    pub async fn extract_dates(&mut self, text: &str, options: TaskOptions) -> Result<TaskResult> {
        pipeline::extract_dates::run(self, text, options).await
    }

    // ── B2B Category 3: Email & Support Intelligence ──

    /// Summarize a support ticket.
    pub async fn ticket_summary(&mut self, ticket: &str, language: &str, options: TaskOptions) -> Result<TaskResult> {
        pipeline::ticket_summary::run(self, ticket, language, options).await
    }

    /// Classify ticket urgency (Critical, High, Medium, Low).
    pub async fn classify_urgency(&mut self, ticket: &str, options: TaskOptions) -> Result<TaskResult> {
        pipeline::classify_urgency::run(self, ticket, options).await
    }

    /// Draft a reply to a support ticket.
    pub async fn ticket_reply(&mut self, ticket: &str, language: &str, options: TaskOptions) -> Result<TaskResult> {
        pipeline::ticket_reply::run(self, ticket, language, options).await
    }

    /// Detect duplicate support tickets.
    pub async fn dedup(&mut self, new_ticket: &str, existing_index: &TextIndex, options: TaskOptions) -> Result<TaskResult> {
        pipeline::dedup::run(self, new_ticket, existing_index, options).await
    }

    /// Auto-categorize an email (Internal, Client, Vendor, Newsletter, Action Required).
    pub async fn email_categorize(&mut self, email: &str, options: TaskOptions) -> Result<TaskResult> {
        pipeline::email_categorize::run(self, email, options).await
    }

    /// Detect sentiment (Positive, Neutral, Negative).
    pub async fn sentiment(&mut self, text: &str, options: TaskOptions) -> Result<TaskResult> {
        pipeline::sentiment::run(self, text, options).await
    }

    // ── B2B Category 4: Compliance & Privacy ──

    /// Scan a document for PII.
    pub async fn pii_scan(&mut self, text: &str, options: TaskOptions) -> Result<TaskResult> {
        pipeline::pii_scan::run(self, text, options).await
    }

    /// Classify document sensitivity (Public, Internal, Confidential, Restricted).
    pub async fn classify_sensitivity(&mut self, text: &str, options: TaskOptions) -> Result<TaskResult> {
        pipeline::classify_sensitivity::run(self, text, options).await
    }

    /// Generate a compliance report from audit log entries.
    pub async fn compliance_report(&mut self, audit_log: &str, language: &str, options: TaskOptions) -> Result<TaskResult> {
        pipeline::compliance_report::run(self, audit_log, language, options).await
    }

    // ── B2B Category 5: Knowledge Management ──

    /// Answer onboarding questions from local docs.
    pub async fn onboarding_qa(&mut self, question: &str, index: &TextIndex, language: &str, options: TaskOptions) -> Result<TaskResult> {
        pipeline::onboarding_qa::run(self, question, index, language, options).await
    }

    /// Look up company policy sections.
    pub async fn policy_lookup(&mut self, query: &str, index: &TextIndex, language: &str, options: TaskOptions) -> Result<TaskResult> {
        pipeline::policy_lookup::run(self, query, index, language, options).await
    }

    /// Generate a 2-sentence abstract for a document.
    pub async fn auto_abstract(&mut self, text: &str, language: &str, options: TaskOptions) -> Result<TaskResult> {
        pipeline::auto_abstract::run(self, text, language, options).await
    }

    /// Find colleagues who are experts on a topic.
    pub async fn find_expert(&mut self, topic: &str, index: &TextIndex, top_k: usize, options: TaskOptions) -> Result<TaskResult> {
        pipeline::find_expert::run(self, topic, index, top_k, options).await
    }

    /// Rerank search results for improved precision.
    pub async fn rerank(&mut self, query: &str, hits: &[TextSearchHit], options: TaskOptions) -> Result<TaskResult> {
        pipeline::rerank::run(self, query, hits, options).await
    }

    // ── B2B Category 6: Team Productivity ──

    /// Synthesize a unified summary from team annotations.
    pub async fn collab_summary(&mut self, annotations: &str, language: &str, options: TaskOptions) -> Result<TaskResult> {
        pipeline::collab_summary::run(self, annotations, language, options).await
    }

    /// Extract decisions from meeting transcripts.
    pub async fn extract_decisions(&mut self, transcript: &str, language: &str, options: TaskOptions) -> Result<TaskResult> {
        pipeline::extract_decisions::run(self, transcript, language, options).await
    }

    /// Generate formal meeting minutes.
    pub async fn meeting_minutes(&mut self, transcript: &str, language: &str, options: TaskOptions) -> Result<TaskResult> {
        pipeline::meeting_minutes::run(self, transcript, language, options).await
    }

    /// Generate follow-up reminders for overdue action items.
    pub async fn follow_up(&mut self, action_items: &str, language: &str, options: TaskOptions) -> Result<TaskResult> {
        pipeline::follow_up::run(self, action_items, language, options).await
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

    /// Initialize the LoRA adapter marketplace with trusted author public keys.
    ///
    /// After initialization, call `load_marketplace_dir` to scan a directory
    /// for signed packs.
    pub fn init_marketplace(&mut self, trusted_keys: Vec<ed25519_dalek::VerifyingKey>) {
        self.marketplace = Some(Marketplace::new(trusted_keys));
    }

    /// Load all signed LoRA adapter packs from a marketplace directory.
    /// Requires `init_marketplace` to have been called first.
    pub fn load_marketplace_dir(&mut self, dir: &std::path::Path) -> Result<()> {
        let marketplace = self
            .marketplace
            .as_mut()
            .ok_or_else(|| ZkAiError::LoRA("marketplace not initialized".to_string()))?;
        marketplace.load_dir(dir)
    }

    /// Install a single LoRA pack from a directory into the marketplace.
    /// Returns the pack id on success.
    pub fn install_pack(&mut self, root: &std::path::Path) -> Result<String> {
        let marketplace = self
            .marketplace
            .as_mut()
            .ok_or_else(|| ZkAiError::LoRA("marketplace not initialized".to_string()))?;
        marketplace.load_pack(root)
    }

    /// List all installed LoRA packs in the marketplace.
    pub fn list_packs(&self) -> Vec<&LoRAPackManifest> {
        self.marketplace.as_ref().map(|m| m.list_packs()).unwrap_or_default()
    }

    /// List adapters in a specific pack.
    pub fn list_pack_adapters(&self, pack_id: &str) -> Option<Vec<&LoRAPackAdapter>> {
        self.marketplace.as_ref()?.list_adapters(pack_id)
    }

    /// Get a LoRA adapter from the marketplace and attach it to the current
    /// inference session for the next `run_inference` call.
    pub fn marketplace_adapter(
        &mut self,
        pack_id: &str,
        task: &str,
        language: &str,
    ) -> Result<LoRAAdapter> {
        let marketplace = self
            .marketplace
            .as_ref()
            .ok_or_else(|| ZkAiError::LoRA("marketplace not initialized".to_string()))?;
        marketplace.get_adapter(pack_id, task, language)
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
        const MAX_PROMPT_LEN: usize = 32_768;
        if prompt.len() > MAX_PROMPT_LEN {
            return Err(ZkAiError::Inference(format!(
                "prompt too long: {} bytes (max {})",
                prompt.len(),
                MAX_PROMPT_LEN
            )));
        }
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
        const MAX_PROMPT_LEN: usize = 32_768;
        if prompt.len() > MAX_PROMPT_LEN {
            return Err(ZkAiError::Inference(format!(
                "prompt too long: {} bytes (max {})",
                prompt.len(),
                MAX_PROMPT_LEN
            )));
        }
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
        const MAX_PROMPT_LEN: usize = 32_768;
        if prompt.len() > MAX_PROMPT_LEN {
            return Err(ZkAiError::Inference(format!(
                "prompt too long: {} bytes (max {})",
                prompt.len(),
                MAX_PROMPT_LEN
            )));
        }
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

    /// Run Whisper speech-to-text inference with mel spectrogram input.
    ///
    /// This is the canonical path for audio transcription — it feeds the
    /// mel spectrogram directly into the Whisper ONNX model instead of
    /// going through the text-based prompt interface. Governor enforcement
    /// and timeout are applied as with text inference.
    pub async fn run_whisper(&mut self, mel: &[Vec<f32>]) -> Result<InferenceOutput> {
        self.governor.check_resources()?;
        let timeout = self.governor.timeout();
        let _permit = self.governor.acquire().await?;

        let session = self.session()
            .ok_or_else(|| ZkAiError::ModelLoad("no inference session loaded".to_string()))?;

        let result = tokio::time::timeout(timeout, session.infer_whisper(mel)).await;

        drop(_permit);

        match result {
            Ok(Ok(output)) => Ok(output),
            Ok(Err(e)) => Err(e),
            Err(_) => Err(ZkAiError::Timeout(timeout)),
        }
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

    /// Warm up the inference session by running a dummy forward pass.
    /// This pre-allocates memory and compiles the ONNX graph so the first
    /// real inference is fast. Call after `ensure_model`.
    pub async fn warmup(&mut self) -> Result<()> {
        if self.session.is_none() {
            return Err(ZkAiError::ModelLoad("no model loaded for warmup".to_string()));
        }
        tracing::info!("warming up inference session");
        let _ = self.run_inference("warmup", None).await?;
        tracing::info!("warmup complete");
        Ok(())
    }

    /// Run batch inference on multiple inputs sequentially.
    /// Each input uses the same model and adapter (if provided).
    /// Returns results in the same order as inputs.
    pub async fn batch_inference(
        &mut self,
        prompts: &[String],
        adapter: Option<LoRAAdapter>,
    ) -> Result<Vec<InferenceOutput>> {
        let mut results = Vec::with_capacity(prompts.len());
        for prompt in prompts {
            let output = self.run_inference(prompt, adapter.clone()).await?;
            results.push(output);
        }
        Ok(results)
    }

    /// Wipe all inference memory: unload the session, drop the model from
    /// memory, and clear any cached state. The model file remains on disk.
    /// Use this when the user requests "forget everything" or when switching
    /// to strict zero-knowledge mode.
    pub async fn wipe_memory(&mut self) -> Result<()> {
        tracing::info!("wiping all inference memory");
        if let Some(mut session) = self.session.take() {
            session.unload().await?;
        }
        // Force garbage collection of any remaining tensors
        // (In Rust, dropping the session should be sufficient)
        tracing::info!("memory wipe complete");
        Ok(())
    }
}
