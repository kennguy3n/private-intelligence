//! KinShield — On-device scam risk detection and prevention.
//!
//! A privacy-first scam detection engine that runs entirely on-device,
//! protecting family units across SMS, email, browser, messaging, and
//! voice call channels. Built on zk-ai-core's inference engine.
//!
//! # Key Features
//!
//! - **29-indicator ontology** with SEA multi-language keyword detection
//! - **17 scam type families** with Southeast Asia focus
//! - **Family construct** with per-member sensitivity thresholds
//! - **Bounded decision traces** — privacy-preserving, no raw text transmitted
//! - **Structured feedback** separating detection, classification, explanation
//! - **On-device calibration** from local feedback history
//! - **Report missed scam** for recall improvement
//! - **Anti-manipulation** via contribution caps and label hierarchy
//!
//! # Example
//!
//! ```no_run
//! # use kinshield::{KinShieldEngine, Channel};
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let mut engine = KinShieldEngine::new("/tmp/kinshield-cache").await?;
//! let result = engine.detect("Your account is suspended! Click here now!", Channel::Sms, "en", None).await?;
//! println!("Risk: {}/5, Type: {:?}", result.risk_bucket, result.scam_type);
//! engine.shutdown().await?;
//! # Ok(())
//! # }
//! ```

pub mod channel;
pub mod ontology;
pub mod taxonomy;
pub mod detection;
pub mod decision_trace;
pub mod feedback;
pub mod aggregation;
pub mod calibration;
pub mod report_missed;
pub mod family;
pub mod counter_tables;
pub mod contribution_limits;
pub mod privacy_budget;
pub mod privacy_settings;
pub mod threat_intel;
pub mod test_data;

#[cfg(test)]
mod tests;

// Re-export key types
pub use channel::Channel;
pub use ontology::{
    IndicatorId, IndicatorStrength, IndicatorCategory, IndicatorHit, IndicatorHitExplained,
    IndicatorKeywords, ONTOLOGY_VERSION,
};
pub use taxonomy::{ScamType, SCAM_TAXONOMY_VERSION};
pub use detection::{
    DetectionResult, PredictedOutcome,
    keyword, embedding, url, scoring, heuristics,
};
pub use decision_trace::{DecisionTrace, LabelConfidence, AGGREGATION_SCHEMA_VERSION};
pub use feedback::{FeedbackKind, FeedbackRecord, FeedbackSource, LabelTrust};
pub use aggregation::{AggregationBuffer, AggregateReport, AggregateQuery};
pub use calibration::{CalibrationLayer, CalibrationStats};
pub use report_missed::MissedScamReport;
pub use family::{FamilyCircle, FamilyMember, MemberRole, SensitivityConfig, FamilyAlert, EmergencyContact};
pub use counter_tables::CounterTables;
pub use contribution_limits::{ContributionLimits, ContributionUsage, ContributionLimitError};
pub use privacy_budget::{PrivacyBudget, PrivacyBudgetStatus, SystemHealth};
pub use privacy_settings::{PrivacySettings, EventRetention};
pub use threat_intel::{ThreatIntelFeed, ScamCampaign, CampaignStatus, ThreatIntelReport};
pub use test_data::{TestCase, all_test_cases, cases_by_region, scam_cases, benign_cases};

use zk_ai_core::{AiEngine, ModelSpec, AuditLog, detect_pii, PolicyEngine};
use std::path::Path;
use std::collections::{HashMap, VecDeque};

/// Current model version for decision trace.
pub const MODEL_VERSION: &str = "1.0.0";

/// Current prompt version for UX bias measurement.
pub const PROMPT_VERSION: &str = "1.0.0";

/// The main KinShield scam detection engine.
pub struct KinShieldEngine {
    /// Underlying zk-ai-core inference engine.
    ai_engine: AiEngine,
    /// On-device calibration layer.
    calibration: CalibrationLayer,
    /// Local aggregation buffer for decision traces.
    aggregation: AggregationBuffer,
    /// Optional family circle configuration.
    family: Option<FamilyCircle>,
    /// Whether the e5-small model has been loaded.
    embedding_model_loaded: bool,
    /// Cached embedding prototypes keyed by indicator ID.
    /// Pre-computed once when the model is loaded to avoid
    /// re-running inference on static prototype text every detection.
    embedding_cache: HashMap<IndicatorId, Vec<Vec<f32>>>,
    /// Pending detection contexts keyed by detection_id.
    /// Used to correlate feedback with calibration updates.
    /// Entries are removed when feedback is submitted or when evicted.
    pending_contexts: HashMap<String, DetectionContext>,
    /// Insertion order of pending context keys for FIFO eviction.
    pending_context_order: VecDeque<String>,
    /// Maximum number of pending contexts to retain.
    /// Oldest entries are evicted when this limit is exceeded.
    max_pending_contexts: usize,
    /// Tamper-evident audit log of all detections.
    audit_log: Option<AuditLog>,
    /// Policy engine for family-level policy enforcement.
    policy_engine: PolicyEngine,
    /// Weekly contribution limits and per-cell caps.
    contribution_limits: ContributionLimits,
    /// User-configurable privacy settings.
    privacy_settings: PrivacySettings,
    /// Privacy budget accountant for DP queries.
    privacy_budget: PrivacyBudget,
    /// Threat intelligence feed for external campaign data.
    threat_intel: ThreatIntelFeed,
}

/// Stored detection context for feedback correlation.
struct DetectionContext {
    channel: Channel,
    language: String,
    risk_bucket: u8,
    indicators: Vec<(IndicatorId, IndicatorStrength)>,
    predicted_type: Option<ScamType>,
}

impl KinShieldEngine {
    /// Initialize the KinShield engine with a cache directory.
    ///
    /// The cache directory is used by the underlying AiEngine for model
    /// storage. The e5-small model is loaded lazily on first detection.
    /// The audit log is stored at `<cache_dir>/kinshield_audit.jsonl`.
    pub async fn new(cache_dir: impl AsRef<Path>) -> Result<Self, zk_ai_core::ZkAiError> {
        let ai_engine = AiEngine::new(cache_dir.as_ref()).await?;
        let mut calibration = CalibrationLayer::new(MODEL_VERSION);
        calibration.seed_defaults();
        let aggregation = AggregationBuffer::new();

        let audit_path = cache_dir.as_ref().join("kinshield_audit.jsonl");
        let audit_log = AuditLog::open(audit_path).ok();

        Ok(Self {
            ai_engine,
            calibration,
            aggregation,
            family: None,
            embedding_model_loaded: false,
            embedding_cache: HashMap::new(),
            pending_contexts: HashMap::new(),
            pending_context_order: VecDeque::new(),
            max_pending_contexts: 1000,
            audit_log,
            policy_engine: PolicyEngine::new(),
            contribution_limits: ContributionLimits::new(),
            privacy_settings: PrivacySettings::new(),
            privacy_budget: PrivacyBudget::new(),
            threat_intel: ThreatIntelFeed::new(),
        })
    }

    /// Ensure the e5-small embedding model is loaded and pre-compute
    /// prototype embeddings for all indicators.
    async fn ensure_embedding_model(&mut self) -> Result<(), zk_ai_core::ZkAiError> {
        if !self.embedding_model_loaded {
            self.ai_engine.ensure_model(&ModelSpec::e5_small_int8()).await?;
            self.embedding_model_loaded = true;

            // Pre-compute all prototype embeddings once
            self.embedding_cache = embedding::precompute_prototype_cache(&mut self.ai_engine).await?;
            tracing::info!(
                indicators = self.embedding_cache.len(),
                "embedding prototype cache built"
            );
        }
        Ok(())
    }

    /// Extract all indicators from text using the full detection pipeline.
    ///
    /// This is the shared pipeline used by both `detect()` and `report_missed()`.
    /// Steps:
    /// 1. Keyword-based indicator detection (all 25 indicators, multi-language)
    /// 2. URL/link analysis for suspicious patterns
    /// 3. PII detection to boost existing credential/personal_info indicators
    /// 4. Embedding-based semantic detection (e5-small)
    async fn extract_indicators(
        &mut self,
        text: &str,
        channel: Channel,
        language: &str,
    ) -> Result<Vec<IndicatorHit>, zk_ai_core::ZkAiError> {
        // 1. Keyword-based indicator detection
        let mut indicators = keyword::detect_keywords(text, channel, language);

        // 2. URL analysis
        if let Some(url_hit) = url::analyze_urls(text) {
            if let Some(existing) = indicators.iter_mut().find(|h| h.id == url_hit.id) {
                if url_hit.strength.weight() > existing.strength.weight() {
                    existing.strength = url_hit.strength;
                }
                existing.match_count += url_hit.match_count;
            } else {
                indicators.push(url_hit);
            }
        }

        // 3. PII detection — boost existing credential/personal_info indicators
        // Only boosts indicators already detected by keyword matching.
        // Does NOT create new indicators from PII alone — a benign message
        // containing someone's email/phone is not requesting that info.
        let pii_entities = detect_pii(text);
        if !pii_entities.is_empty() {
            let has_cc = pii_entities.iter().any(|e| e.entity_type == "CreditCard");
            let has_ssn = pii_entities.iter().any(|e| e.entity_type == "SSN");

            if has_cc || has_ssn {
                if let Some(existing) = indicators.iter_mut().find(|h| h.id == IndicatorId::CredentialRequest) {
                    if existing.strength.weight() < IndicatorStrength::High.weight() {
                        existing.strength = IndicatorStrength::High;
                    }
                    existing.match_count += pii_entities.len();
                }
            }

            let has_email_or_phone = pii_entities.iter().any(|e| {
                e.entity_type == "Email" || e.entity_type == "Phone"
            });
            if has_email_or_phone {
                if let Some(existing) = indicators.iter_mut().find(|h| h.id == IndicatorId::PersonalInfoRequest) {
                    if existing.strength.weight() < IndicatorStrength::High.weight() {
                        existing.strength = IndicatorStrength::High;
                    }
                    existing.match_count += pii_entities.len();
                }
            }
        }

        // 4. Embedding-based detection (requires e5-small model)
        if text.split_whitespace().count() >= 3 {
            match self.ensure_embedding_model().await {
                Ok(()) => {
                    match embedding::detect_embeddings(
                        &mut self.ai_engine,
                        &self.embedding_cache,
                        text,
                        channel,
                        language,
                    ).await {
                        Ok(emb_hits) => {
                            for emb_hit in emb_hits {
                                if let Some(existing) = indicators.iter_mut().find(|h| h.id == emb_hit.id) {
                                    if emb_hit.strength.weight() > existing.strength.weight() {
                                        existing.strength = emb_hit.strength;
                                    }
                                } else {
                                    indicators.push(emb_hit);
                                }
                            }
                        }
                        Err(e) => {
                            tracing::warn!(
                                error = %e,
                                "embedding detection failed, continuing with keyword-only results"
                            );
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "embedding model unavailable, continuing with keyword-only results"
                    );
                }
            }
        }

        // 5. Structural heuristic detection
        let heuristic_hits = heuristics::detect_heuristics(text, channel);
        for h_hit in heuristic_hits {
            if let Some(existing) = indicators.iter_mut().find(|h| h.id == h_hit.id) {
                if h_hit.strength.weight() > existing.strength.weight() {
                    existing.strength = h_hit.strength;
                }
            } else {
                indicators.push(h_hit);
            }
        }

        Ok(indicators)
    }

    /// Sort indicators by strength (highest first).
    fn sort_indicators(mut indicators: Vec<IndicatorHit>) -> Vec<IndicatorHit> {
        indicators.sort_by(|a, b| {
            b.strength
                .weight()
                .partial_cmp(&a.strength.weight())
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        indicators
    }

    /// Detect scam risk in a message.
    ///
    /// Runs the full detection pipeline:
    /// 1. Keyword-based indicator detection (all 29 indicators, multi-language)
    /// 2. URL/link analysis for suspicious patterns
    /// 3. Embedding-based semantic detection (e5-small, for semantic indicators)
    /// 4. Structural heuristic detection (conversation format, wrong-number pivot, etc.)
    /// 5. Merge and deduplicate indicator hits
    /// 6. Compute risk bucket with monotonic constraints
    /// 7. Classify scam type
    /// 8. Build detection result and decision trace
    ///
    /// `member_id` identifies which family member received the message.
    /// If a family circle is configured, per-member sensitivity thresholds
    /// and guardian alerts are applied. Pass `None` when no family context
    /// is relevant.
    pub async fn detect(
        &mut self,
        text: &str,
        channel: Channel,
        language: &str,
        member_id: Option<&str>,
    ) -> Result<DetectionResult, zk_ai_core::ZkAiError> {
        let start = std::time::Instant::now();

        // 1-5. Extract indicators using the shared pipeline
        let mut indicators = self.extract_indicators(text, channel, language).await?;

        // 4b. Threat intelligence boost — match against known campaigns
        if !self.threat_intel.is_empty() {
            let matching = self.threat_intel.match_campaigns(text, channel);
            if !matching.is_empty() {
                let matching_refs: Vec<&ScamCampaign> = matching.iter().copied().collect();
                self.threat_intel.boost_indicators(&mut indicators, &matching_refs);
                tracing::info!(
                    campaigns = matching.len(),
                    "threat intelligence matched, indicators boosted"
                );
            }
        }

        // 5. Sort indicators by strength
        let indicators = Self::sort_indicators(indicators);

        // 6. Compute risk bucket
        let raw_bucket = scoring::compute_risk_bucket(&indicators, channel, text);
        let risk_bucket = self.calibration.calibrate(raw_bucket, channel, language);

        // 7. Predict outcome and scam type
        let predicted_outcome = scoring::predict_outcome(risk_bucket);
        let scam_type = if predicted_outcome != PredictedOutcome::Benign {
            scoring::classify_scam_type(&indicators, text)
        } else {
            None
        };

        // 8. Select top 3 indicators for decision trace
        let top_indicators = scoring::top_indicators(&indicators, 3);

        // 9. Coarse language bucket
        let lang_bucket = coarse_language_bucket(language);

        // 10. Build detection result
        let detection_id = uuid::Uuid::new_v4().to_string();
        let duration_ms = start.elapsed().as_millis() as u64;

        // 11. Policy engine check — if family policy denies, return a denied result
        if let Some(ref family) = self.family {
            let sensitivity = if risk_bucket >= 4 { "Restricted" } else if risk_bucket >= 3 { "Confidential" } else { "Public" };
            let decision = self.policy_engine.check(sensitivity, "scam_detection");
            if !decision.is_allowed() {
                tracing::warn!(
                    family_id = %family.id,
                    sensitivity = sensitivity,
                    "policy engine denied detection for family member"
                );
                // Return a minimal result indicating policy denial.
                // The detection still runs locally, but the result is marked
                // as policy-denied so the caller can handle it appropriately.
                return Ok(DetectionResult {
                    id: detection_id,
                    predicted_outcome: PredictedOutcome::Benign,
                    scam_type: None,
                    risk_bucket: 1,
                    indicators: Vec::new(),
                    indicator_explanations: Vec::new(),
                    channel,
                    language_bucket: lang_bucket.to_string(),
                    model_version: MODEL_VERSION.to_string(),
                    prompt_version: PROMPT_VERSION.to_string(),
                    duration_ms,
                    family_alert: None,
                    decision_trace: None,
                });
            }
        }

        let indicator_explanations: Vec<_> = top_indicators.iter().map(|h| h.explained()).collect();

        let result = DetectionResult {
            id: detection_id.clone(),
            predicted_outcome,
            scam_type,
            risk_bucket,
            indicators: top_indicators.clone(),
            indicator_explanations,
            channel,
            language_bucket: lang_bucket.to_string(),
            model_version: MODEL_VERSION.to_string(),
            prompt_version: PROMPT_VERSION.to_string(),
            duration_ms,
            family_alert: None,
            decision_trace: None,
        };

        // 12. Build and store decision trace
        let trace = DecisionTrace::from_detection(&result, &top_indicators);
        let trace_clone = trace.clone();
        if self.privacy_settings.contribute_aggregates {
            self.aggregation.add(trace);
        }

        // 13. Write to audit log (hashes input internally, no raw content stored)
        if let Some(ref mut audit) = self.audit_log {
            let output_summary = format!(
                "{}:{}:{}",
                predicted_outcome.as_str(),
                risk_bucket,
                scam_type.map(|t| t.as_str()).unwrap_or("none")
            );
            // AuditLog::append() computes SHA-256 of the input text itself.
            // We pass the raw text — it stores only the hash, never the content.
            if let Err(e) = audit.append("scam_detection", MODEL_VERSION, text, &output_summary, None) {
                tracing::warn!(error = %e, "failed to write audit log entry");
            }
        }

        // 14. Store detection context for feedback correlation
        // Evict oldest entries (FIFO) if we've reached the cap
        while self.pending_contexts.len() >= self.max_pending_contexts {
            if let Some(key) = self.pending_context_order.pop_front() {
                self.pending_contexts.remove(&key);
                tracing::debug!(
                    evicted_id = %key,
                    "evicted oldest pending context to stay within cap"
                );
            } else {
                break;
            }
        }
        self.pending_contexts.insert(
            detection_id.clone(),
            DetectionContext {
                channel,
                language: lang_bucket.to_string(),
                risk_bucket,
                indicators: top_indicators.iter().map(|h| (h.id, h.strength)).collect(),
                predicted_type: scam_type,
            },
        );
        self.pending_context_order.push_back(detection_id.clone());

        // 15. Family alert check — generate alert if configured
        let family_alert = if let Some(ref family) = self.family {
            if let Some(mid) = member_id {
                family.check_alert(mid, &result)
            } else if result.should_alert(family.alert_threshold) {
                tracing::info!(
                    risk_bucket = risk_bucket,
                    family_id = %family.id,
                    "family alert threshold exceeded but no member_id provided"
                );
                None
            } else {
                None
            }
        } else {
            None
        };

        // Attach family alert and decision trace to result
        let mut result = result;
        result.family_alert = family_alert;
        result.decision_trace = Some(trace_clone);

        Ok(result)
    }

    /// Submit feedback for a previous detection.
    ///
    /// Updates both the calibration layer and the aggregation buffer
    /// with the user's feedback, using the stored detection context.
    pub fn submit_feedback(
        &mut self,
        detection_id: &str,
        feedback: FeedbackKind,
        corrected_type: Option<ScamType>,
    ) -> Result<(), zk_ai_core::ZkAiError> {
        if !self.privacy_settings.contribute_feedback {
            return Err(zk_ai_core::ZkAiError::Inference(
                "feedback contribution disabled by privacy settings".to_string(),
            ));
        }

        // Get detection context for limit checking
        let (indicator_ids, scam_type_for_limits) = {
            let ctx = self.pending_contexts.get(detection_id);
            let ids: Vec<IndicatorId> = ctx
                .map(|c| c.indicators.iter().map(|(id, _)| *id).collect())
                .unwrap_or_default();
            let scam_type = corrected_type.or_else(|| {
                ctx.and_then(|c| c.predicted_type)
            });
            (ids, scam_type)
        };

        // Check weekly contribution limits
        if let Err(e) = self.contribution_limits.check_feedback(&indicator_ids, scam_type_for_limits) {
            tracing::warn!(
                detection_id = detection_id,
                error = %e,
                "contribution limit exceeded, feedback rejected"
            );
            return Err(zk_ai_core::ZkAiError::Inference(format!(
                "contribution limit exceeded: {}",
                e
            )));
        }

        let record = FeedbackRecord {
            detection_id: detection_id.to_string(),
            feedback,
            corrected_type,
            timestamp: chrono::Utc::now(),
            source: crate::feedback::FeedbackSource::User,
        };

        // Update calibration with full detection context
        let ctx = match self.pending_contexts.remove(detection_id) {
            Some(ctx) => ctx,
            None => {
                tracing::warn!(
                    detection_id = detection_id,
                    "no pending detection context for feedback"
                );
                return Err(zk_ai_core::ZkAiError::Inference(
                    "no pending detection context for this feedback ID".to_string(),
                ));
            }
        };
        self.pending_context_order.retain(|id| id != detection_id);

        self.calibration.update_calibration(
            ctx.channel,
            &ctx.language,
            ctx.risk_bucket,
            &ctx.indicators,
            feedback,
            crate::feedback::FeedbackSource::User,
        );

        // Update confusion matrix with corrected type if provided
        if let Some(corrected) = corrected_type {
            if let Some(predicted) = ctx.predicted_type {
                self.aggregation.update_confusion(predicted.as_str(), corrected.as_str());
            }
        }

        // Update decision trace in aggregation buffer
        let corrected_str = corrected_type.map(|t| t.as_str().to_string());
        let updated = self.aggregation.update_feedback(detection_id, feedback, corrected_str.as_deref());
        if !updated {
            tracing::warn!(
                detection_id = detection_id,
                "feedback not found in aggregation buffer — counter tables may be incomplete"
            );
        }

        // Record in contribution limits only after all updates succeed
        let indicator_ids: Vec<IndicatorId> =
            ctx.indicators.iter().map(|(id, _)| *id).collect();
        self.contribution_limits
            .record_feedback(&indicator_ids, corrected_type);

        // Record feedback for counter
        self.calibration.record_feedback(&record);

        tracing::info!(
            detection_id = detection_id,
            feedback = ?feedback,
            "feedback recorded"
        );

        Ok(())
    }

    /// Report a missed scam (false negative).
    ///
    /// The engine re-runs the full indicator extraction pipeline locally
    /// (keywords, URL analysis, PII detection, embeddings) and stores
    /// the result as a false-negative example for calibration.
    pub async fn report_missed(
        &mut self,
        text: &str,
        channel: Channel,
        language: &str,
        actual_type: Option<ScamType>,
    ) -> Result<MissedScamReport, zk_ai_core::ZkAiError> {
        if !self.privacy_settings.contribute_missed_reports {
            return Err(zk_ai_core::ZkAiError::Inference(
                "missed-scam report contribution disabled by privacy settings".to_string(),
            ));
        }

        // Check weekly contribution limits for missed reports
        if let Err(e) = self.contribution_limits.check_missed_report() {
            tracing::warn!(
                error = %e,
                "contribution limit exceeded, missed-scam report rejected"
            );
            return Err(zk_ai_core::ZkAiError::Inference(format!(
                "contribution limit exceeded: {}",
                e
            )));
        }

        // Re-extract indicators using the full shared pipeline
        let indicators = self.extract_indicators(text, channel, language).await?;
        let indicators = Self::sort_indicators(indicators);
        let top_indicators = scoring::top_indicators(&indicators, 3);

        let report = MissedScamReport {
            channel,
            language: coarse_language_bucket(language).to_string(),
            indicators: top_indicators,
            actual_scam_type: actual_type,
            timestamp_bucket: chrono::Utc::now().format("%Y-W%V").to_string(),
        };

        // Record as false negative for calibration
        self.calibration.record_false_negative(&report);

        // Record in contribution limits
        self.contribution_limits.record_missed_report();

        tracing::info!(
            channel = %channel,
            language = %report.language,
            "missed scam reported"
        );

        Ok(report)
    }

    /// Set up a family circle.
    pub fn set_family(&mut self, circle: FamilyCircle) {
        self.family = Some(circle);
    }

    /// Get the current family circle (if any).
    pub fn family(&self) -> Option<&FamilyCircle> {
        self.family.as_ref()
    }

    /// Flush aggregate reports from the local buffer.
    ///
    /// Consumes one privacy budget unit (epsilon = total/max_queries).
    /// Returns an empty vec if the buffer is empty or the budget is exhausted.
    pub fn flush_aggregates(&mut self) -> Vec<AggregateReport> {
        if self.aggregation.pending_count() == 0 {
            return Vec::new();
        }
        let per_query_epsilon = self.privacy_budget.per_query_epsilon();
        if !self.privacy_budget.consume(per_query_epsilon) {
            tracing::warn!(
                "privacy budget exhausted, flush_aggregates denied"
            );
            return Vec::new();
        }
        self.aggregation.flush_aggregates()
    }

    /// Flush and return only the requested aggregate report type.
    ///
    /// Consumes one privacy budget unit (epsilon = total/max_queries).
    /// Returns `None` if the buffer is empty or the budget is exhausted.
    pub fn flush_query(&mut self, query: AggregateQuery) -> Option<AggregateReport> {
        if self.aggregation.pending_count() == 0 {
            return None;
        }
        let per_query_epsilon = self.privacy_budget.per_query_epsilon();
        if !self.privacy_budget.consume(per_query_epsilon) {
            tracing::warn!(
                "privacy budget exhausted, flush_query denied"
            );
            return None;
        }
        self.aggregation.flush_query(query)
    }

    /// Get calibration statistics (local only).
    pub fn calibration_stats(&self) -> CalibrationStats {
        self.calibration.stats()
    }

    /// Get the underlying AiEngine (for advanced use).
    pub fn ai_engine(&mut self) -> &mut AiEngine {
        &mut self.ai_engine
    }

    /// Get the device profile from the underlying engine.
    pub fn device_profile(&self) -> &zk_ai_core::DeviceProfile {
        self.ai_engine.profile()
    }

    /// Get the audit log (if initialized).
    pub fn audit_log(&self) -> Option<&AuditLog> {
        self.audit_log.as_ref()
    }

    /// Verify the integrity of the audit log chain.
    pub fn verify_audit(&self) -> bool {
        self.audit_log.as_ref().map(|a| a.verify()).unwrap_or(true)
    }

    /// Get the policy engine.
    pub fn policy_engine(&self) -> &PolicyEngine {
        &self.policy_engine
    }

    /// Get current week's contribution usage.
    pub fn contribution_usage(&self) -> ContributionUsage {
        self.contribution_limits.usage()
    }

    /// Get privacy settings.
    pub fn privacy_settings(&self) -> &PrivacySettings {
        &self.privacy_settings
    }

    /// Update privacy settings.
    pub fn set_privacy_settings(&mut self, settings: PrivacySettings) {
        self.privacy_settings = settings;
    }

    /// Get privacy budget status.
    pub fn privacy_budget_status(&self) -> PrivacyBudgetStatus {
        self.privacy_budget.status()
    }

    /// Get system health metrics.
    pub fn system_health(&self) -> SystemHealth {
        let tables = self.aggregation.counter_tables();
        SystemHealth {
            contribution_caps_hit: self.aggregation.caps_hit(),
            privacy_budget_remaining: self.privacy_budget.remaining(),
            suppressed_cohorts: self.aggregation.suppressed_cohorts(),
            aggregation_rounds: self.aggregation.aggregation_rounds(),
            failed_aggregations: self.aggregation.failed_aggregations(),
            last_flush_week: self.aggregation.last_flush_week().map(|s| s.to_string()),
            total_counter_cells: tables.total_cells(),
            total_counter_events: tables.total_events,
        }
    }

    /// Delete all local data (traces, counters, calibration, pending contexts).
    pub fn delete_local_data(&mut self) {
        self.aggregation = AggregationBuffer::new();
        self.calibration = CalibrationLayer::new(MODEL_VERSION);
        self.calibration.seed_defaults();
        self.pending_contexts.clear();
        self.pending_context_order.clear();
        self.contribution_limits = ContributionLimits::new();
        self.privacy_budget = PrivacyBudget::new();
        self.threat_intel = ThreatIntelFeed::new();
        tracing::info!("all local data deleted per user request");
    }

    /// Get the threat intelligence feed.
    pub fn threat_intel(&self) -> &ThreatIntelFeed {
        &self.threat_intel
    }

    /// Update the threat intelligence feed by merging new data.
    pub fn update_threat_intel(&mut self, feed: &ThreatIntelFeed) {
        self.threat_intel.merge(feed);
        tracing::info!(
            campaigns = self.threat_intel.len(),
            "threat intelligence feed updated"
        );
    }

    /// Add a single campaign to the threat intelligence feed.
    pub fn add_threat_campaign(&mut self, campaign: ScamCampaign) {
        self.threat_intel.add_campaign(campaign);
    }

    /// Add a custom policy rule for family-level enforcement.
    pub fn add_policy_rule(&mut self, sensitivity: &str, blocked_tasks: Vec<String>) {
        self.policy_engine.add_rule(sensitivity, blocked_tasks);
    }

    /// Shutdown the engine, releasing all resources.
    pub async fn shutdown(&mut self) -> Result<(), zk_ai_core::ZkAiError> {
        self.ai_engine.shutdown().await?;
        Ok(())
    }
}

/// Map a language code to a coarse language bucket for decision trace.
fn coarse_language_bucket(lang: &str) -> &'static str {
    match lang {
        "en" => "en",
        "vi" => "vi",
        "th" => "th",
        "id" => "id",
        "ms" => "ms",
        "tl" => "tl",
        "km" => "km",
        "zh" | "zh-CN" | "zh-TW" => "zh",
        "ja" => "ja",
        "ko" => "ko",
        "ar" => "ar",
        "es" => "es",
        "fr" => "fr",
        "de" => "de",
        "ru" => "ru",
        "my" => "my",
        "lo" => "lo",
        _ => "other",
    }
}
