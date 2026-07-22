//! Swarm inference coordinator.
//!
//! Enables one device in a group (e.g., a KChat channel) to process
//! AI tasks for the entire group. Uses the group's existing MLS/XMPP
//! messaging infrastructure for E2E-encrypted transport.
//!
//! # Protocol
//!
//! 1. **Capability broadcast**: each device publishes its DeviceProfile
//!    (tier, available models, battery) to the group.
//! 2. **Task initiation**: any member sends an inference request.
//! 3. **Device election**: highest-tier idle device with the required
//!    model volunteers.
//! 4. **Input transfer**: input is MLS-encrypted (by KChat), sent via
//!    XMPP to the elected device.
//! 5. **Inference**: elected device runs inference locally.
//! 6. **Result return**: result sent back via XMPP (MLS-encrypted).
//! 7. **Fallback**: if no device volunteers within 5s, initiator falls
//!    back to local inference or server offload.

use serde::{Deserialize, Serialize};
use std::time::Duration;
use async_trait::async_trait;
use crate::profiler::{DeviceProfile, DeviceTier};
use crate::pipeline::{Task, TaskOptions, TaskResult};
use crate::Result;

/// A device's advertised capabilities in the swarm.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceCapability {
    /// Unique device identifier.
    pub device_id: String,
    /// Human-readable device name.
    pub device_name: String,
    /// Device tier.
    pub tier: DeviceTier,
    /// Available models (by name).
    pub available_models: Vec<String>,
    /// Battery level (0-100, None if on AC power).
    pub battery_level: Option<u8>,
    /// Whether the device is currently idle (not running inference).
    pub is_idle: bool,
}

/// An inference request sent through the swarm.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InferenceRequest {
    /// Unique request ID.
    pub request_id: String,
    /// The task to perform.
    pub task: Task,
    /// Input text (MLS-encrypted by the transport layer).
    pub input: String,
    /// Language for the task.
    pub language: String,
    /// Target language (for translation tasks).
    pub target_language: Option<String>,
    /// Task options.
    pub options: TaskOptions,
    /// Requesting device ID.
    pub requester_id: String,
    /// Timestamp.
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// An inference result returned through the swarm.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InferenceResult {
    /// Matching request ID.
    pub request_id: String,
    /// The result (MLS-encrypted by the transport layer).
    pub result: TaskResult,
    /// Device that performed the inference.
    pub responder_id: String,
    /// Timestamp.
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// Transport interface for swarm communication.
///
/// Consumers (KChat, zk-drive collaboration) implement this trait
/// over their existing messaging infrastructure (XMPP/MLS).
#[async_trait]
pub trait SwarmTransport: Send + Sync {
    /// Broadcast this device's capabilities to the group.
    async fn broadcast_capability(&self, cap: &DeviceCapability) -> Result<()>;

    /// Send an inference request to the group.
    async fn send_request(&self, request: &InferenceRequest) -> Result<()>;

    /// Send an inference result to the group.
    async fn send_result(&self, result: &InferenceResult) -> Result<()>;

    /// Receive the next inference request (for elected devices).
    async fn recv_request(&self) -> Result<InferenceRequest>;

    /// Receive the next inference result (for requesters).
    async fn recv_result(&self) -> Result<InferenceResult>;

    /// Receive a capability update from another device.
    async fn recv_capability(&self) -> Result<DeviceCapability>;
}

/// The swarm coordinator manages device discovery, election, and
/// task routing.
pub struct SwarmCoordinator<T: SwarmTransport> {
    transport: T,
    local_device: DeviceCapability,
    /// Known devices in the swarm.
    devices: Vec<DeviceCapability>,
    /// Timeout for waiting for a volunteer.
    election_timeout: Duration,
}

impl<T: SwarmTransport> SwarmCoordinator<T> {
    /// Create a new swarm coordinator.
    pub fn new(transport: T, local_device: DeviceCapability) -> Self {
        Self {
            transport,
            local_device,
            devices: Vec::new(),
            election_timeout: Duration::from_secs(5),
        }
    }

    /// Broadcast our capabilities to the group.
    pub async fn announce(&self) -> Result<()> {
        self.transport.broadcast_capability(&self.local_device).await
    }

    /// Update a device's capability (called when a capability update
    /// is received).
    pub fn update_device(&mut self, cap: DeviceCapability) {
        if let Some(existing) = self.devices.iter_mut().find(|d| d.device_id == cap.device_id) {
            *existing = cap;
        } else {
            self.devices.push(cap);
        }
    }

    /// Elect the best device to handle an inference request.
    ///
    /// Selection criteria (in order):
    /// 1. Has the required model available
    /// 2. Is idle
    /// 3. Highest tier
    /// 4. Highest battery level (or on AC power)
    pub fn elect_device(&self, required_model: &str) -> Option<&DeviceCapability> {
        let tier_rank = |t: &DeviceTier| match t {
            DeviceTier::HighEnd => 4,
            DeviceTier::MidRange => 3,
            DeviceTier::LowEnd => 2,
            DeviceTier::Throttled => 1,
        };

        self.devices
            .iter()
            .filter(|d| d.available_models.contains(&required_model.to_string()))
            .filter(|d| d.is_idle)
            .filter(|d| !matches!(d.tier, DeviceTier::Throttled))
            .max_by_key(|d| {
                (
                    tier_rank(&d.tier),
                    d.battery_level.unwrap_or(100),
                )
            })
    }

    /// Submit a task to the swarm. If a suitable device is available,
    /// the task is sent to it. Otherwise, returns None (caller should
    /// fall back to local inference or server offload).
    pub async fn submit_task(
        &self,
        task: Task,
        input: String,
        language: String,
        target_language: Option<String>,
        options: TaskOptions,
    ) -> Result<Option<String>> {
        let required_model = match &task {
            Task::ImageSearch => "clip-vit-base-patch32",
            Task::Transcribe | Task::LiveTranscribe | Task::VoiceAction | Task::DictateFormat => "whisper-tiny",
            Task::SemanticSearch | Task::ClassifyTone | Task::Prioritize | Task::AutoTag
            | Task::FindSimilar | Task::Cluster | Task::FindClause | Task::ExtractDates
            | Task::ClassifyUrgency | Task::EmailCategorize | Task::Sentiment
            | Task::PiiScan | Task::ClassifySensitivity | Task::Dedup | Task::FindExpert
            | Task::Rerank => "multilingual-e5-small",
            _ => "mt5-small",
        };

        let elected = self.elect_device(required_model);

        if let Some(_device) = elected {
            let request = InferenceRequest {
                request_id: uuid::Uuid::new_v4().to_string(),
                task,
                input,
                language,
                target_language,
                options,
                requester_id: self.local_device.device_id.clone(),
                timestamp: chrono::Utc::now(),
            };

            self.transport.send_request(&request).await?;

            // Wait for a result within the election timeout
            let result = tokio::time::timeout(
                self.election_timeout,
                self.transport.recv_result(),
            ).await;

            match result {
                Ok(Ok(res)) => return Ok(Some(res.result.output)),
                Ok(Err(_)) | Err(_) => {
                    tracing::warn!("swarm inference timed out or failed, falling back");
                    return Ok(None);
                }
            }
        } else {
            // No suitable device — caller should fall back
            Ok(None)
        }
    }

    /// Check if the local device should volunteer for a request.
    pub fn should_volunteer(&self, request: &InferenceRequest, required_model: &str) -> bool {
        if !self.local_device.is_idle {
            return false;
        }
        if !self.local_device.available_models.contains(&required_model.to_string()) {
            return false;
        }
        if matches!(self.local_device.tier, DeviceTier::Throttled) {
            return false;
        }
        // Don't volunteer for our own requests
        if request.requester_id == self.local_device.device_id {
            return false;
        }
        true
    }

    /// Get the local device capability.
    pub fn local_device(&self) -> &DeviceCapability {
        &self.local_device
    }

    /// Get all known devices in the swarm.
    pub fn devices(&self) -> &[DeviceCapability] {
        &self.devices
    }
}

/// Create a DeviceCapability from a DeviceProfile.
pub fn capability_from_profile(
    profile: &DeviceProfile,
    device_id: String,
    device_name: String,
    available_models: Vec<String>,
    is_idle: bool,
) -> DeviceCapability {
    DeviceCapability {
        device_id,
        device_name,
        tier: profile.tier,
        available_models,
        battery_level: profile.battery_level,
        is_idle,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ZkAiError;

    fn mock_device(id: &str, tier: DeviceTier, idle: bool, models: Vec<&str>) -> DeviceCapability {
        DeviceCapability {
            device_id: id.to_string(),
            device_name: id.to_string(),
            tier,
            available_models: models.iter().map(|s| s.to_string()).collect(),
            battery_level: Some(80),
            is_idle: idle,
        }
    }

    #[test]
    fn test_elect_device_picks_highest_tier() {
        let transport = MockTransport;
        let mut coord = SwarmCoordinator::new(transport, mock_device("local", DeviceTier::LowEnd, true, vec!["mt5-small"]));
        coord.update_device(mock_device("dev1", DeviceTier::MidRange, true, vec!["mt5-small"]));
        coord.update_device(mock_device("dev2", DeviceTier::HighEnd, true, vec!["mt5-small"]));

        let elected = coord.elect_device("mt5-small").unwrap();
        assert_eq!(elected.device_id, "dev2");
    }

    #[test]
    fn test_elect_device_skips_busy() {
        let transport = MockTransport;
        let mut coord = SwarmCoordinator::new(transport, mock_device("local", DeviceTier::LowEnd, true, vec!["mt5-small"]));
        coord.update_device(mock_device("dev1", DeviceTier::HighEnd, false, vec!["mt5-small"]));
        coord.update_device(mock_device("dev2", DeviceTier::MidRange, true, vec!["mt5-small"]));

        let elected = coord.elect_device("mt5-small").unwrap();
        assert_eq!(elected.device_id, "dev2");
    }

    #[test]
    fn test_elect_device_skips_missing_model() {
        let transport = MockTransport;
        let mut coord = SwarmCoordinator::new(transport, mock_device("local", DeviceTier::LowEnd, true, vec!["mt5-small"]));
        coord.update_device(mock_device("dev1", DeviceTier::HighEnd, true, vec!["clip-vit-base-patch32"]));

        let elected = coord.elect_device("mt5-small");
        assert!(elected.is_none());
    }

    #[test]
    fn test_elect_device_skips_throttled() {
        let transport = MockTransport;
        let mut coord = SwarmCoordinator::new(transport, mock_device("local", DeviceTier::LowEnd, true, vec!["mt5-small"]));
        coord.update_device(mock_device("dev1", DeviceTier::Throttled, true, vec!["mt5-small"]));
        coord.update_device(mock_device("dev2", DeviceTier::LowEnd, true, vec!["mt5-small"]));

        let elected = coord.elect_device("mt5-small").unwrap();
        assert_eq!(elected.device_id, "dev2");
    }

    #[test]
    fn test_should_volunteer() {
        let transport = MockTransport;
        let local = mock_device("local", DeviceTier::HighEnd, true, vec!["mt5-small"]);
        let coord = SwarmCoordinator::new(transport, local);

        let request = InferenceRequest {
            request_id: "req1".to_string(),
            task: Task::Summarize,
            input: "test".to_string(),
            language: "en".to_string(),
            target_language: None,
            options: TaskOptions::default(),
            requester_id: "other".to_string(),
            timestamp: chrono::Utc::now(),
        };

        assert!(coord.should_volunteer(&request, "mt5-small"));
    }

    #[test]
    fn test_should_not_volunteer_for_own_request() {
        let transport = MockTransport;
        let local = mock_device("local", DeviceTier::HighEnd, true, vec!["mt5-small"]);
        let coord = SwarmCoordinator::new(transport, local);

        let request = InferenceRequest {
            request_id: "req1".to_string(),
            task: Task::Summarize,
            input: "test".to_string(),
            language: "en".to_string(),
            target_language: None,
            options: TaskOptions::default(),
            requester_id: "local".to_string(),
            timestamp: chrono::Utc::now(),
        };

        assert!(!coord.should_volunteer(&request, "mt5-small"));
    }

    // Mock transport for testing
    struct MockTransport;

    #[async_trait]
    impl SwarmTransport for MockTransport {
        async fn broadcast_capability(&self, _: &DeviceCapability) -> Result<()> { Ok(()) }
        async fn send_request(&self, _: &InferenceRequest) -> Result<()> { Ok(()) }
        async fn send_result(&self, _: &InferenceResult) -> Result<()> { Ok(()) }
        async fn recv_request(&self) -> Result<InferenceRequest> {
            Err(ZkAiError::Swarm("mock".to_string()))
        }
        async fn recv_result(&self) -> Result<InferenceResult> {
            Err(ZkAiError::Swarm("mock".to_string()))
        }
        async fn recv_capability(&self) -> Result<DeviceCapability> {
            Err(ZkAiError::Swarm("mock".to_string()))
        }
    }
}
