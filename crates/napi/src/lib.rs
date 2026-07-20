//! N-API binding for zk-ai — Electron desktop (macOS, Windows, Linux).
//!
//! Exposes the zk-ai-core API to Node.js / Electron via napi-rs.

#![deny(clippy::all)]

use napi::bindgen_prelude::*;
use napi_derive::napi;

use zk_ai_core::{
    AiEngine, TaskOptions as CoreTaskOptions,
    DeviceCapability, DeviceTier,
};

/// Device tier string.
#[napi]
pub fn detect_device() -> Result<DeviceProfileJs> {
    let runtime = tokio::runtime::Runtime::new()
        .map_err(|e| Error::from_reason(format!("runtime: {e}")))?;
    let profile = runtime.block_on(zk_ai_core::DeviceProfiler::detect())
        .map_err(|e| Error::from_reason(e.to_string()))?;
    Ok(DeviceProfileJs::from(profile))
}

/// JS-facing device profile.
#[napi(object)]
pub struct DeviceProfileJs {
    pub tier: String,
    pub acceleration: String,
    pub total_memory_mb: u32,
    pub available_memory_mb: u32,
    pub cpu_cores: u32,
    pub has_npu: bool,
    pub npu_tops: Option<u32>,
    pub battery_level: Option<u8>,
    pub thermal_state: String,
    pub platform: String,
}

impl From<zk_ai_core::DeviceProfile> for DeviceProfileJs {
    fn from(p: zk_ai_core::DeviceProfile) -> Self {
        Self {
            tier: p.tier.to_string(),
            acceleration: p.acceleration.to_string(),
            total_memory_mb: p.total_memory_mb,
            available_memory_mb: p.available_memory_mb,
            cpu_cores: p.cpu_cores,
            has_npu: p.has_npu,
            npu_tops: p.npu_tops,
            battery_level: p.battery_level,
            thermal_state: format!("{:?}", p.thermal_state).to_lowercase(),
            platform: p.platform,
        }
    }
}

/// JS-facing task result.
#[napi(object)]
pub struct TaskResultJs {
    pub output: String,
    pub task: String,
    pub model: String,
    pub adapter: Option<String>,
    pub duration_ms: i64,
    pub input_tokens: u32,
    pub output_tokens: u32,
}

impl From<zk_ai_core::TaskResult> for TaskResultJs {
    fn from(r: zk_ai_core::TaskResult) -> Self {
        Self {
            output: r.output,
            task: r.task.to_string(),
            model: r.model,
            adapter: r.adapter,
            duration_ms: r.duration_ms as i64,
            input_tokens: r.input_tokens,
            output_tokens: r.output_tokens,
        }
    }
}

/// JS-facing task options.
#[napi(object)]
pub struct TaskOptionsJs {
    pub max_tokens: Option<u32>,
    pub stream: bool,
}

impl Default for TaskOptionsJs {
    fn default() -> Self {
        Self { max_tokens: None, stream: false }
    }
}

impl From<TaskOptionsJs> for CoreTaskOptions {
    fn from(opts: TaskOptionsJs) -> Self {
        CoreTaskOptions {
            max_tokens: opts.max_tokens.unwrap_or(0),
            stream: opts.stream,
            ..Default::default()
        }
    }
}

/// AI engine for desktop.
#[napi]
pub struct ZkAiEngine {
    inner: std::sync::Arc<tokio::sync::Mutex<Option<AiEngine>>>,
}

#[napi]
impl ZkAiEngine {
    #[napi(constructor)]
    pub fn new(cache_dir: String) -> Result<Self> {
        let runtime = tokio::runtime::Runtime::new()
            .map_err(|e| Error::from_reason(format!("runtime: {e}")))?;
        let engine = runtime.block_on(AiEngine::new(cache_dir))
            .map_err(|e| Error::from_reason(e.to_string()))?;
        Ok(Self { inner: std::sync::Arc::new(tokio::sync::Mutex::new(Some(engine))) })
    }

    #[napi]
    pub fn profile(&self) -> Result<DeviceProfileJs> {
        let inner = self.inner.clone();
        let runtime = tokio::runtime::Runtime::new()
            .map_err(|e| Error::from_reason(format!("runtime: {e}")))?;
        let guard = runtime.block_on(inner.lock());
        let p = guard.as_ref().unwrap().profile().clone();
        Ok(DeviceProfileJs::from(p))
    }

    #[napi]
    pub async fn summarize(&self, text: String, language: String) -> Result<TaskResultJs> {
        let inner = self.inner.clone();
        let mut guard = inner.lock().await;
        let result = guard.as_mut().unwrap()
            .summarize(&text, &language, CoreTaskOptions::default())
            .await
            .map_err(|e| Error::from_reason(e.to_string()))?;
        Ok(TaskResultJs::from(result))
    }

    /// Summarize with options (supports streaming).
    #[napi]
    pub async fn summarize_with_options(
        &self,
        text: String,
        language: String,
        options: TaskOptionsJs,
    ) -> Result<TaskResultJs> {
        let inner = self.inner.clone();
        let mut guard = inner.lock().await;
        let result = guard.as_mut().unwrap()
            .summarize(&text, &language, options.into())
            .await
            .map_err(|e| Error::from_reason(e.to_string()))?;
        Ok(TaskResultJs::from(result))
    }

    /// Summarize with streaming. Returns the full result after streaming
    /// completes internally. Use `summarize_with_options` with `stream: true`.
    #[napi]
    pub async fn summarize_stream(
        &self,
        text: String,
        language: String,
    ) -> Result<TaskResultJs> {
        let inner = self.inner.clone();
        let mut guard = inner.lock().await;
        let opts = CoreTaskOptions { stream: true, ..Default::default() };
        let result = guard.as_mut().unwrap()
            .summarize(&text, &language, opts)
            .await
            .map_err(|e| Error::from_reason(e.to_string()))?;
        Ok(TaskResultJs::from(result))
    }

    #[napi]
    pub async fn key_points(&self, text: String, language: String) -> Result<TaskResultJs> {
        let inner = self.inner.clone();
        let mut guard = inner.lock().await;
        let result = guard.as_mut().unwrap()
            .key_points(&text, &language, CoreTaskOptions::default())
            .await
            .map_err(|e| Error::from_reason(e.to_string()))?;
        Ok(TaskResultJs::from(result))
    }

    #[napi]
    pub async fn translate(
        &self,
        text: String,
        source_lang: String,
        target_lang: String,
    ) -> Result<TaskResultJs> {
        let inner = self.inner.clone();
        let mut guard = inner.lock().await;
        let result = guard.as_mut().unwrap()
            .translate(&text, &source_lang, &target_lang, CoreTaskOptions::default())
            .await
            .map_err(|e| Error::from_reason(e.to_string()))?;
        Ok(TaskResultJs::from(result))
    }

    #[napi]
    pub async fn generate_doc(
        &self,
        topic: String,
        outline: String,
        language: String,
    ) -> Result<TaskResultJs> {
        let inner = self.inner.clone();
        let mut guard = inner.lock().await;
        let result = guard.as_mut().unwrap()
            .generate_doc(&topic, &outline, &language, CoreTaskOptions::default())
            .await
            .map_err(|e| Error::from_reason(e.to_string()))?;
        Ok(TaskResultJs::from(result))
    }

    #[napi]
    pub async fn generate_slides(
        &self,
        topic: String,
        source_content: String,
        language: String,
    ) -> Result<TaskResultJs> {
        let inner = self.inner.clone();
        let mut guard = inner.lock().await;
        let result = guard.as_mut().unwrap()
            .generate_slides(&topic, &source_content, &language, CoreTaskOptions::default())
            .await
            .map_err(|e| Error::from_reason(e.to_string()))?;
        Ok(TaskResultJs::from(result))
    }

    #[napi]
    pub async fn image_search(&self, query: String) -> Result<TaskResultJs> {
        let inner = self.inner.clone();
        let mut guard = inner.lock().await;
        let result = guard.as_mut().unwrap()
            .image_search(&query, CoreTaskOptions::default())
            .await
            .map_err(|e| Error::from_reason(e.to_string()))?;
        Ok(TaskResultJs::from(result))
    }

    #[napi]
    pub async fn semantic_search(&self, query: String) -> Result<TaskResultJs> {
        let inner = self.inner.clone();
        let mut guard = inner.lock().await;
        let result = guard.as_mut().unwrap()
            .semantic_search(&query, CoreTaskOptions::default())
            .await
            .map_err(|e| Error::from_reason(e.to_string()))?;
        Ok(TaskResultJs::from(result))
    }

    #[napi]
    pub async fn shutdown(&self) -> Result<()> {
        let inner = self.inner.clone();
        let mut guard = inner.lock().await;
        guard.as_mut().unwrap()
            .shutdown()
            .await
            .map_err(|e| Error::from_reason(e.to_string()))
    }
}

/// Device capability for swarm coordination.
#[napi(object)]
pub struct SwarmCapabilityJs {
    pub device_id: String,
    pub device_name: String,
    pub tier: String,
    pub available_models: Vec<String>,
    pub battery_level: Option<u8>,
    pub is_idle: bool,
}

impl From<DeviceCapability> for SwarmCapabilityJs {
    fn from(c: DeviceCapability) -> Self {
        Self {
            device_id: c.device_id,
            device_name: c.device_name,
            tier: c.tier.to_string(),
            available_models: c.available_models,
            battery_level: c.battery_level,
            is_idle: c.is_idle,
        }
    }
}

impl From<SwarmCapabilityJs> for DeviceCapability {
    fn from(c: SwarmCapabilityJs) -> Self {
        let tier = match c.tier.as_str() {
            "high_end" => DeviceTier::HighEnd,
            "mid_range" => DeviceTier::MidRange,
            "low_end" => DeviceTier::LowEnd,
            _ => DeviceTier::Throttled,
        };
        Self {
            device_id: c.device_id,
            device_name: c.device_name,
            tier,
            available_models: c.available_models,
            battery_level: c.battery_level,
            is_idle: c.is_idle,
        }
    }
}

/// Swarm coordinator for distributed inference across devices.
#[napi]
pub struct SwarmCoordinatorJs {
    devices: std::sync::Mutex<Vec<DeviceCapability>>,
    local: DeviceCapability,
}

#[napi]
impl SwarmCoordinatorJs {
    #[napi(constructor)]
    pub fn new(
        device_id: String,
        device_name: String,
        tier: String,
        available_models: Vec<String>,
        battery_level: Option<u8>,
        is_idle: bool,
    ) -> Self {
        let cap = SwarmCapabilityJs {
            device_id,
            device_name,
            tier,
            available_models,
            battery_level,
            is_idle,
        };
        Self {
            devices: std::sync::Mutex::new(Vec::new()),
            local: cap.into(),
        }
    }

    /// Update a remote device's capability.
    #[napi]
    pub fn update_device(&mut self, cap: SwarmCapabilityJs) {
        let native: DeviceCapability = cap.into();
        let mut devices = self.devices.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(existing) = devices.iter_mut().find(|d| d.device_id == native.device_id) {
            *existing = native;
        } else {
            devices.push(native);
        }
    }

    /// Elect the best device for a given model.
    /// Returns the device ID or null if no suitable device.
    #[napi]
    pub fn elect_device(&self, required_model: String) -> Option<String> {
        let tier_rank = |t: &DeviceTier| match t {
            DeviceTier::HighEnd => 4,
            DeviceTier::MidRange => 3,
            DeviceTier::LowEnd => 2,
            DeviceTier::Throttled => 1,
        };
        let devices = self.devices.lock().unwrap_or_else(|e| e.into_inner());
        devices
            .iter()
            .filter(|d| d.available_models.contains(&required_model))
            .filter(|d| d.is_idle)
            .filter(|d| !matches!(d.tier, DeviceTier::Throttled))
            .max_by_key(|d| (tier_rank(&d.tier), d.battery_level.unwrap_or(100)))
            .map(|d| d.device_id.clone())
    }

    /// Check if the local device should volunteer for a request.
    #[napi]
    pub fn should_volunteer(&self, requester_id: String, required_model: String) -> bool {
        if !self.local.is_idle {
            return false;
        }
        if !self.local.available_models.contains(&required_model) {
            return false;
        }
        if matches!(self.local.tier, DeviceTier::Throttled) {
            return false;
        }
        if self.local.device_id == requester_id {
            return false;
        }
        true
    }

    /// Get the local device ID.
    #[napi(getter)]
    pub fn local_device_id(&self) -> String {
        self.local.device_id.clone()
    }

    /// Get all known device IDs.
    #[napi]
    pub fn device_ids(&self) -> Vec<String> {
        let devices = self.devices.lock().unwrap_or_else(|e| e.into_inner());
        devices.iter().map(|d| d.device_id.clone()).collect()
    }
}
