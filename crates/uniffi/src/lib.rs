//! UniFFI bindings for zk-ai — iOS (Swift) and Android (Kotlin).
//!
//! Exposes the zk-ai-core API to native mobile apps via UniFFI.

uniffi::setup_scaffolding!();

use zk_ai_core::{
    AiEngine, DeviceProfile, DeviceTier, Acceleration, ThermalState,
    TaskOptions as CoreTaskOptions, TaskResult as CoreTaskResult,
    ModelSpec, ModelManager,
    DeviceCapability,
};

/// Device tier enum for FFI.
#[uniffi::export]
pub fn detect_device() -> FfiDeviceProfile {
    // On mobile, the binding layer (Swift/Kotlin) should call
    // detect_device_with_values instead, passing platform-specific
    // values. This default uses the core's native detection.
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let profile = runtime.block_on(DeviceProfiler::detect()).unwrap_or_default();
    FfiDeviceProfile::from(profile)
}

/// Detect device with externally-provided values (from Swift/Kotlin).
#[uniffi::export]
pub fn detect_device_with_values(
    acceleration: String,
    total_memory_mb: u32,
    cpu_cores: u32,
    has_npu: bool,
    npu_tops: Option<u32>,
    battery_level: Option<u8>,
    thermal_state: String,
    platform: String,
) -> FfiDeviceProfile {
    let acc = match acceleration.as_str() {
        "metal" => Acceleration::Metal,
        "coreml" => Acceleration::CoreML,
        "directml" => Acceleration::DirectML,
        "cuda" => Acceleration::Cuda,
        "vulkan" => Acceleration::Vulkan,
        "nnapi" => Acceleration::NNAPI,
        "webgpu" => Acceleration::WebGPU,
        "cpu_simd" => Acceleration::CpuSimd,
        _ => Acceleration::Cpu,
    };

    let thermal = match thermal_state.as_str() {
        "nominal" => ThermalState::Nominal,
        "fair" => ThermalState::Fair,
        "serious" => ThermalState::Serious,
        "critical" => ThermalState::Critical,
        _ => ThermalState::Nominal,
    };

    let mut profile = DeviceProfile {
        tier: DeviceTier::LowEnd,
        acceleration: acc,
        total_memory_mb,
        available_memory_mb: (total_memory_mb as f64 * 0.7) as u32,
        cpu_cores,
        has_npu,
        npu_tops,
        battery_level,
        thermal_state: thermal,
        platform,
        arch: "aarch64".to_string(),
    };

    // Recompute tier
    profile.tier = compute_tier_external(&profile);
    FfiDeviceProfile::from(profile)
}

/// FFI-facing device profile.
#[derive(uniffi::Record)]
pub struct FfiDeviceProfile {
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

impl From<DeviceProfile> for FfiDeviceProfile {
    fn from(p: DeviceProfile) -> Self {
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

/// FFI-facing task result.
#[derive(uniffi::Record)]
pub struct FfiTaskResult {
    pub output: String,
    pub task: String,
    pub model: String,
    pub adapter: Option<String>,
    pub duration_ms: u64,
    pub input_tokens: u32,
    pub output_tokens: u32,
}

impl From<CoreTaskResult> for FfiTaskResult {
    fn from(r: CoreTaskResult) -> Self {
        Self {
            output: r.output,
            task: r.task.to_string(),
            model: r.model,
            adapter: r.adapter,
            duration_ms: r.duration_ms,
            input_tokens: r.input_tokens,
            output_tokens: r.output_tokens,
        }
    }
}

/// FFI-facing task options.
#[derive(uniffi::Record)]
pub struct FfiTaskOptions {
    pub max_tokens: u32,
    pub stream: bool,
}

impl Default for FfiTaskOptions {
    fn default() -> Self {
        Self { max_tokens: 256, stream: false }
    }
}

impl From<FfiTaskOptions> for CoreTaskOptions {
    fn from(opts: FfiTaskOptions) -> Self {
        CoreTaskOptions {
            max_tokens: opts.max_tokens,
            stream: opts.stream,
            ..Default::default()
        }
    }
}

/// FFI-facing AI engine.
#[derive(uniffi::Object)]
pub struct ZkAiEngine {
    inner: tokio::sync::Mutex<AiEngine>,
}

#[uniffi::export]
impl ZkAiEngine {
    #[uniffi::constructor]
    pub fn new(cache_dir: String) -> Result<Self, String> {
        let runtime = tokio::runtime::Runtime::new().map_err(|e| e.to_string())?;
        let engine = runtime.block_on(AiEngine::new(cache_dir)).map_err(|e| e.to_string())?;
        Ok(Self { inner: tokio::sync::Mutex::new(engine) })
    }

    pub fn profile(&self) -> FfiDeviceProfile {
        let runtime = tokio::runtime::Runtime::new().map_err(|e| e.to_string()).unwrap();
        let guard = runtime.block_on(self.inner.lock());
        FfiDeviceProfile::from(guard.profile().clone())
    }

    pub async fn summarize(&self, text: String, language: String) -> Result<FfiTaskResult, String> {
        let mut guard = self.inner.lock().await;
        guard.summarize(&text, &language, CoreTaskOptions::default())
            .await
            .map(FfiTaskResult::from)
            .map_err(|e| e.to_string())
    }

    /// Summarize with options (supports streaming).
    pub async fn summarize_with_options(
        &self,
        text: String,
        language: String,
        options: FfiTaskOptions,
    ) -> Result<FfiTaskResult, String> {
        let mut guard = self.inner.lock().await;
        guard.summarize(&text, &language, options.into())
            .await
            .map(FfiTaskResult::from)
            .map_err(|e| e.to_string())
    }

    /// Summarize with streaming enabled.
    pub async fn summarize_stream(&self, text: String, language: String) -> Result<FfiTaskResult, String> {
        let mut guard = self.inner.lock().await;
        let opts = CoreTaskOptions { stream: true, ..Default::default() };
        guard.summarize(&text, &language, opts)
            .await
            .map(FfiTaskResult::from)
            .map_err(|e| e.to_string())
    }

    pub async fn key_points(&self, text: String, language: String) -> Result<FfiTaskResult, String> {
        let mut guard = self.inner.lock().await;
        guard.key_points(&text, &language, CoreTaskOptions::default())
            .await
            .map(FfiTaskResult::from)
            .map_err(|e| e.to_string())
    }

    pub async fn translate(
        &self,
        text: String,
        source_lang: String,
        target_lang: String,
    ) -> Result<FfiTaskResult, String> {
        let mut guard = self.inner.lock().await;
        guard.translate(&text, &source_lang, &target_lang, CoreTaskOptions::default())
            .await
            .map(FfiTaskResult::from)
            .map_err(|e| e.to_string())
    }

    pub async fn generate_doc(
        &self,
        topic: String,
        outline: String,
        language: String,
    ) -> Result<FfiTaskResult, String> {
        let mut guard = self.inner.lock().await;
        guard.generate_doc(&topic, &outline, &language, CoreTaskOptions::default())
            .await
            .map(FfiTaskResult::from)
            .map_err(|e| e.to_string())
    }

    pub async fn generate_slides(
        &self,
        topic: String,
        source_content: String,
        language: String,
    ) -> Result<FfiTaskResult, String> {
        let mut guard = self.inner.lock().await;
        guard.generate_slides(&topic, &source_content, &language, CoreTaskOptions::default())
            .await
            .map(FfiTaskResult::from)
            .map_err(|e| e.to_string())
    }

    pub async fn image_search(&self, query: String) -> Result<FfiTaskResult, String> {
        let mut guard = self.inner.lock().await;
        guard.image_search(&query, CoreTaskOptions::default())
            .await
            .map(FfiTaskResult::from)
            .map_err(|e| e.to_string())
    }

    pub async fn semantic_search(&self, query: String) -> Result<FfiTaskResult, String> {
        let mut guard = self.inner.lock().await;
        guard.semantic_search(&query, CoreTaskOptions::default())
            .await
            .map(FfiTaskResult::from)
            .map_err(|e| e.to_string())
    }

    pub async fn shutdown(&self) -> Result<(), String> {
        let mut guard = self.inner.lock().await;
        guard.shutdown().await.map_err(|e| e.to_string())
    }
}

/// External tier computation (mirrors the private function in profiler.rs).
fn compute_tier_external(profile: &DeviceProfile) -> DeviceTier {
    if let Some(level) = profile.battery_level {
        if level < 20 {
            return DeviceTier::Throttled;
        }
    }
    match profile.thermal_state {
        ThermalState::Serious | ThermalState::Critical => return DeviceTier::Throttled,
        _ => {}
    }

    let has_strong_gpu = matches!(
        profile.acceleration,
        Acceleration::Metal | Acceleration::CoreML | Acceleration::Cuda | Acceleration::DirectML
    );
    let has_strong_npu = profile.npu_tops.unwrap_or(0) >= 10;
    let has_strong_memory = profile.available_memory_mb >= 8192;

    if has_strong_gpu && has_strong_memory {
        return DeviceTier::HighEnd;
    }
    if has_strong_npu && profile.available_memory_mb >= 4096 {
        return DeviceTier::HighEnd;
    }

    let has_mid_npu = profile.npu_tops.unwrap_or(0) >= 5;
    let has_mid_memory = profile.available_memory_mb >= 4096;
    let has_any_gpu = matches!(
        profile.acceleration,
        Acceleration::Metal | Acceleration::CoreML | Acceleration::DirectML
            | Acceleration::Vulkan | Acceleration::NNAPI | Acceleration::WebGPU
    );

    if has_any_gpu && has_mid_memory {
        return DeviceTier::MidRange;
    }
    if has_mid_npu {
        return DeviceTier::MidRange;
    }

    DeviceTier::LowEnd
}

// Re-export for the binding
pub use zk_ai_core::DeviceProfiler;

/// FFI-facing swarm device capability.
#[derive(uniffi::Record)]
pub struct FfiSwarmCapability {
    pub device_id: String,
    pub device_name: String,
    pub tier: String,
    pub available_models: Vec<String>,
    pub battery_level: Option<u8>,
    pub is_idle: bool,
}

impl From<DeviceCapability> for FfiSwarmCapability {
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

impl From<FfiSwarmCapability> for DeviceCapability {
    fn from(c: FfiSwarmCapability) -> Self {
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

/// FFI-facing swarm coordinator.
#[derive(uniffi::Object)]
pub struct FfiSwarmCoordinator {
    devices: std::sync::Mutex<Vec<DeviceCapability>>,
    local: DeviceCapability,
}

#[uniffi::export]
impl FfiSwarmCoordinator {
    #[uniffi::constructor]
    pub fn new(
        device_id: String,
        device_name: String,
        tier: String,
        available_models: Vec<String>,
        battery_level: Option<u8>,
        is_idle: bool,
    ) -> Self {
        let cap = FfiSwarmCapability {
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
    pub fn update_device(&self, cap: FfiSwarmCapability) {
        let native: DeviceCapability = cap.into();
        let mut devices = self.devices.lock().unwrap();
        if let Some(existing) = devices.iter_mut().find(|d| d.device_id == native.device_id) {
            *existing = native;
        } else {
            devices.push(native);
        }
    }

    /// Elect the best device for a given model.
    /// Returns the device ID or null if no suitable device.
    pub fn elect_device(&self, required_model: String) -> Option<String> {
        let tier_rank = |t: &DeviceTier| match t {
            DeviceTier::HighEnd => 4,
            DeviceTier::MidRange => 3,
            DeviceTier::LowEnd => 2,
            DeviceTier::Throttled => 1,
        };
        let devices = self.devices.lock().unwrap();
        devices
            .iter()
            .filter(|d| d.available_models.contains(&required_model))
            .filter(|d| d.is_idle)
            .filter(|d| !matches!(d.tier, DeviceTier::Throttled))
            .max_by_key(|d| (tier_rank(&d.tier), d.battery_level.unwrap_or(100)))
            .map(|d| d.device_id.clone())
    }

    /// Check if the local device should volunteer for a request.
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
    pub fn local_device_id(&self) -> String {
        self.local.device_id.clone()
    }

    /// Get all known device IDs.
    pub fn device_ids(&self) -> Vec<String> {
        let devices = self.devices.lock().unwrap();
        devices.iter().map(|d| d.device_id.clone()).collect()
    }
}
