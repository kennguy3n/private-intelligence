//! WASM binding for zk-ai — browser + WebGPU.
//!
//! Exposes the zk-ai-core API to JavaScript via wasm-bindgen.
//! Runs inference in a Web Worker (off-main-thread) to avoid UI jank.

use std::rc::Rc;
use std::cell::RefCell;
use wasm_bindgen::prelude::*;
use zk_ai_core::{
    AiEngine, DeviceProfiler, DeviceProfile,
    TaskOptions as CoreTaskOptions,
    DeviceCapability, DeviceTier,
};

/// JS-facing device profile.
#[wasm_bindgen]
#[derive(Clone)]
pub struct JsDeviceProfile {
    inner: DeviceProfile,
}

#[wasm_bindgen]
impl JsDeviceProfile {
    #[wasm_bindgen(getter)]
    pub fn tier(&self) -> String { self.inner.tier.to_string() }

    #[wasm_bindgen(getter)]
    pub fn acceleration(&self) -> String { self.inner.acceleration.to_string() }

    #[wasm_bindgen(getter)]
    pub fn memory_mb(&self) -> u32 { self.inner.available_memory_mb }

    #[wasm_bindgen(getter)]
    pub fn cpu_cores(&self) -> u32 { self.inner.cpu_cores }

    #[wasm_bindgen(getter)]
    pub fn has_npu(&self) -> bool { self.inner.has_npu }

    #[wasm_bindgen(getter)]
    pub fn platform(&self) -> String { self.inner.platform.clone() }
}

/// Create a device profile from browser-detected values.
#[wasm_bindgen]
pub fn detect_device(
    has_webgpu: bool,
    cpu_cores: u32,
    device_memory_mb: u32,
    battery_level: Option<u8>,
) -> JsDeviceProfile {
    let profile = DeviceProfiler::from_js(has_webgpu, cpu_cores, device_memory_mb, battery_level);
    JsDeviceProfile { inner: profile }
}

/// JS-facing AI engine.
///
/// Uses `Rc<RefCell<>>` for interior mutability so that async futures
/// (which must be `'static`) can access the engine without borrowing `&mut self`.
#[wasm_bindgen]
pub struct JsAiEngine {
    engine: Rc<RefCell<Option<AiEngine>>>,
}

#[wasm_bindgen]
impl JsAiEngine {
    /// Create a new engine with the given cache directory.
    /// Returns a Promise that resolves to a `JsAiEngine`.
    #[wasm_bindgen(constructor)]
    pub fn new(_cache_dir: String) -> JsAiEngine {
        JsAiEngine {
            engine: Rc::new(RefCell::new(None)),
        }
    }

    /// Async factory: create and initialize the engine.
    /// Usage in JS: `const engine = await JsAiEngine.create("/cache");`
    pub fn create(cache_dir: String) -> js_sys::Promise {
        wasm_bindgen_futures::future_to_promise(async move {
            let engine = AiEngine::new(cache_dir)
                .await
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
            let js_engine = JsAiEngine {
                engine: Rc::new(RefCell::new(Some(engine))),
            };
            Ok(js_engine.into())
        })
    }

    /// Get the device profile.
    pub fn profile(&self) -> JsDeviceProfile {
        let profile = self.engine.borrow().as_ref().unwrap().profile().clone();
        JsDeviceProfile { inner: profile }
    }

    /// Summarize text.
    pub fn summarize(&self, text: String, language: String) -> js_sys::Promise {
        let engine = self.engine.clone();
        wasm_bindgen_futures::future_to_promise(async move {
            let result = engine.borrow_mut().as_mut().unwrap()
                .summarize(&text, &language, CoreTaskOptions::default())
                .await
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
            Ok(JsTaskResult { inner: result }.into())
        })
    }

    /// Extract key points.
    pub fn key_points(&self, text: String, language: String) -> js_sys::Promise {
        let engine = self.engine.clone();
        wasm_bindgen_futures::future_to_promise(async move {
            let result = engine.borrow_mut().as_mut().unwrap()
                .key_points(&text, &language, CoreTaskOptions::default())
                .await
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
            Ok(JsTaskResult { inner: result }.into())
        })
    }

    /// Translate text.
    pub fn translate(
        &self,
        text: String,
        source_lang: String,
        target_lang: String,
    ) -> js_sys::Promise {
        let engine = self.engine.clone();
        wasm_bindgen_futures::future_to_promise(async move {
            let result = engine.borrow_mut().as_mut().unwrap()
                .translate(&text, &source_lang, &target_lang, CoreTaskOptions::default())
                .await
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
            Ok(JsTaskResult { inner: result }.into())
        })
    }

    /// Generate a document.
    pub fn generate_doc(
        &self,
        topic: String,
        outline: String,
        language: String,
    ) -> js_sys::Promise {
        let engine = self.engine.clone();
        wasm_bindgen_futures::future_to_promise(async move {
            let result = engine.borrow_mut().as_mut().unwrap()
                .generate_doc(&topic, &outline, &language, CoreTaskOptions::default())
                .await
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
            Ok(JsTaskResult { inner: result }.into())
        })
    }

    /// Generate slide content.
    pub fn generate_slides(
        &self,
        topic: String,
        source_content: String,
        language: String,
    ) -> js_sys::Promise {
        let engine = self.engine.clone();
        wasm_bindgen_futures::future_to_promise(async move {
            let result = engine.borrow_mut().as_mut().unwrap()
                .generate_slides(&topic, &source_content, &language, CoreTaskOptions::default())
                .await
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
            Ok(JsTaskResult { inner: result }.into())
        })
    }

    /// Search for images.
    pub fn image_search(&self, query: String) -> js_sys::Promise {
        let engine = self.engine.clone();
        wasm_bindgen_futures::future_to_promise(async move {
            let result = engine.borrow_mut().as_mut().unwrap()
                .image_search(&query, CoreTaskOptions::default())
                .await
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
            Ok(JsTaskResult { inner: result }.into())
        })
    }

    /// Semantic search over text passages.
    pub fn semantic_search(&self, query: String) -> js_sys::Promise {
        let engine = self.engine.clone();
        wasm_bindgen_futures::future_to_promise(async move {
            let result = engine.borrow_mut().as_mut().unwrap()
                .semantic_search(&query, CoreTaskOptions::default())
                .await
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
            Ok(JsTaskResult { inner: result }.into())
        })
    }

    /// Summarize text with streaming enabled.
    pub fn summarize_stream(&self, text: String, language: String) -> js_sys::Promise {
        let engine = self.engine.clone();
        wasm_bindgen_futures::future_to_promise(async move {
            let opts = CoreTaskOptions { stream: true, ..Default::default() };
            let result = engine.borrow_mut().as_mut().unwrap()
                .summarize(&text, &language, opts)
                .await
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
            Ok(JsTaskResult { inner: result }.into())
        })
    }

    /// Shutdown the engine.
    pub fn shutdown(&self) -> js_sys::Promise {
        let engine = self.engine.clone();
        wasm_bindgen_futures::future_to_promise(async move {
            engine.borrow_mut().as_mut().unwrap()
                .shutdown()
                .await
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
            Ok(JsValue::UNDEFINED)
        })
    }
}

/// JS-facing task result.
#[wasm_bindgen]
pub struct JsTaskResult {
    inner: zk_ai_core::TaskResult,
}

#[wasm_bindgen]
impl JsTaskResult {
    #[wasm_bindgen(getter)]
    pub fn output(&self) -> String { self.inner.output.clone() }

    #[wasm_bindgen(getter)]
    pub fn task(&self) -> String { self.inner.task.to_string() }

    #[wasm_bindgen(getter)]
    pub fn model(&self) -> String { self.inner.model.clone() }

    #[wasm_bindgen(getter)]
    pub fn adapter(&self) -> Option<String> { self.inner.adapter.clone() }

    #[wasm_bindgen(getter)]
    pub fn duration_ms(&self) -> u64 { self.inner.duration_ms }

    #[wasm_bindgen(getter)]
    pub fn input_tokens(&self) -> u32 { self.inner.input_tokens }

    #[wasm_bindgen(getter)]
    pub fn output_tokens(&self) -> u32 { self.inner.output_tokens }
}

/// JS-facing device capability for swarm.
#[wasm_bindgen]
pub struct JsSwarmCapability {
    device_id: String,
    device_name: String,
    tier: String,
    available_models: Vec<String>,
    battery_level: Option<u8>,
    is_idle: bool,
}

#[wasm_bindgen]
impl JsSwarmCapability {
    #[wasm_bindgen(constructor)]
    pub fn new(
        device_id: String,
        device_name: String,
        tier: String,
        available_models: Vec<String>,
        battery_level: Option<u8>,
        is_idle: bool,
    ) -> Self {
        Self {
            device_id,
            device_name,
            tier,
            available_models,
            battery_level,
            is_idle,
        }
    }

    #[wasm_bindgen(getter)]
    pub fn device_id(&self) -> String { self.device_id.clone() }
    #[wasm_bindgen(setter)]
    pub fn set_device_id(&mut self, v: String) { self.device_id = v; }

    #[wasm_bindgen(getter)]
    pub fn device_name(&self) -> String { self.device_name.clone() }
    #[wasm_bindgen(setter)]
    pub fn set_device_name(&mut self, v: String) { self.device_name = v; }

    #[wasm_bindgen(getter)]
    pub fn tier(&self) -> String { self.tier.clone() }
    #[wasm_bindgen(setter)]
    pub fn set_tier(&mut self, v: String) { self.tier = v; }

    #[wasm_bindgen(getter)]
    pub fn available_models(&self) -> Vec<String> { self.available_models.clone() }
    #[wasm_bindgen(setter)]
    pub fn set_available_models(&mut self, v: Vec<String>) { self.available_models = v; }

    #[wasm_bindgen(getter)]
    pub fn battery_level(&self) -> Option<u8> { self.battery_level }
    #[wasm_bindgen(setter)]
    pub fn set_battery_level(&mut self, v: Option<u8>) { self.battery_level = v; }

    #[wasm_bindgen(getter)]
    pub fn is_idle(&self) -> bool { self.is_idle }
    #[wasm_bindgen(setter)]
    pub fn set_is_idle(&mut self, v: bool) { self.is_idle = v; }
}

impl From<DeviceCapability> for JsSwarmCapability {
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

impl From<JsSwarmCapability> for DeviceCapability {
    fn from(c: JsSwarmCapability) -> Self {
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

/// JS-facing swarm coordinator.
///
/// The JS layer implements the transport (XMPP/MLS) natively and passes
/// capability updates / election results through this wrapper.
#[wasm_bindgen]
pub struct JsSwarmCoordinator {
    devices: Vec<DeviceCapability>,
    local: DeviceCapability,
}

#[wasm_bindgen]
impl JsSwarmCoordinator {
    /// Create a new swarm coordinator from a device profile + capability info.
    #[wasm_bindgen(constructor)]
    pub fn new(
        device_id: String,
        device_name: String,
        tier: String,
        available_models: Vec<String>,
        battery_level: Option<u8>,
        is_idle: bool,
    ) -> JsSwarmCoordinator {
        let cap = JsSwarmCapability::new(
            device_id,
            device_name,
            tier,
            available_models,
            battery_level,
            is_idle,
        );
        Self {
            devices: Vec::new(),
            local: cap.into(),
        }
    }

    /// Update a remote device's capability.
    pub fn update_device(&mut self, cap: JsSwarmCapability) {
        let native: DeviceCapability = cap.into();
        if let Some(existing) = self.devices.iter_mut().find(|d| d.device_id == native.device_id) {
            *existing = native;
        } else {
            self.devices.push(native);
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
        self.devices
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
    #[wasm_bindgen(getter)]
    pub fn local_device_id(&self) -> String {
        self.local.device_id.clone()
    }

    /// Get all known device IDs.
    pub fn device_ids(&self) -> Vec<String> {
        self.devices.iter().map(|d| d.device_id.clone()).collect()
    }
}
