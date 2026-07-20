//! C ABI for zk-ai — Go cgo binding (server-side offload service).
//!
//! Exposes a minimal C interface that the Go server wraps via cgo.
//! The Go server handles HTTP, auth, and privacy guards; this crate
//! just provides the inference entry points.

#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::sync::{Mutex, MutexGuard};
use zk_ai_core::{AiEngine, TaskOptions, DeviceCapability, DeviceTier};

/// Global engine instance and tokio runtime (created once at init).
struct GlobalState {
    engine: Option<AiEngine>,
    runtime: Option<tokio::runtime::Runtime>,
}

static STATE: Mutex<GlobalState> = Mutex::new(GlobalState {
    engine: None,
    runtime: None,
});

/// Lock the global state, recovering from mutex poisoning.
fn lock_state() -> MutexGuard<'static, GlobalState> {
    STATE.lock().unwrap_or_else(|e| e.into_inner())
}

/// Serialize a result to a C string, safely handling null bytes.
fn to_c_string<T: serde::Serialize>(val: &T) -> *mut c_char {
    let json = serde_json::to_string(val).unwrap_or_default();
    match CString::new(json) {
        Ok(s) => CString::into_raw(s),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Initialize the AI engine with a cache directory.
///
/// # Safety
/// `cache_dir` must be a valid null-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn zkai_init(cache_dir: *const c_char) -> i32 {
    let cache_dir = match CStr::from_ptr(cache_dir).to_str() {
        Ok(s) => s,
        Err(_) => return -1,
    };

    let runtime = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(_) => return -2,
    };

    let engine = match runtime.block_on(AiEngine::new(cache_dir)) {
        Ok(e) => e,
        Err(_) => return -3,
    };

    let mut guard = lock_state();
    guard.engine = Some(engine);
    guard.runtime = Some(runtime);
    0
}

/// Run a summarization task.
///
/// # Safety
/// `text` and `language` must be valid null-terminated C strings.
/// The returned string must be freed with `zkai_free_string`.
#[no_mangle]
pub unsafe extern "C" fn zkai_summarize(
    text: *const c_char,
    language: *const c_char,
) -> *mut c_char {
    let text = match CStr::from_ptr(text).to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };
    let language = match CStr::from_ptr(language).to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };

    let mut guard = lock_state();
    let runtime = match guard.runtime.take() {
        Some(rt) => rt,
        None => return std::ptr::null_mut(),
    };
    let mut engine = match guard.engine.take() {
        Some(e) => e,
        None => {
            guard.runtime = Some(runtime);
            return std::ptr::null_mut();
        }
    };

    let result = runtime.block_on(engine.summarize(text, language, TaskOptions::default()));
    guard.engine = Some(engine);
    guard.runtime = Some(runtime);
    match result {
        Ok(r) => to_c_string(&r),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Run a translation task.
#[no_mangle]
pub unsafe extern "C" fn zkai_translate(
    text: *const c_char,
    source_lang: *const c_char,
    target_lang: *const c_char,
) -> *mut c_char {
    let text = match CStr::from_ptr(text).to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };
    let source_lang = match CStr::from_ptr(source_lang).to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };
    let target_lang = match CStr::from_ptr(target_lang).to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };

    let mut guard = lock_state();
    let runtime = match guard.runtime.take() {
        Some(rt) => rt,
        None => return std::ptr::null_mut(),
    };
    let mut engine = match guard.engine.take() {
        Some(e) => e,
        None => {
            guard.runtime = Some(runtime);
            return std::ptr::null_mut();
        }
    };

    let result = runtime.block_on(engine.translate(text, source_lang, target_lang, TaskOptions::default()));
    guard.engine = Some(engine);
    guard.runtime = Some(runtime);
    match result {
        Ok(r) => to_c_string(&r),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Run a key-point extraction task.
#[no_mangle]
pub unsafe extern "C" fn zkai_key_points(
    text: *const c_char,
    language: *const c_char,
) -> *mut c_char {
    let text = match CStr::from_ptr(text).to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };
    let language = match CStr::from_ptr(language).to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };

    let mut guard = lock_state();
    let runtime = match guard.runtime.take() {
        Some(rt) => rt,
        None => return std::ptr::null_mut(),
    };
    let mut engine = match guard.engine.take() {
        Some(e) => e,
        None => {
            guard.runtime = Some(runtime);
            return std::ptr::null_mut();
        }
    };

    let result = runtime.block_on(engine.key_points(text, language, TaskOptions::default()));
    guard.engine = Some(engine);
    guard.runtime = Some(runtime);
    match result {
        Ok(r) => to_c_string(&r),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Run a summarization task with streaming enabled.
#[no_mangle]
pub unsafe extern "C" fn zkai_summarize_stream(
    text: *const c_char,
    language: *const c_char,
) -> *mut c_char {
    let text = match CStr::from_ptr(text).to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };
    let language = match CStr::from_ptr(language).to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };

    let mut guard = lock_state();
    let runtime = match guard.runtime.take() {
        Some(rt) => rt,
        None => return std::ptr::null_mut(),
    };
    let mut engine = match guard.engine.take() {
        Some(e) => e,
        None => {
            guard.runtime = Some(runtime);
            return std::ptr::null_mut();
        }
    };

    let opts = TaskOptions { stream: true, ..Default::default() };
    let result = runtime.block_on(engine.summarize(text, language, opts));
    guard.engine = Some(engine);
    guard.runtime = Some(runtime);
    match result {
        Ok(r) => to_c_string(&r),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Get the device profile as JSON.
#[no_mangle]
pub unsafe extern "C" fn zkai_device_profile() -> *mut c_char {
    let guard = lock_state();
    match guard.engine.as_ref() {
        Some(engine) => to_c_string(engine.profile()),
        None => std::ptr::null_mut(),
    }
}

/// Run a semantic search task.
#[no_mangle]
pub unsafe extern "C" fn zkai_semantic_search(
    query: *const c_char,
) -> *mut c_char {
    let query = match CStr::from_ptr(query).to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };

    let mut guard = lock_state();
    let runtime = match guard.runtime.take() {
        Some(rt) => rt,
        None => return std::ptr::null_mut(),
    };
    let mut engine = match guard.engine.take() {
        Some(e) => e,
        None => {
            guard.runtime = Some(runtime);
            return std::ptr::null_mut();
        }
    };

    let result = runtime.block_on(engine.semantic_search(query, TaskOptions::default()));
    guard.engine = Some(engine);
    guard.runtime = Some(runtime);
    match result {
        Ok(r) => to_c_string(&r),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Run a document generation task.
///
/// # Safety
/// `topic`, `outline`, and `language` must be valid null-terminated C strings.
/// The returned string must be freed with `zkai_free_string`.
#[no_mangle]
pub unsafe extern "C" fn zkai_generate_doc(
    topic: *const c_char,
    outline: *const c_char,
    language: *const c_char,
) -> *mut c_char {
    let topic = match CStr::from_ptr(topic).to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };
    let outline = match CStr::from_ptr(outline).to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };
    let language = match CStr::from_ptr(language).to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };

    let mut guard = lock_state();
    let runtime = match guard.runtime.take() {
        Some(rt) => rt,
        None => return std::ptr::null_mut(),
    };
    let mut engine = match guard.engine.take() {
        Some(e) => e,
        None => {
            guard.runtime = Some(runtime);
            return std::ptr::null_mut();
        }
    };

    let result = runtime.block_on(engine.generate_doc(topic, outline, language, TaskOptions::default()));
    guard.engine = Some(engine);
    guard.runtime = Some(runtime);
    match result {
        Ok(r) => to_c_string(&r),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Run a slide content generation task.
///
/// # Safety
/// `topic`, `source_content`, and `language` must be valid null-terminated C strings.
/// The returned string must be freed with `zkai_free_string`.
#[no_mangle]
pub unsafe extern "C" fn zkai_generate_slides(
    topic: *const c_char,
    source_content: *const c_char,
    language: *const c_char,
) -> *mut c_char {
    let topic = match CStr::from_ptr(topic).to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };
    let source_content = match CStr::from_ptr(source_content).to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };
    let language = match CStr::from_ptr(language).to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };

    let mut guard = lock_state();
    let runtime = match guard.runtime.take() {
        Some(rt) => rt,
        None => return std::ptr::null_mut(),
    };
    let mut engine = match guard.engine.take() {
        Some(e) => e,
        None => {
            guard.runtime = Some(runtime);
            return std::ptr::null_mut();
        }
    };

    let result = runtime.block_on(engine.generate_slides(topic, source_content, language, TaskOptions::default()));
    guard.engine = Some(engine);
    guard.runtime = Some(runtime);
    match result {
        Ok(r) => to_c_string(&r),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Run an image search task.
///
/// # Safety
/// `query` must be a valid null-terminated C string.
/// The returned string must be freed with `zkai_free_string`.
#[no_mangle]
pub unsafe extern "C" fn zkai_image_search(
    query: *const c_char,
) -> *mut c_char {
    let query = match CStr::from_ptr(query).to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };

    let mut guard = lock_state();
    let runtime = match guard.runtime.take() {
        Some(rt) => rt,
        None => return std::ptr::null_mut(),
    };
    let mut engine = match guard.engine.take() {
        Some(e) => e,
        None => {
            guard.runtime = Some(runtime);
            return std::ptr::null_mut();
        }
    };

    let result = runtime.block_on(engine.image_search(query, TaskOptions::default()));
    guard.engine = Some(engine);
    guard.runtime = Some(runtime);
    match result {
        Ok(r) => to_c_string(&r),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Shutdown the engine.
#[no_mangle]
pub extern "C" fn zkai_shutdown() -> i32 {
    let mut guard = lock_state();
    let rt = guard.runtime.take();
    let engine = guard.engine.take();
    if let (Some(rt), Some(mut engine)) = (rt, engine) {
        let _ = rt.block_on(engine.shutdown());
    }
    guard.engine = None;
    guard.runtime = None;
    0
}

/// Free a string returned by any zkai_* function.
///
/// # Safety
/// `ptr` must be a valid pointer returned by a zkai_* function.
#[no_mangle]
pub unsafe extern "C" fn zkai_free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        let _ = CString::from_raw(ptr);
    }
}

/// Global swarm state for the Go server.
struct SwarmState {
    devices: Vec<DeviceCapability>,
    local: Option<DeviceCapability>,
}

static SWARM_STATE: Mutex<SwarmState> = Mutex::new(SwarmState {
    devices: Vec::new(),
    local: None,
});

/// Initialize the swarm coordinator with the local device's capability.
///
/// # Safety
/// `device_id`, `device_name`, and `tier` must be valid null-terminated C strings.
/// `available_models_json` is a JSON array of model name strings.
#[no_mangle]
pub unsafe extern "C" fn zkai_swarm_init(
    device_id: *const c_char,
    device_name: *const c_char,
    tier: *const c_char,
    available_models_json: *const c_char,
    battery_level: i32,
    is_idle: i32,
) -> i32 {
    let device_id = match CStr::from_ptr(device_id).to_str() {
        Ok(s) => s.to_string(),
        Err(_) => return -1,
    };
    let device_name = match CStr::from_ptr(device_name).to_str() {
        Ok(s) => s.to_string(),
        Err(_) => return -1,
    };
    let tier_str = match CStr::from_ptr(tier).to_str() {
        Ok(s) => s,
        Err(_) => return -1,
    };
    let tier = match tier_str {
        "high_end" => DeviceTier::HighEnd,
        "mid_range" => DeviceTier::MidRange,
        "low_end" => DeviceTier::LowEnd,
        _ => DeviceTier::Throttled,
    };
    let models_json = match CStr::from_ptr(available_models_json).to_str() {
        Ok(s) => s,
        Err(_) => return -1,
    };
    let available_models: Vec<String> = serde_json::from_str(models_json).unwrap_or_default();
    let battery = if battery_level >= 0 { Some(battery_level as u8) } else { None };

    let mut state = SWARM_STATE.lock().unwrap_or_else(|e| e.into_inner());
    state.local = Some(DeviceCapability {
        device_id,
        device_name,
        tier,
        available_models,
        battery_level: battery,
        is_idle: is_idle != 0,
    });
    state.devices.clear();
    0
}

/// Update a remote device's capability in the swarm.
///
/// # Safety
/// All string arguments must be valid null-terminated C strings.
#[no_mangle]
pub unsafe extern "C" fn zkai_swarm_update_device(
    device_id: *const c_char,
    device_name: *const c_char,
    tier: *const c_char,
    available_models_json: *const c_char,
    battery_level: i32,
    is_idle: i32,
) -> i32 {
    let device_id = match CStr::from_ptr(device_id).to_str() {
        Ok(s) => s.to_string(),
        Err(_) => return -1,
    };
    let device_name = match CStr::from_ptr(device_name).to_str() {
        Ok(s) => s.to_string(),
        Err(_) => return -1,
    };
    let tier_str = match CStr::from_ptr(tier).to_str() {
        Ok(s) => s,
        Err(_) => return -1,
    };
    let tier = match tier_str {
        "high_end" => DeviceTier::HighEnd,
        "mid_range" => DeviceTier::MidRange,
        "low_end" => DeviceTier::LowEnd,
        _ => DeviceTier::Throttled,
    };
    let models_json = match CStr::from_ptr(available_models_json).to_str() {
        Ok(s) => s,
        Err(_) => return -1,
    };
    let available_models: Vec<String> = serde_json::from_str(models_json).unwrap_or_default();
    let battery = if battery_level >= 0 { Some(battery_level as u8) } else { None };

    let cap = DeviceCapability {
        device_id,
        device_name,
        tier,
        available_models,
        battery_level: battery,
        is_idle: is_idle != 0,
    };

    let mut state = SWARM_STATE.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(existing) = state.devices.iter_mut().find(|d| d.device_id == cap.device_id) {
        *existing = cap;
    } else {
        state.devices.push(cap);
    }
    0
}

/// Elect the best device for a given model.
/// Returns the device ID as a C string, or null if no suitable device.
///
/// # Safety
/// `required_model` must be a valid null-terminated C string.
/// The returned string must be freed with `zkai_free_string`.
#[no_mangle]
pub unsafe extern "C" fn zkai_swarm_elect(
    required_model: *const c_char,
) -> *mut c_char {
    let required_model = match CStr::from_ptr(required_model).to_str() {
        Ok(s) => s.to_string(),
        Err(_) => return std::ptr::null_mut(),
    };

    let tier_rank = |t: &DeviceTier| match t {
        DeviceTier::HighEnd => 4,
        DeviceTier::MidRange => 3,
        DeviceTier::LowEnd => 2,
        DeviceTier::Throttled => 1,
    };

    let state = SWARM_STATE.lock().unwrap_or_else(|e| e.into_inner());
    let elected = state
        .devices
        .iter()
        .filter(|d| d.available_models.contains(&required_model))
        .filter(|d| d.is_idle)
        .filter(|d| !matches!(d.tier, DeviceTier::Throttled))
        .max_by_key(|d| (tier_rank(&d.tier), d.battery_level.unwrap_or(100)));

    match elected {
        Some(d) => match CString::new(d.device_id.clone()) {
            Ok(s) => CString::into_raw(s),
            Err(_) => std::ptr::null_mut(),
        },
        None => std::ptr::null_mut(),
    }
}

/// Check if the local device should volunteer for a request.
/// Returns 1 if yes, 0 if no.
///
/// # Safety
/// `requester_id` and `required_model` must be valid null-terminated C strings.
#[no_mangle]
pub unsafe extern "C" fn zkai_swarm_should_volunteer(
    requester_id: *const c_char,
    required_model: *const c_char,
) -> i32 {
    let requester_id = match CStr::from_ptr(requester_id).to_str() {
        Ok(s) => s.to_string(),
        Err(_) => return 0,
    };
    let required_model = match CStr::from_ptr(required_model).to_str() {
        Ok(s) => s.to_string(),
        Err(_) => return 0,
    };

    let state = SWARM_STATE.lock().unwrap_or_else(|e| e.into_inner());
    let local = match &state.local {
        Some(l) => l,
        None => return 0,
    };

    if !local.is_idle { return 0; }
    if !local.available_models.contains(&required_model) { return 0; }
    if matches!(local.tier, DeviceTier::Throttled) { return 0; }
    if local.device_id == requester_id { return 0; }
    1
}
