//! Device capability detection and tiering.
//!
//! The profiler runs at startup and assigns a [`DeviceTier`] based on
//! available GPU/NPU, memory, and CPU cores. On mobile and desktop it
//! also monitors battery level and thermal state, which can cause
//! re-tiering at runtime (e.g., HighEnd → Throttled when the battery
//! drops below 20%).
//!
//! # Platform detection
//!
//! - **WASM (browser)**: Uses JS-injected values (navigator.gpu,
//!   navigator.hardwareConcurrency, navigator.deviceMemory) passed in
//!   via the wasm binding layer.
//! - **macOS**: sysctl for memory/CPU, Metal device for GPU info,
//!   ProcessInfo for thermal state.
//! - **Windows**: DXGI/DXCore for GPU, GlobalMemoryStatusEx for memory.
//! - **Linux**: /proc/meminfo, lspci, Vulkan physical device.
//! - **iOS**: Metal device, ProcessInfo.thermalState, UIDevice.battery.
//! - **Android**: ActivityManager, BatteryManager, NNAPI enumeration.

use serde::{Deserialize, Serialize};
use crate::Result;

/// Device capability tier. Governs model size, decoding strategy,
/// and resource limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeviceTier {
    /// Dedicated GPU ≥4GB VRAM, Apple M-series, 8GB+ RAM, or NPU ≥10 TOPS.
    /// Full models, beam search (width=4), parallel LoRA + CLIP.
    HighEnd,

    /// Integrated GPU, 4-8GB RAM, or NPU 5-10 TOPS.
    /// Quantized models, greedy decode, sequential LoRA/CLIP.
    MidRange,

    /// CPU-only, <4GB RAM, no NPU.
    /// Smallest quantized models, greedy decode, CLIP optional.
    LowEnd,

    /// Battery <20% or thermal pressure.
    /// Pause non-essential inference, queue tasks.
    Throttled,
}

impl std::fmt::Display for DeviceTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DeviceTier::HighEnd => write!(f, "high_end"),
            DeviceTier::MidRange => write!(f, "mid_range"),
            DeviceTier::LowEnd => write!(f, "low_end"),
            DeviceTier::Throttled => write!(f, "throttled"),
        }
    }
}

/// Available hardware acceleration backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Acceleration {
    /// Apple Metal (macOS / iOS).
    Metal,
    /// Apple CoreML + ANE (macOS / iOS).
    CoreML,
    /// Microsoft DirectML (Windows).
    DirectML,
    /// NVIDIA CUDA (Linux / Windows).
    Cuda,
    /// Khronos Vulkan (Linux / Windows).
    Vulkan,
    /// Android NNAPI (NPU / GPU delegate).
    NNAPI,
    /// WebGPU (browser).
    WebGPU,
    /// CPU with SIMD (WASM SIMD, NEON, AVX).
    CpuSimd,
    /// CPU only, no SIMD.
    Cpu,
}

impl std::fmt::Display for Acceleration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Acceleration::Metal => write!(f, "metal"),
            Acceleration::CoreML => write!(f, "coreml"),
            Acceleration::DirectML => write!(f, "directml"),
            Acceleration::Cuda => write!(f, "cuda"),
            Acceleration::Vulkan => write!(f, "vulkan"),
            Acceleration::NNAPI => write!(f, "nnapi"),
            Acceleration::WebGPU => write!(f, "webgpu"),
            Acceleration::CpuSimd => write!(f, "cpu_simd"),
            Acceleration::Cpu => write!(f, "cpu"),
        }
    }
}

/// Thermal pressure state (mirrors Apple's ProcessInfo.thermalState
/// but used cross-platform).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ThermalState {
    Nominal,
    Fair,
    Serious,
    Critical,
}

impl Default for ThermalState {
    fn default() -> Self {
        ThermalState::Nominal
    }
}

/// Complete device capability profile.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceProfile {
    pub tier: DeviceTier,
    pub acceleration: Acceleration,
    pub total_memory_mb: u32,
    pub available_memory_mb: u32,
    pub cpu_cores: u32,
    pub has_npu: bool,
    pub npu_tops: Option<u32>,
    pub battery_level: Option<u8>,
    pub thermal_state: ThermalState,
    pub platform: String,
    pub arch: String,
}

impl Default for DeviceProfile {
    fn default() -> Self {
        Self {
            tier: DeviceTier::LowEnd,
            acceleration: Acceleration::Cpu,
            total_memory_mb: 0,
            available_memory_mb: 0,
            cpu_cores: 1,
            has_npu: false,
            npu_tops: None,
            battery_level: None,
            thermal_state: ThermalState::Nominal,
            platform: "unknown".to_string(),
            arch: "unknown".to_string(),
        }
    }
}

/// Device profiler that detects capabilities at startup.
pub struct DeviceProfiler;

impl DeviceProfiler {
    /// Detect device capabilities and return a profile.
    ///
    /// On WASM this reads values injected from JavaScript. On native
    /// platforms it queries system APIs directly.
    pub async fn detect() -> Result<DeviceProfile> {
        let mut profile = detect_platform()?;
        profile.tier = compute_tier(&profile);
        Ok(profile)
    }

    /// Create a profile from externally-provided values (used by
    /// the WASM binding layer where JS detects browser capabilities).
    pub fn from_js(
        has_webgpu: bool,
        cpu_cores: u32,
        device_memory_mb: u32,
        battery_level: Option<u8>,
    ) -> DeviceProfile {
        let acceleration = if has_webgpu {
            Acceleration::WebGPU
        } else {
            Acceleration::CpuSimd
        };

        let mut profile = DeviceProfile {
            tier: DeviceTier::LowEnd,
            acceleration,
            total_memory_mb: device_memory_mb,
            available_memory_mb: device_memory_mb,
            cpu_cores,
            has_npu: false,
            npu_tops: None,
            battery_level,
            thermal_state: ThermalState::Nominal,
            platform: "wasm".to_string(),
            arch: "wasm32".to_string(),
        };
        profile.tier = compute_tier(&profile);
        profile
    }

    /// Update battery and thermal state (called periodically by
    /// the platform binding to trigger re-tiering).
    pub fn update_power_state(
        profile: &mut DeviceProfile,
        battery_level: Option<u8>,
        thermal_state: ThermalState,
    ) {
        profile.battery_level = battery_level;
        profile.thermal_state = thermal_state;
        profile.tier = compute_tier(profile);
    }
}

/// Compute the device tier from the profile's hardware signals.
fn compute_tier(profile: &DeviceProfile) -> DeviceTier {
    // Throttled takes priority
    if let Some(level) = profile.battery_level {
        if level < 20 {
            return DeviceTier::Throttled;
        }
    }
    match profile.thermal_state {
        ThermalState::Serious | ThermalState::Critical => return DeviceTier::Throttled,
        _ => {}
    }

    // High-end: dedicated GPU, Apple M-series, 8GB+ RAM, or NPU ≥10 TOPS
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

    // Mid-range: integrated GPU, 4-8GB RAM, or NPU 5-10 TOPS
    let has_mid_npu = profile.npu_tops.unwrap_or(0) >= 5;
    let has_mid_memory = profile.available_memory_mb >= 4096;
    let has_any_gpu = matches!(
        profile.acceleration,
        Acceleration::Metal
            | Acceleration::CoreML
            | Acceleration::DirectML
            | Acceleration::Vulkan
            | Acceleration::NNAPI
            | Acceleration::WebGPU
    );

    if has_any_gpu && has_mid_memory {
        return DeviceTier::MidRange;
    }
    if has_mid_npu {
        return DeviceTier::MidRange;
    }

    // Low-end: everything else
    DeviceTier::LowEnd
}

/// Platform-specific detection.
fn detect_platform() -> Result<DeviceProfile> {
    #[cfg(target_arch = "wasm32")]
    {
        return detect_wasm();
    }

    #[cfg(all(target_os = "macos", not(target_arch = "wasm32")))]
    {
        return detect_macos();
    }

    #[cfg(all(target_os = "linux", not(target_arch = "wasm32")))]
    {
        return detect_linux();
    }

    #[cfg(all(target_os = "windows", not(target_arch = "wasm32")))]
    {
        return detect_windows();
    }

    #[cfg(all(target_os = "ios", not(target_arch = "wasm32")))]
    {
        return detect_ios();
    }

    #[cfg(all(target_os = "android", not(target_arch = "wasm32")))]
    {
        return detect_android();
    }

    #[cfg(not(any(
        target_arch = "wasm32",
        target_os = "macos",
        target_os = "linux",
        target_os = "windows",
        target_os = "ios",
        target_os = "android"
    )))]
    {
        return Ok(DeviceProfile::default());
    }
}

// ─── WASM ──────────────────────────────────────────────────────────

#[cfg(target_arch = "wasm32")]
fn detect_wasm() -> Result<DeviceProfile> {
    // On WASM, the binding layer (crates/wasm) calls DeviceProfiler::from_js
    // with browser-detected values. This default is used when called
    // directly without JS injection.
    Ok(DeviceProfile {
        tier: DeviceTier::LowEnd,
        acceleration: Acceleration::CpuSimd,
        total_memory_mb: 2048,
        available_memory_mb: 1024,
        cpu_cores: 4,
        has_npu: false,
        npu_tops: None,
        battery_level: None,
        thermal_state: ThermalState::Nominal,
        platform: "wasm".to_string(),
        arch: "wasm32".to_string(),
    })
}

// ─── macOS ─────────────────────────────────────────────────────────

#[cfg(all(target_os = "macos", not(target_arch = "wasm32")))]
fn detect_macos() -> Result<DeviceProfile> {
    let total_memory_mb = get_sysctl_u64("hw.memsize")
        .map(|b| (b / (1024 * 1024)) as u32)
        .unwrap_or(8192);

    let cpu_cores = get_sysctl_u64("hw.logicalcpu")
        .map(|c| c as u32)
        .unwrap_or(num_cpus());

    let cpu_brand = get_sysctl_string("machdep.cpu.brand_string")
        .unwrap_or_default();

    // Apple Silicon (M-series) has Metal + ANE; Intel Macs have Metal only.
    let is_apple_silicon = cpu_brand.contains("Apple");
    let acceleration = if is_apple_silicon {
        Acceleration::CoreML
    } else {
        Acceleration::Metal
    };

    let has_npu = is_apple_silicon;

    // Available memory: use ~70% of total as a heuristic (the OS needs the rest).
    let available_memory_mb = (total_memory_mb as f64 * 0.7) as u32;

    Ok(DeviceProfile {
        tier: DeviceTier::LowEnd, // recomputed by compute_tier
        acceleration,
        total_memory_mb,
        available_memory_mb,
        cpu_cores,
        has_npu,
        npu_tops: if has_npu { Some(15) } else { None }, // Apple ANE ~15.8 TOPS
        battery_level: get_macos_battery_level(),
        thermal_state: ThermalState::Nominal, // updated via NSProcessInfo in binding
        platform: "macos".to_string(),
        arch: std::env::consts::ARCH.to_string(),
    })
}

#[cfg(all(target_os = "macos", not(target_arch = "wasm32")))]
fn get_sysctl_u64(key: &str) -> Option<u64> {
    let output = std::process::Command::new("sysctl")
        .args(["-n", key])
        .output()
        .ok()?;
    let s = String::from_utf8_lossy(&output.stdout).trim().to_string();
    s.parse::<u64>().ok()
}

#[cfg(all(target_os = "macos", not(target_arch = "wasm32")))]
fn get_sysctl_string(key: &str) -> Option<String> {
    let output = std::process::Command::new("sysctl")
        .args(["-n", key])
        .output()
        .ok()?;
    Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

#[cfg(all(target_os = "macos", not(target_arch = "wasm32")))]
fn get_macos_battery_level() -> Option<u8> {
    let output = std::process::Command::new("pmset")
        .args(["-g", "batt"])
        .output()
        .ok()?;
    let s = String::from_utf8_lossy(&output.stdout);
    // Parse "InternalBattery-0 (id=xxxx) 42%; discharging;"
    for line in s.lines() {
        if line.contains("Battery") {
            if let Some(pct_str) = line.split('%').next() {
                if let Some(num_part) = pct_str.rsplit(' ').next() {
                    if let Ok(pct) = num_part.trim().parse::<u8>() {
                        return Some(pct);
                    }
                }
            }
        }
    }
    None
}

// ─── Linux ─────────────────────────────────────────────────────────

#[cfg(all(target_os = "linux", not(target_arch = "wasm32")))]
fn detect_linux() -> Result<DeviceProfile> {
    let total_memory_mb = get_linux_memory_mb().unwrap_or(4096);
    let cpu_cores = num_cpus();
    let has_gpu = has_linux_gpu();
    let acceleration = if has_gpu { Acceleration::Vulkan } else { Acceleration::CpuSimd };
    let available_memory_mb = (total_memory_mb as f64 * 0.7) as u32;

    Ok(DeviceProfile {
        tier: DeviceTier::LowEnd,
        acceleration,
        total_memory_mb,
        available_memory_mb,
        cpu_cores,
        has_npu: false,
        npu_tops: None,
        battery_level: get_linux_battery_level(),
        thermal_state: ThermalState::Nominal,
        platform: "linux".to_string(),
        arch: std::env::consts::ARCH.to_string(),
    })
}

#[cfg(all(target_os = "linux", not(target_arch = "wasm32")))]
fn get_linux_memory_mb() -> Option<u32> {
    let content = std::fs::read_to_string("/proc/meminfo").ok()?;
    for line in content.lines() {
        if line.starts_with("MemTotal:") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                if let Ok(kb) = parts[1].parse::<u64>() {
                    return Some((kb / 1024) as u32);
                }
            }
        }
    }
    None
}

#[cfg(all(target_os = "linux", not(target_arch = "wasm32")))]
fn has_linux_gpu() -> bool {
    // Check for DRM/KMS device nodes (present when a GPU driver is loaded)
    std::fs::metadata("/dev/dri").is_ok()
}

#[cfg(all(target_os = "linux", not(target_arch = "wasm32")))]
fn get_linux_battery_level() -> Option<u8> {
    std::fs::read_to_string("/sys/class/power_supply/BAT0/capacity")
        .ok()
        .and_then(|s| s.trim().parse::<u8>().ok())
        .or_else(|| {
            std::fs::read_to_string("/sys/class/power_supply/BAT1/capacity")
                .ok()
                .and_then(|s| s.trim().parse::<u8>().ok())
        })
}

// ─── Windows ───────────────────────────────────────────────────────

#[cfg(all(target_os = "windows", not(target_arch = "wasm32")))]
fn detect_windows() -> Result<DeviceProfile> {
    let cpu_cores = num_cpus();
    let (total_memory_mb, available_memory_mb) = get_windows_memory_mb()
        .unwrap_or((8192, (8192_f64 * 0.7) as u32));

    let mut profile = DeviceProfile {
        tier: DeviceTier::LowEnd,
        acceleration: Acceleration::DirectML,
        total_memory_mb,
        available_memory_mb,
        cpu_cores,
        has_npu: false,
        npu_tops: None,
        battery_level: None,
        thermal_state: ThermalState::Nominal,
        platform: "windows".to_string(),
        arch: std::env::consts::ARCH.to_string(),
    };
    profile.tier = compute_tier(&profile);
    Ok(profile)
}

#[cfg(all(target_os = "windows", not(target_arch = "wasm32")))]
fn get_windows_memory_mb() -> Option<(u32, u32)> {
    use windows_sys::Win32::System::SystemInformation::{
        GlobalMemoryStatusEx, MEMORYSTATUSEX,
    };
    use windows_sys::Win32::Foundation::FALSE;

    let mut mem_status: MEMORYSTATUSEX = unsafe { std::mem::zeroed() };
    mem_status.dwLength = std::mem::size_of::<MEMORYSTATUSEX>() as u32;

    let result = unsafe { GlobalMemoryStatusEx(&mut mem_status) };
    if result == FALSE {
        return None;
    }

    let total_mb = (mem_status.ullTotalPhys / (1024 * 1024)) as u32;
    let avail_mb = (mem_status.ullAvailPhys / (1024 * 1024)) as u32;
    Some((total_mb, avail_mb))
}

// ─── iOS ───────────────────────────────────────────────────────────

#[cfg(all(target_os = "ios", not(target_arch = "wasm32")))]
fn detect_ios() -> Result<DeviceProfile> {
    // iOS detection is done in the UniFFI binding layer (Swift)
    // which calls back with precise values. This default is used
    // when the core is called directly.
    Ok(DeviceProfile {
        tier: DeviceTier::MidRange,
        acceleration: Acceleration::CoreML,
        total_memory_mb: 4096,
        available_memory_mb: 2048,
        cpu_cores: 6,
        has_npu: true,
        npu_tops: Some(11), // A14+ ANE
        battery_level: None,
        thermal_state: ThermalState::Nominal,
        platform: "ios".to_string(),
        arch: "aarch64".to_string(),
    })
}

// ─── Android ───────────────────────────────────────────────────────

#[cfg(all(target_os = "android", not(target_arch = "wasm32")))]
fn detect_android() -> Result<DeviceProfile> {
    // Android detection is done in the UniFFI binding layer (Kotlin)
    // which calls back with precise values. This default is used
    // when the core is called directly.
    Ok(DeviceProfile {
        tier: DeviceTier::MidRange,
        acceleration: Acceleration::NNAPI,
        total_memory_mb: 4096,
        available_memory_mb: 2048,
        cpu_cores: 8,
        has_npu: false,
        npu_tops: None,
        battery_level: None,
        thermal_state: ThermalState::Nominal,
        platform: "android".to_string(),
        arch: "aarch64".to_string(),
    })
}

/// Fallback CPU count detection (avoids the num_cpus crate dependency
/// on WASM where it isn't available).
#[cfg(not(target_arch = "wasm32"))]
fn num_cpus() -> u32 {
    std::thread::available_parallelism()
        .map(|n| n.get() as u32)
        .unwrap_or(4)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_tier_high_end() {
        let profile = DeviceProfile {
            tier: DeviceTier::LowEnd,
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
        };
        assert_eq!(compute_tier(&profile), DeviceTier::HighEnd);
    }

    #[test]
    fn test_compute_tier_throttled_battery() {
        let profile = DeviceProfile {
            tier: DeviceTier::HighEnd,
            acceleration: Acceleration::Metal,
            total_memory_mb: 16384,
            available_memory_mb: 16384,
            cpu_cores: 10,
            has_npu: true,
            npu_tops: Some(15),
            battery_level: Some(15),
            thermal_state: ThermalState::Nominal,
            platform: "ios".to_string(),
            arch: "aarch64".to_string(),
        };
        assert_eq!(compute_tier(&profile), DeviceTier::Throttled);
    }

    #[test]
    fn test_compute_tier_throttled_thermal() {
        let profile = DeviceProfile {
            tier: DeviceTier::HighEnd,
            acceleration: Acceleration::Metal,
            total_memory_mb: 16384,
            available_memory_mb: 16384,
            cpu_cores: 10,
            has_npu: true,
            npu_tops: Some(15),
            battery_level: Some(80),
            thermal_state: ThermalState::Serious,
            platform: "ios".to_string(),
            arch: "aarch64".to_string(),
        };
        assert_eq!(compute_tier(&profile), DeviceTier::Throttled);
    }

    #[test]
    fn test_compute_tier_mid_range() {
        let profile = DeviceProfile {
            tier: DeviceTier::LowEnd,
            acceleration: Acceleration::WebGPU,
            total_memory_mb: 6144,
            available_memory_mb: 4096,
            cpu_cores: 6,
            has_npu: false,
            npu_tops: None,
            battery_level: Some(70),
            thermal_state: ThermalState::Nominal,
            platform: "wasm".to_string(),
            arch: "wasm32".to_string(),
        };
        assert_eq!(compute_tier(&profile), DeviceTier::MidRange);
    }

    #[test]
    fn test_compute_tier_low_end() {
        let profile = DeviceProfile {
            tier: DeviceTier::LowEnd,
            acceleration: Acceleration::Cpu,
            total_memory_mb: 2048,
            available_memory_mb: 1024,
            cpu_cores: 2,
            has_npu: false,
            npu_tops: None,
            battery_level: Some(90),
            thermal_state: ThermalState::Nominal,
            platform: "android".to_string(),
            arch: "aarch64".to_string(),
        };
        assert_eq!(compute_tier(&profile), DeviceTier::LowEnd);
    }

    #[test]
    fn test_from_js_webgpu() {
        let profile = DeviceProfiler::from_js(true, 8, 8192, Some(90));
        assert_eq!(profile.acceleration, Acceleration::WebGPU);
        assert_eq!(profile.cpu_cores, 8);
    }

    #[test]
    fn test_from_js_no_webgpu() {
        let profile = DeviceProfiler::from_js(false, 4, 2048, None);
        assert_eq!(profile.acceleration, Acceleration::CpuSimd);
    }

    #[test]
    fn test_update_power_state_throttles() {
        let mut profile = DeviceProfiler::from_js(true, 8, 8192, Some(90));
        assert_ne!(profile.tier, DeviceTier::Throttled);
        DeviceProfiler::update_power_state(&mut profile, Some(15), ThermalState::Nominal);
        assert_eq!(profile.tier, DeviceTier::Throttled);
    }
}
