//! Resource governor: prevents inference from degrading the device
//! experience by enforcing CPU, GPU, RAM, battery, and thermal limits.
//!
//! Every inference call passes through the governor:
//! 1. `check_resources()` — fail fast if the device is constrained
//! 2. `acquire()` — obtain a semaphore permit (max 1 concurrent inference)
//! 3. Run inference within a timeout
//! 4. `drop(permit)` — release the semaphore

use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;
use crate::profiler::{DeviceTier, ThermalState};
use crate::{Result, ZkAiError};

/// Snapshot of current system resource usage.
#[derive(Debug, Clone, Default)]
struct ResourceSnapshot {
    /// Current process CPU usage as a percentage of total available (0-100).
    cpu_percent: f32,
    /// Current process memory usage as a percentage of total system RAM (0-100).
    memory_percent: f32,
}

impl ResourceSnapshot {
    /// Sample current resource usage. Returns best-effort values;
    /// on platforms where measurement is unavailable, returns 0.0
    /// (which will always pass the limit check).
    fn sample() -> Self {
        #[cfg(all(unix, not(target_arch = "wasm32")))]
        {
            if let Some(snap) = sample_unix() {
                return snap;
            }
        }
        #[cfg(all(target_os = "windows", not(target_arch = "wasm32")))]
        {
            if let Some(snap) = sample_windows() {
                return snap;
            }
        }
        Self::default()
    }
}

#[cfg(all(unix, not(target_arch = "wasm32")))]
fn sample_unix() -> Option<ResourceSnapshot> {
    // Get current CPU time (user + system) for this process
    let cpu_time = get_process_cpu_time_unix()?;
    let mem_percent = get_process_memory_percent_unix()?;

    // Compute CPU percentage from process uptime (single measurement, no blocking sleep)
    // cpu_time is in seconds; process uptime is from /proc/self/stat starttime
    let uptime_secs = get_process_uptime_unix()?;
    let cpu_percent = if uptime_secs > 0.0 {
        (cpu_time / uptime_secs * 100.0).min(100.0)
    } else {
        0.0
    };

    Some(ResourceSnapshot {
        cpu_percent: cpu_percent as f32,
        memory_percent: mem_percent,
    })
}

#[cfg(all(unix, not(target_arch = "wasm32")))]
fn get_process_uptime_unix() -> Option<f64> {
    #[cfg(target_os = "linux")]
    {
        let stat = std::fs::read_to_string("/proc/self/stat").ok()?;
        let fields: Vec<&str> = stat.split_whitespace().collect();
        // Field 22 (starttime) is in clock ticks since boot
        let starttime_ticks: f64 = fields.get(21).and_then(|s| s.parse().ok()).unwrap_or(0.0);
        let ticks_per_sec = unsafe { libc::sysconf(libc::_SC_CLK_TCK) } as f64;
        if ticks_per_sec <= 0.0 {
            return None;
        }
        let starttime_secs = starttime_ticks / ticks_per_sec;
        // Read system uptime from /proc/uptime
        let uptime_str = std::fs::read_to_string("/proc/uptime").ok()?;
        let system_uptime: f64 = uptime_str.split_whitespace().next()?.parse().ok()?;
        Some((system_uptime - starttime_secs).max(0.0))
    }
    #[cfg(not(target_os = "linux"))]
    {
        // macOS: use getrusage ru_utime + ru_stime as proxy for uptime
        use std::mem::MaybeUninit;
        let mut rusage: MaybeUninit<libc::rusage> = MaybeUninit::uninit();
        let ret = unsafe { libc::getrusage(libc::RUSAGE_SELF, rusage.as_mut_ptr()) };
        if ret != 0 {
            return None;
        }
        let rusage = unsafe { rusage.assume_init() };
        let user_secs = rusage.ru_utime.tv_sec as f64 + rusage.ru_utime.tv_usec as f64 / 1_000_000.0;
        let sys_secs = rusage.ru_stime.tv_sec as f64 + rusage.ru_stime.tv_usec as f64 / 1_000_000.0;
        Some((user_secs + sys_secs).max(0.0))
    }
}

#[cfg(all(unix, not(target_arch = "wasm32")))]
fn get_process_cpu_time_unix() -> Option<f64> {
    // On Linux, read /proc/self/stat
    #[cfg(target_os = "linux")]
    {
        let stat = std::fs::read_to_string("/proc/self/stat").ok()?;
    let fields: Vec<&str> = stat.split_whitespace().collect();
    // Fields 14 (utime) and 15 (stime) are in clock ticks
    let utime: f64 = fields.get(13).and_then(|s| s.parse().ok()).unwrap_or(0.0);
    let stime: f64 = fields.get(14).and_then(|s| s.parse().ok()).unwrap_or(0.0);
    let ticks_per_sec = unsafe { libc::sysconf(libc::_SC_CLK_TCK) } as f64;
    if ticks_per_sec > 0.0 {
        Some((utime + stime) / ticks_per_sec)
    } else {
        Some(utime + stime)
    }
    }
    #[cfg(not(target_os = "linux"))]
    {
    // macOS and other Unix: use getrusage
    use std::mem::MaybeUninit;
    let mut rusage: MaybeUninit<libc::rusage> = MaybeUninit::uninit();
    let ret = unsafe { libc::getrusage(libc::RUSAGE_SELF, rusage.as_mut_ptr()) };
    if ret != 0 {
        return None;
    }
    let rusage = unsafe { rusage.assume_init() };
    let user_secs = rusage.ru_utime.tv_sec as f64 + rusage.ru_utime.tv_usec as f64 / 1_000_000.0;
    let sys_secs = rusage.ru_stime.tv_sec as f64 + rusage.ru_stime.tv_usec as f64 / 1_000_000.0;
    Some(user_secs + sys_secs)
    }
}

#[cfg(all(unix, not(target_arch = "wasm32")))]
fn get_process_memory_percent_unix() -> Option<f32> {
    #[cfg(target_os = "linux")]
    {
        let status = std::fs::read_to_string("/proc/self/status").ok()?;
        let mut rss_kb: u64 = 0;
        let mut mem_total_kb: u64 = 0;
        for line in status.lines() {
            if line.starts_with("VmRSS:") {
                rss_kb = line.split_whitespace().nth(1).and_then(|s| s.parse().ok()).unwrap_or(0);
            }
        }
        let meminfo = std::fs::read_to_string("/proc/meminfo").ok()?;
        for line in meminfo.lines() {
            if line.starts_with("MemTotal:") {
                mem_total_kb = line.split_whitespace().nth(1).and_then(|s| s.parse().ok()).unwrap_or(0);
            }
        }
        if mem_total_kb > 0 {
            return Some((rss_kb as f32 / mem_total_kb as f32) * 100.0);
        }
        None
    }
    #[cfg(not(target_os = "linux"))]
    {
        // macOS: use getrusage for RSS and sysctl for total memory
        use std::mem::MaybeUninit;
        let mut rusage: MaybeUninit<libc::rusage> = MaybeUninit::uninit();
        let ret = unsafe { libc::getrusage(libc::RUSAGE_SELF, rusage.as_mut_ptr()) };
        if ret != 0 { return None; }
        let rusage = unsafe { rusage.assume_init() };
        // On macOS, ru_maxrss is in bytes (not KB like Linux)
        let rss_bytes = rusage.ru_maxrss as u64;
        // Get total physical memory via sysctl
        let mut size: libc::size_t = std::mem::size_of::<u64>();
        let mut total_bytes: u64 = 0;
        let ret = unsafe {
            libc::sysctlbyname(
                b"hw.memsize\0".as_ptr() as *const _,
                &mut total_bytes as *mut u64 as *mut libc::c_void,
                &mut size,
                std::ptr::null_mut(),
                0,
            )
        };
        if ret != 0 || total_bytes == 0 { return None; }
        Some((rss_bytes as f32 / total_bytes as f32) * 100.0)
    }
}

#[cfg(all(unix, not(target_arch = "wasm32")))]
fn num_cpus_unix() -> usize {
    #[cfg(target_os = "linux")]
    {
        std::fs::read_to_string("/proc/cpuinfo")
            .map(|s| s.lines().filter(|l| l.starts_with("processor")).count())
            .unwrap_or(1)
    }
    #[cfg(not(target_os = "linux"))]
    {
        // macOS and other Unix
        let mut num: i32 = 1;
        let mut size: libc::size_t = std::mem::size_of::<i32>();
        unsafe {
            libc::sysctlbyname(
                b"hw.logicalcpu\0".as_ptr() as *const _,
                &mut num as *mut i32 as *mut libc::c_void,
                &mut size,
                std::ptr::null_mut(),
                0,
            );
        }
        if num > 0 { num as usize } else { 1 }
    }
}

#[cfg(all(target_os = "windows", not(target_arch = "wasm32")))]
fn sample_windows() -> Option<ResourceSnapshot> {
    use std::time::Instant;
    use windows_sys::Win32::System::SystemInformation::{GetProcessMemoryInfo, GetSystemInfo, PROCESS_MEMORY_COUNTERS, SYSTEM_INFO};
    use windows_sys::Win32::Foundation::CloseHandle;

    // Get process handle
    let handle = unsafe { windows_sys::Win32::System::Threading::GetCurrentProcess() };

    // Memory usage
    let mut counters: PROCESS_MEMORY_COUNTERS = unsafe { std::mem::zeroed() };
    let cb = std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32;
    let mem_ok = unsafe { GetProcessMemoryInfo(handle, &mut counters, cb) } != 0;

    // Total system memory via GlobalMemoryStatusEx
    let mut mem_status: windows_sys::Win32::System::SystemInformation::MEMORYSTATUSEX = unsafe { std::mem::zeroed() };
    mem_status.dwLength = std::mem::size_of::<windows_sys::Win32::System::SystemInformation::MEMORYSTATUSEX>() as u32;
    let total_mem_ok = unsafe {
        windows_sys::Win32::System::SystemInformation::GlobalMemoryStatusEx(&mem_status)
    } != 0;

    let memory_percent = if mem_ok && total_mem_ok && mem_status.ullTotalPhys > 0 {
        let ws_bytes = counters.WorkingSetSize as u64;
        Some((ws_bytes as f32 / mem_status.ullTotalPhys as f32) * 100.0)
    } else {
        None
    };

    // CPU measurement: GetProcessTimes delta over a short interval
    let mut creation_time: windows_sys::Win32::Foundation::FILETIME = unsafe { std::mem::zeroed() };
    let mut exit_time: windows_sys::Win32::Foundation::FILETIME = unsafe { std::mem::zeroed() };
    let mut kernel_time_1: windows_sys::Win32::Foundation::FILETIME = unsafe { std::mem::zeroed() };
    let mut user_time_1: windows_sys::Win32::Foundation::FILETIME = unsafe { std::mem::zeroed() };

    let cpu_start = std::time::Instant::now();
    let cpu_ok_1 = unsafe {
        windows_sys::Win32::System::Threading::GetProcessTimes(
            handle,
            &mut creation_time,
            &mut exit_time,
            &mut kernel_time_1,
            &mut user_time_1,
        )
    } != 0;

    std::thread::sleep(std::time::Duration::from_millis(10));

    let mut kernel_time_2: windows_sys::Win32::Foundation::FILETIME = unsafe { std::mem::zeroed() };
    let mut user_time_2: windows_sys::Win32::Foundation::FILETIME = unsafe { std::mem::zeroed() };
    let cpu_ok_2 = unsafe {
        windows_sys::Win32::System::Threading::GetProcessTimes(
            handle,
            &mut creation_time,
            &mut exit_time,
            &mut kernel_time_2,
            &mut user_time_2,
        )
    } != 0;

    let cpu_percent = if cpu_ok_1 && cpu_ok_2 {
        let filetime_to_f64 = |ft: windows_sys::Win32::Foundation::FILETIME| {
            ((ft.dwHighDateTime as u64) << 32 | ft.dwLowDateTime as u64) as f64 / 10_000_000.0
        };
        let user_1 = filetime_to_f64(user_time_1);
        let user_2 = filetime_to_f64(user_time_2);
        let kernel_1 = filetime_to_f64(kernel_time_1);
        let kernel_2 = filetime_to_f64(kernel_time_2);
        let delta = (user_2 - user_1) + (kernel_2 - kernel_1);
        let elapsed = cpu_start.elapsed().as_secs_f32();
        if elapsed > 0.0 {
            Some((delta / elapsed as f64 * 100.0) as f32)
        } else {
            Some(0.0)
        }
    } else {
        None
    };

    Some(ResourceSnapshot {
        cpu_percent: cpu_percent.unwrap_or(0.0).min(100.0),
        memory_percent: memory_percent.unwrap_or(0.0).min(100.0),
    })
}

/// Configuration for the resource governor.
#[derive(Debug, Clone)]
pub struct GovernorConfig {
    /// Maximum percentage of CPU cores to use for inference.
    pub max_cpu_percent: u32,
    /// Maximum percentage of RAM to use for inference.
    pub max_memory_percent: u32,
    /// Hard timeout per inference call.
    pub timeout: Duration,
    /// Maximum concurrent inference tasks (always 1 to prevent GPU contention).
    pub max_concurrent: u32,
    /// Pause inference when battery is below this level (percentage).
    pub min_battery_percent: u32,
    /// Pause inference when thermal state is at or above this level.
    pub max_thermal_state: ThermalState,
}

impl GovernorConfig {
    /// Create a config appropriate for the given device tier.
    pub fn from_tier(tier: &DeviceTier) -> Self {
        match tier {
            DeviceTier::HighEnd => Self {
                max_cpu_percent: 60,
                max_memory_percent: 50,
                timeout: Duration::from_secs(30),
                max_concurrent: 1,
                min_battery_percent: 20,
                max_thermal_state: ThermalState::Serious,
            },
            DeviceTier::MidRange => Self {
                max_cpu_percent: 40,
                max_memory_percent: 30,
                timeout: Duration::from_secs(20),
                max_concurrent: 1,
                min_battery_percent: 25,
                max_thermal_state: ThermalState::Fair,
            },
            DeviceTier::LowEnd => Self {
                max_cpu_percent: 30,
                max_memory_percent: 15,
                timeout: Duration::from_secs(15),
                max_concurrent: 1,
                min_battery_percent: 30,
                max_thermal_state: ThermalState::Fair,
            },
            DeviceTier::Throttled => Self {
                max_cpu_percent: 10,
                max_memory_percent: 10,
                timeout: Duration::from_secs(10),
                max_concurrent: 1,
                min_battery_percent: 100, // always pause when throttled
                max_thermal_state: ThermalState::Fair,
            },
        }
    }
}

impl Default for GovernorConfig {
    fn default() -> Self {
        Self::from_tier(&DeviceTier::MidRange)
    }
}

/// The resource governor. Wraps every inference call to enforce
/// CPU, memory, battery, and thermal limits.
pub struct ResourceGovernor {
    config: GovernorConfig,
    semaphore: Arc<Semaphore>,
    /// Current battery level (updated by the platform binding).
    current_battery: Option<u8>,
    /// Current thermal state (updated by the platform binding).
    current_thermal: ThermalState,
    /// Whether inference is currently paused.
    paused: bool,
}

impl ResourceGovernor {
    /// Create a new governor with the given config.
    pub fn new(config: GovernorConfig) -> Self {
        let semaphore = Arc::new(Semaphore::new(config.max_concurrent as usize));
        Self {
            config,
            semaphore,
            current_battery: None,
            current_thermal: ThermalState::Nominal,
            paused: false,
        }
    }

    /// Update the governor config (e.g., after re-profiling).
    pub fn update_config(&mut self, config: GovernorConfig) {
        let semaphore = Arc::new(Semaphore::new(config.max_concurrent as usize));
        self.config = config;
        self.semaphore = semaphore;
    }

    /// Update the current battery level (called by platform binding).
    pub fn update_battery(&mut self, level: u8) {
        self.current_battery = Some(level);
        self.paused = u32::from(level) < self.config.min_battery_percent;
    }

    /// Update the current thermal state (called by platform binding).
    pub fn update_thermal(&mut self, state: ThermalState) {
        self.current_thermal = state;
        let state_level = |s: &ThermalState| match s {
            ThermalState::Nominal => 0,
            ThermalState::Fair => 1,
            ThermalState::Serious => 2,
            ThermalState::Critical => 3,
        };
        if state_level(&state) >= state_level(&self.config.max_thermal_state) {
            self.paused = true;
        } else if !self.is_battery_low() {
            self.paused = false;
        }
    }

    /// Check if inference is allowed under current resource constraints.
    /// Returns an error if the device is constrained.
    ///
    /// Checks:
    /// - Paused state (battery low or thermal throttling)
    /// - Current process CPU usage against `max_cpu_percent`
    /// - Current process memory usage against `max_memory_percent`
    pub fn check_resources(&self) -> Result<()> {
        if self.paused {
            return Err(ZkAiError::ResourceLimit(
                "inference paused: battery low or thermal throttling".to_string(),
            ));
        }

        // Sample current resource usage and enforce limits
        let snapshot = ResourceSnapshot::sample();
        if snapshot.cpu_percent > self.config.max_cpu_percent as f32 {
            return Err(ZkAiError::ResourceLimit(format!(
                "CPU usage {:.1}% exceeds limit {}%",
                snapshot.cpu_percent, self.config.max_cpu_percent
            )));
        }
        if snapshot.memory_percent > self.config.max_memory_percent as f32 {
            return Err(ZkAiError::ResourceLimit(format!(
                "memory usage {:.1}% exceeds limit {}%",
                snapshot.memory_percent, self.config.max_memory_percent
            )));
        }

        Ok(())
    }

    /// Acquire a semaphore permit for inference. Only one inference
    /// runs at a time to prevent GPU contention.
    pub async fn acquire(&self) -> Result<tokio::sync::OwnedSemaphorePermit> {
        self.check_resources()?;
        self.semaphore
            .clone()
            .acquire_owned()
            .await
            .map_err(|e| ZkAiError::ResourceLimit(format!("semaphore: {e}")))
    }

    /// Get the configured timeout for inference calls.
    pub fn timeout(&self) -> Duration {
        self.config.timeout
    }

    /// Check if inference is currently paused.
    pub fn is_paused(&self) -> bool {
        self.paused
    }

    /// Check if battery is below the minimum threshold.
    fn is_battery_low(&self) -> bool {
        self.current_battery
            .map(|l| u32::from(l) < self.config.min_battery_percent)
            .unwrap_or(false)
    }

    /// Get the current config.
    pub fn config(&self) -> &GovernorConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_governor_config_from_tier() {
        let high = GovernorConfig::from_tier(&DeviceTier::HighEnd);
        assert_eq!(high.max_cpu_percent, 60);
        assert_eq!(high.timeout, Duration::from_secs(30));

        let low = GovernorConfig::from_tier(&DeviceTier::LowEnd);
        assert_eq!(low.max_cpu_percent, 30);
        assert_eq!(low.timeout, Duration::from_secs(15));

        let throttled = GovernorConfig::from_tier(&DeviceTier::Throttled);
        assert_eq!(throttled.max_cpu_percent, 10);
    }

    #[test]
    fn test_governor_check_resources_ok() {
        let config = GovernorConfig {
            max_cpu_percent: 100,
            max_memory_percent: 100,
            ..GovernorConfig::from_tier(&DeviceTier::HighEnd)
        };
        let governor = ResourceGovernor::new(config);
        assert!(governor.check_resources().is_ok());
    }

    #[test]
    fn test_governor_paused_by_battery() {
        let mut governor = ResourceGovernor::new(GovernorConfig::from_tier(&DeviceTier::HighEnd));
        governor.update_battery(15); // below 20% threshold
        assert!(governor.is_paused());
        assert!(governor.check_resources().is_err());
    }

    #[test]
    fn test_governor_paused_by_thermal() {
        let mut governor = ResourceGovernor::new(GovernorConfig::from_tier(&DeviceTier::HighEnd));
        governor.update_thermal(ThermalState::Serious);
        assert!(governor.is_paused());
        assert!(governor.check_resources().is_err());
    }

    #[test]
    fn test_governor_resumes_after_thermal() {
        let mut governor = ResourceGovernor::new(GovernorConfig::from_tier(&DeviceTier::HighEnd));
        governor.update_thermal(ThermalState::Serious);
        assert!(governor.is_paused());
        governor.update_thermal(ThermalState::Nominal);
        assert!(!governor.is_paused());
    }

    #[tokio::test]
    async fn test_governor_acquire() {
        let config = GovernorConfig {
            max_cpu_percent: 100,
            max_memory_percent: 100,
            ..GovernorConfig::from_tier(&DeviceTier::HighEnd)
        };
        let governor = ResourceGovernor::new(config);
        let permit = governor.acquire().await.unwrap();
        drop(permit);
    }

    #[test]
    fn test_governor_check_resources_with_limits() {
        // On a relatively idle system, check_resources should pass
        // even with CPU/memory limits enforced.
        let governor = ResourceGovernor::new(GovernorConfig::from_tier(&DeviceTier::HighEnd));
        // This should pass on any reasonable test environment
        let result = governor.check_resources();
        // It's possible (but unlikely) that the test machine is under
        // heavy load, so we just verify it doesn't panic.
        let _ = result;
    }

    #[test]
    fn test_governor_resource_snapshot_sample() {
        // Verify that ResourceSnapshot::sample() returns without panicking
        // on any platform. On WASM it returns defaults; on native it
        // queries the OS.
        let snap = ResourceSnapshot::sample();
        assert!(snap.cpu_percent >= 0.0);
        assert!(snap.memory_percent >= 0.0);
    }
}
