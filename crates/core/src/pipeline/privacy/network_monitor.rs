//! Network monitor for tracking outbound connections during inference.
//!
//! Used to prove data residency (all inference was local, no network calls).

use std::sync::atomic::{AtomicU32, AtomicBool, Ordering};

/// Tracks outbound network connections during inference sessions.
pub struct NetworkMonitor {
    /// Total outbound connections observed.
    connection_count: AtomicU32,
    /// Whether monitoring is active.
    active: AtomicBool,
}

impl NetworkMonitor {
    /// Create a new network monitor.
    pub fn new() -> Self {
        Self {
            connection_count: AtomicU32::new(0),
            active: AtomicBool::new(false),
        }
    }

    /// Start monitoring.
    pub fn start(&self) {
        self.active.store(true, Ordering::SeqCst);
        self.connection_count.store(0, Ordering::SeqCst);
    }

    /// Stop monitoring and return the connection count.
    pub fn stop(&self) -> u32 {
        self.active.store(false, Ordering::SeqCst);
        self.connection_count.load(Ordering::SeqCst)
    }

    /// Record an outbound connection (called by the transport layer).
    pub fn record_connection(&self) {
        if self.active.load(Ordering::SeqCst) {
            self.connection_count.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// Whether any connections were observed during the last monitoring period.
    pub fn had_connections(&self) -> bool {
        self.connection_count.load(Ordering::SeqCst) > 0
    }
}

impl Default for NetworkMonitor {
    fn default() -> Self {
        Self::new()
    }
}
