//! Minimal deterministic RNG for inference sampling.
//!
//! Uses xorshift64 for reproducibility — no external dependency needed.
//! The default seed is drawn from system entropy for non-deterministic use.

/// A simple xorshift64-based PRNG.
pub struct SimpleRng {
    state: u64,
}

impl SimpleRng {
    /// Create a new RNG seeded from system entropy.
    ///
    /// Uses the `getrandom` crate to obtain 8 bytes of cryptographic
    /// randomness from the OS entropy source (e.g., `/dev/urandom`,
    /// `BCryptGenRandom`, or `crypto.getRandomValues` in WASM).
    /// Falls back to system time if entropy is unavailable.
    pub fn new() -> Self {
        let seed = seed_from_entropy().unwrap_or_else(|| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0xCAFEBABE)
        });
        Self::from_seed(seed)
    }

    /// Create a new RNG with a specific seed.
    pub fn from_seed(seed: u64) -> Self {
        Self {
            state: if seed == 0 { 0xCAFEBABE } else { seed },
        }
    }

    /// Generate the next u64.
    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }

    /// Generate a float in [0, 1).
    pub fn next_f32(&mut self) -> f32 {
        (self.next_u64() >> 40) as f32 / (1u64 << 24) as f32
    }
}

/// Seed from system entropy using the `getrandom` crate.
fn seed_from_entropy() -> Option<u64> {
    let mut buf = [0u8; 8];
    getrandom::getrandom(&mut buf).ok()?;
    let seed = u64::from_le_bytes(buf);
    if seed == 0 {
        // Extremely unlikely, but avoid the degenerate state
        return Some(0xCAFEBABE);
    }
    Some(seed)
}

impl Default for SimpleRng {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rng_deterministic() {
        let mut a = SimpleRng::from_seed(42);
        let mut b = SimpleRng::from_seed(42);
        for _ in 0..10 {
            assert_eq!(a.next_u64(), b.next_u64());
        }
    }

    #[test]
    fn test_rng_range() {
        let mut rng = SimpleRng::from_seed(123);
        for _ in 0..100 {
            let v = rng.next_f32();
            assert!(v >= 0.0 && v < 1.0);
        }
    }

    #[test]
    fn test_rng_nonzero_seed() {
        let mut rng = SimpleRng::from_seed(0);
        let v = rng.next_u64();
        assert_ne!(v, 0);
    }

    #[test]
    fn test_rng_new_seeds_from_entropy() {
        // Two RNGs created in succession should (almost certainly)
        // have different states when seeded from system entropy.
        let a = SimpleRng::new();
        let b = SimpleRng::new();
        // The probability of two 64-bit entropy values colliding is negligible
        assert_ne!(a.state, b.state);
    }

    #[test]
    fn test_seed_from_entropy_returns_some() {
        // On any reasonable platform, getrandom should succeed
        let seed = seed_from_entropy();
        assert!(seed.is_some());
        assert_ne!(seed.unwrap(), 0);
    }
}
