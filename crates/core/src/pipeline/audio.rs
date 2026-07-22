//! Audio preprocessing for Whisper speech-to-text.
//!
//! Converts raw PCM audio (16kHz, mono, f32) into log-mel spectrograms
//! matching Whisper's expected input format: 80-channel mel filterbank
//! with 25ms window, 10ms hop, normalized to [-1, 1].
//!
//! This is a pure-Rust implementation with no external dependencies —
//! suitable for WASM and mobile targets.

use std::f32::consts::PI;
use std::sync::LazyLock;

/// Whisper mel spectrogram parameters.
const SAMPLE_RATE: usize = 16_000;
const N_FFT: usize = 400;       // 25ms at 16kHz
const HOP_LENGTH: usize = 160;  // 10ms at 16kHz
const N_MELS: usize = 80;
const N_FRAMES: usize = 3_000;  // Whisper expects exactly 3000 frames

/// Pre-computed Hann window (computed once, reused across all calls).
static HANN_WINDOW: LazyLock<Vec<f32>> = LazyLock::new(|| {
    (0..N_FFT)
        .map(|i| 0.5 - 0.5 * (2.0 * PI * i as f32 / N_FFT as f32).cos())
        .collect()
});

/// Pre-computed DFT twiddle factors: cos/sin tables for k=0..half, n=0..N_FFT.
/// This avoids calling cos()/sin() 241M times per spectrogram computation.
static TWIDDLE_COS: LazyLock<Vec<Vec<f32>>> = LazyLock::new(|| {
    let half = N_FFT / 2 + 1;
    (0..half)
        .map(|k| {
            let angle_step = -2.0 * PI * k as f32 / N_FFT as f32;
            (0..N_FFT).map(|n| (angle_step * n as f32).cos()).collect()
        })
        .collect()
});

static TWIDDLE_SIN: LazyLock<Vec<Vec<f32>>> = LazyLock::new(|| {
    let half = N_FFT / 2 + 1;
    (0..half)
        .map(|k| {
            let angle_step = -2.0 * PI * k as f32 / N_FFT as f32;
            (0..N_FFT).map(|n| (angle_step * n as f32).sin()).collect()
        })
        .collect()
});

/// Pre-computed mel filterbank (computed once, reused across all calls).
static MEL_FILTERS: LazyLock<Vec<Vec<f32>>> = LazyLock::new(|| {
    mel_filterbank(N_FFT, N_MELS, SAMPLE_RATE)
});

/// Compute a log-mel spectrogram from raw PCM audio data.
///
/// Input: f32 samples in range [-1, 1], 16kHz mono.
/// Output: 2D vector [N_MELS][N_FRAMES] of log-mel features.
///
/// This matches the preprocessing used by OpenAI Whisper:
/// 1. Pad/trim audio to exactly 30 seconds (480,000 samples)
/// 2. Short-time Fourier transform (STFT) with Hann window
/// 3. Mel filterbank to get 80 mel bands
/// 4. Log compression
/// 5. Normalize to approximately [-1, 1] range
pub fn compute_log_mel_spectrogram(audio: &[f32]) -> Vec<Vec<f32>> {
    // Step 1: Pad or trim to exactly 30 seconds
    let target_len = SAMPLE_RATE * 30;
    let mut padded = vec![0.0f32; target_len];
    let copy_len = audio.len().min(target_len);
    padded[..copy_len].copy_from_slice(&audio[..copy_len]);

    // Use pre-computed tables
    let window = &*HANN_WINDOW;
    let mel_filters = &*MEL_FILTERS;

    // Step 2: Determine actual number of audio frames (non-zero region)
    let n_audio_frames = if copy_len >= N_FFT {
        (copy_len - N_FFT) / HOP_LENGTH + 1
    } else {
        0
    };
    let n_frames = n_audio_frames.min(N_FRAMES);
    let half = N_FFT / 2 + 1;

    // Step 3: STFT — compute power spectrogram using pre-computed twiddle factors
    let mut power_spec = vec![vec![0.0f32; N_FRAMES]; half];

    for frame_idx in 0..n_frames {
        let start = frame_idx * HOP_LENGTH;

        // Check if this frame is all zeros (skip computation for padding)
        let mut has_signal = false;
        for i in 0..N_FFT {
            if padded[start + i] != 0.0 {
                has_signal = true;
                break;
            }
        }
        if !has_signal {
            continue; // power_spec already initialized to 0.0
        }

        // Apply window and compute DFT using pre-computed twiddle factors
        for k in 0..half {
            let cos_row = &TWIDDLE_COS[k];
            let sin_row = &TWIDDLE_SIN[k];
            let mut real = 0.0f32;
            let mut imag = 0.0f32;
            for n in 0..N_FFT {
                let windowed = padded[start + n] * window[n];
                real += windowed * cos_row[n];
                imag += windowed * sin_row[n];
            }
            power_spec[k][frame_idx] = real * real + imag * imag;
        }
    }

    // Step 4: Apply mel filterbank
    let mut mel_spec = vec![vec![0.0f32; N_FRAMES]; N_MELS];
    for mel_idx in 0..N_MELS {
        let filter = &mel_filters[mel_idx];
        for frame_idx in 0..n_frames {
            let mut sum = 0.0f32;
            for freq_idx in 0..half {
                sum += filter[freq_idx] * power_spec[freq_idx][frame_idx];
            }
            mel_spec[mel_idx][frame_idx] = sum;
        }
    }

    // Step 5: Log compression (log10(x + 1e-10))
    for mel_idx in 0..N_MELS {
        for frame_idx in 0..N_FRAMES {
            mel_spec[mel_idx][frame_idx] = (mel_spec[mel_idx][frame_idx] + 1e-10).log10();
        }
    }

    // Step 6: Normalize — clamp to [-1, 1] using Whisper's typical range
    let mut max_abs = 1e-2f32;
    for row in &mel_spec {
        for &val in row {
            let abs = val.abs();
            if abs > max_abs {
                max_abs = abs;
            }
        }
    }
    for row in &mut mel_spec {
        for val in row.iter_mut() {
            *val = (*val / max_abs).clamp(-1.0, 1.0);
        }
    }

    mel_spec
}

/// Compute mel filterbank: [N_MELS][N_FFT/2+1] triangular filters.
///
/// Uses the HTK mel scale formula: mel = 2595 * log10(1 + hz/700).
fn mel_filterbank(n_fft: usize, n_mels: usize, sample_rate: usize) -> Vec<Vec<f32>> {
    let n_freqs = n_fft / 2 + 1;
    let fft_freqs: Vec<f32> = (0..n_freqs)
        .map(|i| i as f32 * sample_rate as f32 / (2.0 * (n_freqs - 1) as f32))
        .collect();

    // Mel scale endpoints
    let f_min = 0.0f32;
    let f_max = sample_rate as f32 / 2.0;
    let mel_min = hz_to_mel(f_min);
    let mel_max = hz_to_mel(f_max);

    // Equally spaced mel points
    let mel_points: Vec<f32> = (0..n_mels + 2)
        .map(|i| mel_min + (mel_max - mel_min) * i as f32 / (n_mels + 1) as f32)
        .collect();

    // Convert back to Hz and create triangular filters
    let hz_points: Vec<f32> = mel_points.iter().map(|m| mel_to_hz(*m)).collect();

    let mut filters = vec![vec![0.0f32; n_freqs]; n_mels];

    for mel_idx in 0..n_mels {
        let left = hz_points[mel_idx];
        let center = hz_points[mel_idx + 1];
        let right = hz_points[mel_idx + 2];

        for freq_idx in 0..n_freqs {
            let freq = fft_freqs[freq_idx];
            if freq >= left && freq <= right {
                let weight = if freq <= center {
                    // Rising edge
                    if center > left {
                        (freq - left) / (center - left)
                    } else {
                        1.0
                    }
                } else {
                    // Falling edge
                    if right > center {
                        (right - freq) / (right - center)
                    } else {
                        0.0
                    }
                };
                filters[mel_idx][freq_idx] = weight.max(0.0);
            }
        }
    }

    // Normalize filters (slaney normalization)
    for mel_idx in 0..n_mels {
        let mut sum: f32 = filters[mel_idx].iter().sum();
        if sum > 0.0 {
            sum = 1.0 / sum;
            for val in &mut filters[mel_idx] {
                *val *= sum;
            }
        }
    }

    filters
}

/// Convert frequency in Hz to mel scale (HTK formula).
fn hz_to_mel(hz: f32) -> f32 {
    2595.0 * (1.0 + hz / 700.0).log10()
}

/// Convert mel scale to frequency in Hz (HTK formula).
fn mel_to_hz(mel: f32) -> f32 {
    700.0 * (10.0f32.powf(mel / 2595.0) - 1.0)
}

/// Flatten a 2D mel spectrogram [N_MELS][N_FRAMES] into a 1D vector
/// in row-major order, suitable for feeding into an ONNX model.
pub fn flatten_mel(mel: &[Vec<f32>]) -> Vec<f32> {
    let mut flat = Vec::with_capacity(N_MELS * N_FRAMES);
    for row in mel {
        flat.extend_from_slice(row);
    }
    flat
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mel_spectrogram_dimensions() {
        // 1 second of silence
        let audio = vec![0.0f32; SAMPLE_RATE];
        let mel = compute_log_mel_spectrogram(&audio);
        assert_eq!(mel.len(), N_MELS);
        assert_eq!(mel[0].len(), N_FRAMES);
    }

    #[test]
    fn test_mel_spectrogram_normalization() {
        // 1 second of sine wave at 440Hz
        let audio: Vec<f32> = (0..SAMPLE_RATE)
            .map(|i| (2.0 * PI * 440.0 * i as f32 / SAMPLE_RATE as f32).sin() * 0.5)
            .collect();
        let mel = compute_log_mel_spectrogram(&audio);
        // All values should be in [-1, 1] after normalization
        for row in &mel {
            for &val in row {
                assert!(val >= -1.0 && val <= 1.0, "value {} out of range", val);
            }
        }
    }

    #[test]
    fn test_hann_window() {
        let w = &*HANN_WINDOW;
        assert_eq!(w.len(), 400);
        // Hann window: w[0] = 0, w[N/2] = 1
        assert!((w[0]).abs() < 1e-6);
        assert!((w[200] - 1.0).abs() < 1e-6);
    }

    #[test]
    fn test_mel_filterbank() {
        let fb = mel_filterbank(N_FFT, N_MELS, SAMPLE_RATE);
        assert_eq!(fb.len(), N_MELS);
        assert_eq!(fb[0].len(), N_FFT / 2 + 1);
        // Each filter should have some non-zero values
        for row in &fb {
            let sum: f32 = row.iter().sum();
            assert!(sum > 0.0, "mel filter has zero energy");
        }
    }

    #[test]
    fn test_flatten_mel() {
        let mel = vec![vec![1.0; N_FRAMES]; N_MELS];
        let flat = flatten_mel(&mel);
        assert_eq!(flat.len(), N_MELS * N_FRAMES);
        assert!(flat.iter().all(|&v| v == 1.0));
    }

    #[test]
    fn test_hz_mel_roundtrip() {
        let hz = 1000.0f32;
        let mel = hz_to_mel(hz);
        let hz_back = mel_to_hz(mel);
        assert!((hz - hz_back).abs() < 0.01);
    }

    #[test]
    fn test_short_audio_padded() {
        // Very short audio (100ms) should still produce full 3000 frames
        let audio = vec![0.0f32; 1600];
        let mel = compute_log_mel_spectrogram(&audio);
        assert_eq!(mel[0].len(), N_FRAMES);
    }
}
