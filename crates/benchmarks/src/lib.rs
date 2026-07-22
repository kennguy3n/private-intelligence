//! Shared benchmark utilities for zk-ai benchmarks.

use tempfile::TempDir;
use zk_ai_core::pipeline::SUPPORTED_LANGUAGES;
use zk_ai_core::governor::GovernorConfig;
use zk_ai_core::AiEngine;

/// Create a test engine with fake model files (fallback inference path).
/// Measures pipeline/governor/search overhead without real ONNX models.
pub async fn setup_fallback_engine() -> (TempDir, AiEngine) {
    let cache_dir = tempfile::tempdir().unwrap();
    let models_dir = cache_dir.path().join("models");
    std::fs::create_dir_all(&models_dir).unwrap();
    for filename in &[
        "mt5-small-1.0.0-int8.onnx",
        "multilingual-e5-small-1.0.0-int8.onnx",
        "clip-vit-base-patch32-1.0.0-int8.onnx",
        "whisper-tiny-1.0.0-int8.onnx",
    ] {
        std::fs::write(models_dir.join(filename), b"fake_model").unwrap();
    }
    let adapters_dir = cache_dir.path().join("adapters");
    std::fs::create_dir_all(&adapters_dir).unwrap();
    for lang in SUPPORTED_LANGUAGES {
        for task in &["summarize", "keypoints", "gendoc", "slides"] {
            std::fs::write(
                adapters_dir.join(format!("{}.{}.bin", task, lang)),
                b"fake_adapter",
            ).unwrap();
        }
        for target in SUPPORTED_LANGUAGES {
            if lang != target {
                std::fs::write(
                    adapters_dir.join(format!("translate.{}_{}.bin", lang, target)),
                    b"fake_adapter",
                ).unwrap();
            }
        }
    }
    let mut engine = AiEngine::new(cache_dir.path()).await.unwrap();
    engine.governor_mut().update_config(GovernorConfig {
        max_cpu_percent: 100,
        max_memory_percent: 100,
        ..Default::default()
    });
    (cache_dir, engine)
}

/// Sample multilingual text inputs for benchmarks.
pub fn sample_inputs() -> Vec<(&'static str, &'static str)> {
    vec![
        ("en", "The quarterly board meeting covered revenue growth of 23% year-over-year and the acquisition of TechCorp for $50M."),
        ("vi", "Cuộc họp hội đồng quản trị thảo luận tăng trưởng doanh thu 23% và mua lại TechCorp với giá 50 triệu đô la."),
        ("th", "การประชุมคณะกรรมการหารือการเติบโตของรายได้ 23% และเข้าซื้อกิจการ TechCorp ในราคา 50 ล้านดอลลาร์"),
        ("ar", "اجتماع مجلس الإدارة ناقش نمو الإيرادات بنسبة 23% والاستحواذ على TechCorp مقابل 50 مليون دولار."),
        ("zh", "董事会会议讨论了23%的收入增长和以5000万美元收购TechCorp。"),
        ("es", "La reunión del consejo discutió el crecimiento de ingresos del 23% y la adquisición de TechCorp por 50 millones de dólares."),
    ]
}

/// Deterministic synthetic embedding for search benchmarks.
/// Uses word-level hashing for better semantic similarity than char-based.
pub fn synthetic_embedding(text: &str, dim: usize) -> Vec<f32> {
    let mut embedding = vec![0.0; dim];
    for word in text.split_whitespace() {
        let mut hash: u64 = 5381;
        for &b in word.as_bytes() {
            hash = hash.wrapping_mul(33).wrapping_add(b as u64);
        }
        for i in 0..3 {
            let idx = ((hash.wrapping_add(i * 17)) % dim as u64) as usize;
            embedding[idx] += 1.0;
        }
    }
    let norm: f32 = embedding.iter().map(|v| v * v).sum::<f32>().sqrt();
    if norm > 0.0 {
        for v in &mut embedding { *v /= norm; }
    }
    embedding
}
