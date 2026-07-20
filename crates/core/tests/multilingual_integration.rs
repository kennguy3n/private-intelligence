//! Comprehensive multilingual + mixed-language integration tests.
//!
//! These tests exercise the full pipeline stack:
//! - All 6 supported languages (en, vi, th, ar, zh, es) across all text tasks
//! - Cross-language translation pairs
//! - Semantic search with multilingual text index
//! - Image search with CLIP-style embeddings
//! - Swarm coordinator with multilingual device election
//! - Governor resource enforcement under realistic conditions
//! - Pipeline prompt construction with native language instructions
//! - Streaming inference across languages
//! - End-to-end workflow: summarize → translate → key_points → generate_doc → generate_slides

use zk_ai_core::*;
use zk_ai_core::pipeline::{
    Task, TaskOptions, TaskResult,
    SUPPORTED_LANGUAGES, validate_language, build_prompt,
};
use zk_ai_core::pipeline::text_index::{TextIndex, TextEntry, TextSearchHit};
use zk_ai_core::pipeline::image_index::{ImageIndex, ImageEntry, ImageSearchHit, cosine_similarity};
use zk_ai_core::swarm::*;
use zk_ai_core::profiler::*;
use zk_ai_core::governor::*;
use zk_ai_core::inference::*;
use zk_ai_core::model_manager::*;

use std::path::PathBuf;
use std::sync::Arc;

// ─── Test Helpers ──────────────────────────────────────────────────

/// Multilingual test corpus — realistic content in each supported language.
struct MultilingualCorpus;

impl MultilingualCorpus {
    fn summarize_inputs() -> Vec<(&'static str, &'static str)> {
        vec![
            ("en", "The quarterly report shows a 15% increase in revenue driven by strong performance in the cloud services division. Customer retention reached 92% and new enterprise contracts totaled 47. The engineering team shipped 12 major features including the real-time collaboration suite and advanced analytics dashboard."),
            ("vi", "Báo cáo quý cho thấy doanh thu tăng 15% nhờ hiệu suất mạnh của bộ phận dịch vụ đám mây. Tỷ lệ giữ chân khách hàng đạt 92% và hợp đồng doanh nghiệp mới tổng cộng 47. Đội kỹ thuật đã phát hành 12 tính năng lớn bao gồm bộ công cụ cộng tác thời gian thực và bảng điều khiển phân tích nâng cao."),
            ("th", "รายงานไตรมาสแสดงรายได้เพิ่มขึ้น 15% จากผลการดำเนินงานที่แข็งแกร่งในส่วนบริการคลาวด์ อัตราการรักษาลูกค้าอยู่ที่ 92% และสัญญาองค์กรใหม่รวม 47 ฉบบ ทีมวิศวกรรมส่งมอบฟีเจอร์หลัก 12 รายการรวมถึงชุดการทำงานร่วมกันแบบเรียลไทม์และแดชบอร์ดวิเคราะห์ขั้นสูง"),
            ("ar", "يظهر التقرير الفصلي زيادة في الإيرادات بنسبة 15% مدفوعة بأداء قوي في قسم خدمات السحابة. وصل معدل الاحتفاظ بالعملاء إلى 92% وبلغت عقود المؤسسات الجديدة 47 عقدًا. شحن فريق الهندسة 12 ميزة رئيسية بما في ذلك مجموعة التعاون في الوقت الفعلي ولوحة التحليلات المتقدمة."),
            ("zh", "季度报告显示收入增长15%，主要受云服务部门强劲表现的推动。客户留存率达到92%，新企业合同总计47份。工程团队发布了12项主要功能，包括实时协作套件和高级分析仪表板。"),
            ("es", "El informe trimestral muestra un aumento del 15% en los ingresos impulsado por el fuerte desempeño de la división de servicios en la nube. La retención de clientes alcanzó el 92% y los nuevos contratos empresariales totalizaron 47. El equipo de ingeniería lanzó 12 funciones principales, incluida la suite de colaboración en tiempo real y el panel de análisis avanzado."),
        ]
    }

    fn key_points_inputs() -> Vec<(&'static str, &'static str)> {
        vec![
            ("en", "The meeting covered three main topics: budget allocation for Q4, hiring plans for the engineering team, and the upcoming product launch timeline. The budget was approved at $2.5M with 60% allocated to engineering. We plan to hire 8 engineers and 3 designers. The product launch is scheduled for March 15th with a beta release on February 1st."),
            ("vi", "Cuộc họp bao gồm ba chủ đề chính: phân bổ ngân sách cho quý 4, kế hoạch tuyển dụng cho đội kỹ thuật và tiến độ ra mắt sản phẩm sắp tới. Ngân sách được phê duyệt ở mức 2,5 triệu đô la với 60% dành cho kỹ thuật. Chúng tôi dự kiến tuyển dụng 8 kỹ sư và 3 nhà thiết kế. Ra mắt sản phẩm dự kiến vào ngày 15 tháng 3 với bản beta vào ngày 1 tháng 2."),
            ("th", "การประชุมครอบคลุมหัวข้อหลักสามประเด็น: การจัดสรรงบประมาณสำหรับไตรมาส 4 แผนการจ้างงานทีมวิศวกรรม และกำหนดการเปิดตัวผลิตภัณฑ์ที่กำลังจะมาถึง งบประมาณได้รับอนุมัติที่ 2.5 ล้านดอลลาร์โดยจัดสรร 60% ให้วิศวกรรม เราวางแผนที่จะจ้างวิศวกร 8 คนและนักออกแบบ 3 คน การเปิดตัวผลิตภัณฑ์มีกำหนดไว้ที่ 15 มีนาคม"),
            ("ar", "غطى الاجتماع ثلاثة مواضيع رئيسية: تخصيص الميزانية للربع الرابع، وخطط التوظيف لفريق الهندسة، والجدول الزمني لإطلاق المنتج القادم. تمت الموافقة على الميزانية بمبلغ 2.5 مليون دولار مع تخصيص 60% للهندسة. نخطط لتوظيف 8 مهندسين و3 مصممين. إطلاق المنتج مجدول في 15 مارس مع إصدار تجريبي في 1 فبراير."),
            ("zh", "会议涵盖了三个主要议题：第四季度预算分配、工程团队招聘计划以及即将推出的产品发布时间表。预算批准为250万美元，其中60%分配给工程部门。我们计划招聘8名工程师和3名设计师。产品发布定于3月15日，2月1日发布测试版。"),
            ("es", "La reunión cubrió tres temas principales: asignación de presupuesto para el cuarto trimestre, planes de contratación para el equipo de ingeniería y el cronograma de lanzamiento del próximo producto. El presupuesto fue aprobado en $2.5M con 60% asignado a ingeniería. Planificamos contratar 8 ingenieros y 3 diseñadores. El lanzamiento del producto está programado para el 15 de marzo."),
        ]
    }

    fn generate_doc_inputs() -> Vec<(&'static str, &'static str, &'static str)> {
        vec![
            ("en", "Cloud Migration Strategy", "1. Current infrastructure assessment\n2. Migration phases\n3. Risk mitigation\n4. Cost analysis\n5. Timeline"),
            ("vi", "Chiến lược chuyển đổi đám mây", "1. Đánh giá hạ tầng hiện tại\n2. Các giai đoạn chuyển đổi\n3. Giảm thiểu rủi ro\n4. Phân tích chi phí\n5. Tiến độ"),
            ("th", "กลยุทธ์การย้ายระบบคลาวด์", "1. ประเมินโครงสร้างพื้นฐานปัจจุบัน\n2. ขั้นตอนการย้ายระบบ\n3. การลดความเสี่ยง\n4. การวิเคราะห์ต้นทุน\n5. กำหนดการ"),
            ("ar", "استراتيجية الترحيل السحابي", "1. تقييم البنية التحتية الحالية\n2. مراحل الترحيل\n3. التخفيف من المخاطر\n4. تحليل التكاليف\n5. الجدول الزمني"),
            ("zh", "云迁移策略", "1. 当前基础设施评估\n2. 迁移阶段\n3. 风险缓解\n4. 成本分析\n5. 时间表"),
            ("es", "Estrategia de Migración a la Nube", "1. Evaluación de infraestructura actual\n2. Fases de migración\n3. Mitigación de riesgos\n4. Análisis de costos\n5. Cronograma"),
        ]
    }

    fn generate_slides_inputs() -> Vec<(&'static str, &'static str, &'static str)> {
        vec![
            ("en", "Introduction to Machine Learning", "Machine learning is a subset of AI that enables systems to learn from data. It includes supervised, unsupervised, and reinforcement learning paradigms."),
            ("vi", "Giới thiệu về Học máy", "Học máy là tập con của AI cho phép hệ thống học từ dữ liệu. Nó bao gồm các mô hình học có giám sát, không giám sát và học tăng cường."),
            ("th", "บทนำสู่การเรียนรู้ของเครื่อง", "การเรียนรู้ของเครื่องเป็นส่วนย่อยของ AI ที่ช่วยให้ระบบเรียนรู้จากข้อมูล ประกอบด้วยการเรียนรู้แบบมีผู้ควบคุม ไม่มีผู้ควบคุม และการเรียนรู้แบบเสริมแรง"),
            ("ar", "مقدمة في تعلم الآلة", "تعلم الآلة هو فرع من الذكاء الاصطناعي يتيح للأنظمة التعلم من البيانات. يشمل التعلم الخاضع للإشراف وغير الخاضع للإشراف والتعلم المعزز."),
            ("zh", "机器学习简介", "机器学习是人工智能的一个子集，使系统能够从数据中学习。它包括监督学习、无监督学习和强化学习范式。"),
            ("es", "Introducción al Aprendizaje Automático", "El aprendizaje automático es un subconjunto de la IA que permite a los sistemas aprender de los datos. Incluye paradigmas de aprendizaje supervisado, no supervisado y por refuerzo."),
        ]
    }

    fn translate_pairs() -> Vec<(&'static str, &'static str, &'static str)> {
        vec![
            ("en", "vi", "The system uses end-to-end encryption to protect user data."),
            ("vi", "en", "Hệ thống sử dụng mã hóa đầu cuối để bảo vệ dữ liệu người dùng."),
            ("en", "th", "The system uses end-to-end encryption to protect user data."),
            ("en", "ar", "The system uses end-to-end encryption to protect user data."),
            ("en", "zh", "The system uses end-to-end encryption to protect user data."),
            ("en", "es", "The system uses end-to-end encryption to protect user data."),
            ("zh", "en", "系统使用端到端加密来保护用户数据。"),
            ("ar", "en", "يستخدم النظام تشفيرًا من طرف إلى طرف لحماية بيانات المستخدم."),
            ("es", "vi", "El sistema utiliza cifrado de extremo a extremo para proteger los datos del usuario."),
            ("th", "en", "ระบบใช้การเข้ารหัสจากต้นทางถึงปลายทางเพื่อปกป้องข้อมูลผู้ใช้"),
        ]
    }

    fn semantic_search_corpus() -> Vec<(&'static str, &'static str, Option<&'static str>)> {
        vec![
            ("doc_en_1", "Cloud computing enables on-demand access to computing resources over the internet.", Some("cloud-basics.md")),
            ("doc_en_2", "End-to-end encryption ensures that only the sender and recipient can read messages.", Some("security.md")),
            ("doc_vi_1", "Điện toán đám mây cho phép truy cập theo yêu cầu vào tài nguyên máy tính qua internet.", Some("cloud-basics-vi.md")),
            ("doc_vi_2", "Mã hóa đầu cuối đảm bảo rằng chỉ người gửi và người nhận mới có thể đọc tin nhắn.", Some("security-vi.md")),
            ("doc_th_1", "การประมวลผลแบบคลาวด์ช่วยให้สามารถเข้าถึงทรัพยากรการประมวลผลได้ตามความต้องการผ่านอินเทอร์เน็ต", Some("cloud-basics-th.md")),
            ("doc_ar_1", "الحوسبة السحابية تمكن من الوصول عند الطلب إلى موارد الحوسبة عبر الإنترنت.", Some("cloud-basics-ar.md")),
            ("doc_zh_1", "云计算通过互联网按需访问计算资源。", Some("cloud-basics-zh.md")),
            ("doc_es_1", "La computación en la nube permite el acceso bajo demanda a recursos informáticos a través de internet.", Some("cloud-basics-es.md")),
            ("doc_es_2", "El cifrado de extremo a extremo garantiza que solo el remitente y el destinatario puedan leer los mensajes.", Some("security-es.md")),
        ]
    }
}

/// Create a test engine with fake model files in a temp directory.
/// The fallback inference path will be used (no real ONNX model/tokenizer).
/// Must be called from within a tokio async context.
async fn setup_test_engine() -> (tempfile::TempDir, AiEngine) {
    let cache_dir = tempfile::tempdir().unwrap();

    // Create fake model files so InferenceSession::load doesn't fail
    let models_dir = cache_dir.path().join("models");
    std::fs::create_dir_all(&models_dir).unwrap();

    for filename in &[
        "mt5-small-1.0.0-int8.onnx",
        "multilingual-e5-small-1.0.0-int8.onnx",
        "clip-vit-base-patch32-1.0.0-int8.onnx",
    ] {
        std::fs::write(models_dir.join(filename), b"fake model").unwrap();
    }

    // Create fake adapter files
    let adapters_dir = cache_dir.path().join("adapters");
    std::fs::create_dir_all(&adapters_dir).unwrap();
    for lang in SUPPORTED_LANGUAGES {
        for task in &["summarize", "keypoints", "gendoc", "slides"] {
            std::fs::write(
                adapters_dir.join(format!("{}.{}.bin", task, lang)),
                b"LRA1\x00\x00\x00\x00",
            ).unwrap();
        }
        for target in SUPPORTED_LANGUAGES {
            if lang != target {
                std::fs::write(
                    adapters_dir.join(format!("translate.{}_{}.bin", lang, target)),
                    b"LRA1\x00\x00\x00\x00",
                ).unwrap();
            }
        }
    }

    // Use the public AiEngine::new API (does device profiling)
    let mut engine = AiEngine::new(cache_dir.path()).await.unwrap();

    // Override governor to permissive settings for testing
    engine.governor_mut().update_config(GovernorConfig {
        max_cpu_percent: 100,
        max_memory_percent: 100,
        timeout: std::time::Duration::from_secs(60),
        max_concurrent: 1,
        min_battery_percent: 0,
        max_thermal_state: ThermalState::Critical,
    });

    (cache_dir, engine)
}

// ─── Language Coverage Tests ───────────────────────────────────────

#[cfg(test)]
mod language_coverage {
    use super::*;

    #[test]
    fn test_all_supported_languages_present() {
        assert_eq!(SUPPORTED_LANGUAGES.len(), 22);
        // Original 6
        assert!(SUPPORTED_LANGUAGES.contains(&"en"));
        assert!(SUPPORTED_LANGUAGES.contains(&"vi"));
        assert!(SUPPORTED_LANGUAGES.contains(&"th"));
        assert!(SUPPORTED_LANGUAGES.contains(&"ar"));
        assert!(SUPPORTED_LANGUAGES.contains(&"zh"));
        assert!(SUPPORTED_LANGUAGES.contains(&"es"));
        // Expanded 16
        assert!(SUPPORTED_LANGUAGES.contains(&"fr"));
        assert!(SUPPORTED_LANGUAGES.contains(&"de"));
        assert!(SUPPORTED_LANGUAGES.contains(&"ja"));
        assert!(SUPPORTED_LANGUAGES.contains(&"ko"));
        assert!(SUPPORTED_LANGUAGES.contains(&"id"));
        assert!(SUPPORTED_LANGUAGES.contains(&"ms"));
        assert!(SUPPORTED_LANGUAGES.contains(&"tl"));
        assert!(SUPPORTED_LANGUAGES.contains(&"pt"));
        assert!(SUPPORTED_LANGUAGES.contains(&"ru"));
        assert!(SUPPORTED_LANGUAGES.contains(&"hi"));
        assert!(SUPPORTED_LANGUAGES.contains(&"tr"));
        assert!(SUPPORTED_LANGUAGES.contains(&"fa"));
        assert!(SUPPORTED_LANGUAGES.contains(&"ur"));
        assert!(SUPPORTED_LANGUAGES.contains(&"bn"));
        assert!(SUPPORTED_LANGUAGES.contains(&"ne"));
        assert!(SUPPORTED_LANGUAGES.contains(&"km"));
    }

    #[test]
    fn test_validate_language_accepts_all_supported() {
        for lang in SUPPORTED_LANGUAGES {
            assert!(validate_language(lang).is_ok(), "validate_language({}) should succeed", lang);
        }
    }

    #[test]
    fn test_validate_language_rejects_unsupported() {
        // These are NOT in our 22-language list
        assert!(validate_language("xx").is_err());
        assert!(validate_language("sw").is_err());
        assert!(validate_language("it").is_err());
        assert!(validate_language("nl").is_err());
        assert!(validate_language("").is_err());
        assert!(validate_language("EN").is_err()); // case-sensitive
    }

    #[test]
    fn test_build_prompt_includes_native_instructions() {
        let prompt_vi = build_prompt("Summarize", "vi", "test content");
        assert!(prompt_vi.contains("Trả lời bằng tiếng Việt."));
        assert!(prompt_vi.contains("test content"));

        let prompt_th = build_prompt("Summarize", "th", "test content");
        assert!(prompt_th.contains("ตอบเป็นภาษาไทย"));

        let prompt_ar = build_prompt("Summarize", "ar", "test content");
        assert!(prompt_ar.contains("أجب باللغة العربية."));

        let prompt_zh = build_prompt("Summarize", "zh", "test content");
        assert!(prompt_zh.contains("请用中文回答。"));

        let prompt_es = build_prompt("Summarize", "es", "test content");
        assert!(prompt_es.contains("Responde en español."));

        let prompt_en = build_prompt("Summarize", "en", "test content");
        assert!(prompt_en.contains("Answer in English."));
    }

    #[test]
    fn test_build_prompt_structure_consistent_across_languages() {
        let task = "Summarize the following";
        let content = "test content here";

        for lang in SUPPORTED_LANGUAGES {
            let prompt = build_prompt(task, lang, content);
            assert!(prompt.starts_with("Summarize the following: "), "prompt for {} should start with task", lang);
            assert!(prompt.contains(content), "prompt for {} should contain content", lang);
        }
    }
}

// ─── Multilingual Text Pipeline Tests ──────────────────────────────

#[cfg(test)]
mod multilingual_pipelines {
    use super::*;

    #[tokio::test]
    async fn test_summarize_all_languages() {
        let (_tmp, mut engine) = setup_test_engine().await;
        let spec = ModelSpec::mt5_small_int8();
        engine.ensure_model(&spec).await.unwrap();

        for (lang, text) in MultilingualCorpus::summarize_inputs() {
            let result = engine.summarize(text, lang, TaskOptions::default()).await;
            assert!(result.is_ok(), "summarize({}) failed: {:?}", lang, result.err());
            let result = result.unwrap();
            assert_eq!(result.task, Task::Summarize);
            assert_eq!(result.model, "mt5-small-int8");
            assert!(result.adapter.is_some(), "adapter should be set for {}", lang);
            // duration_ms can be 0 in fallback mode (very fast)
            assert!(result.duration_ms < 10000, "duration should be reasonable for {}", lang);
            assert!(!result.output.is_empty(), "output should not be empty for {}", lang);
            // Fallback mode should produce meaningful extracted content
            assert!(!result.output.is_empty(), "output should not be empty for {}", lang);
            // Smart fallback extracts content from the input
            assert!(result.output.len() > 10, "output should have meaningful content for {}", lang);
        }
    }

    #[tokio::test]
    async fn test_key_points_all_languages() {
        let (_tmp, mut engine) = setup_test_engine().await;
        let spec = ModelSpec::mt5_small_int8();
        engine.ensure_model(&spec).await.unwrap();

        for (lang, text) in MultilingualCorpus::key_points_inputs() {
            let result = engine.key_points(text, lang, TaskOptions::default()).await;
            assert!(result.is_ok(), "key_points({}) failed: {:?}", lang, result.err());
            let result = result.unwrap();
            assert_eq!(result.task, Task::KeyPoints);
            assert_eq!(result.model, "mt5-small-int8");
            assert!(result.adapter.is_some(), "adapter should be set for {}", lang);
        }
    }

    #[tokio::test]
    async fn test_generate_doc_all_languages() {
        let (_tmp, mut engine) = setup_test_engine().await;
        let spec = ModelSpec::mt5_small_int8();
        engine.ensure_model(&spec).await.unwrap();

        for (lang, topic, outline) in MultilingualCorpus::generate_doc_inputs() {
            let result = engine.generate_doc(topic, outline, lang, TaskOptions::default()).await;
            assert!(result.is_ok(), "generate_doc({}) failed: {:?}", lang, result.err());
            let result = result.unwrap();
            assert_eq!(result.task, Task::GenerateDoc);
            assert_eq!(result.model, "mt5-small-int8");
            assert!(result.adapter.is_some());
        }
    }

    #[tokio::test]
    async fn test_generate_slides_all_languages() {
        let (_tmp, mut engine) = setup_test_engine().await;
        let spec = ModelSpec::mt5_small_int8();
        engine.ensure_model(&spec).await.unwrap();

        for (lang, topic, content) in MultilingualCorpus::generate_slides_inputs() {
            let result = engine.generate_slides(topic, content, lang, TaskOptions::default()).await;
            assert!(result.is_ok(), "generate_slides({}) failed: {:?}", lang, result.err());
            let result = result.unwrap();
            assert_eq!(result.task, Task::GenerateSlides);
            assert_eq!(result.model, "mt5-small-int8");
            assert!(result.adapter.is_some());
        }
    }

    #[tokio::test]
    async fn test_unsupported_language_rejected() {
        let (_tmp, mut engine) = setup_test_engine().await;
        let spec = ModelSpec::mt5_small_int8();
        engine.ensure_model(&spec).await.unwrap();

        let result = engine.summarize("test text", "xx", TaskOptions::default()).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, ZkAiError::UnsupportedLanguage(ref l) if l == "xx"));
    }
}

// ─── Cross-Language Translation Tests ──────────────────────────────

#[cfg(test)]
mod translation {
    use super::*;

    #[tokio::test]
    async fn test_translate_all_language_pairs() {
        let (_tmp, mut engine) = setup_test_engine().await;
        let spec = ModelSpec::mt5_small_int8();
        engine.ensure_model(&spec).await.unwrap();

        for (src, dst, text) in MultilingualCorpus::translate_pairs() {
            let result = engine.translate(text, src, dst, TaskOptions::default()).await;
            assert!(result.is_ok(), "translate({}→{}) failed: {:?}", src, dst, result.err());
            let result = result.unwrap();
            assert_eq!(result.task, Task::Translate);
            assert_eq!(result.model, "mt5-small-int8");
            assert!(result.adapter.is_some(), "adapter should be set for {}→{}", src, dst);
            let adapter = result.adapter.as_ref().unwrap();
            assert!(adapter.contains(src), "adapter should contain source lang {}", src);
            assert!(adapter.contains(dst), "adapter should contain target lang {}", dst);
        }
    }

    #[tokio::test]
    async fn test_translate_rejects_unsupported_source() {
        let (_tmp, mut engine) = setup_test_engine().await;
        let spec = ModelSpec::mt5_small_int8();
        engine.ensure_model(&spec).await.unwrap();

        let result = engine.translate("test", "xx", "en", TaskOptions::default()).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_translate_rejects_unsupported_target() {
        let (_tmp, mut engine) = setup_test_engine().await;
        let spec = ModelSpec::mt5_small_int8();
        engine.ensure_model(&spec).await.unwrap();

        let result = engine.translate("test", "en", "xx", TaskOptions::default()).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_translate_same_language_pair() {
        let (_tmp, mut engine) = setup_test_engine().await;
        let spec = ModelSpec::mt5_small_int8();
        engine.ensure_model(&spec).await.unwrap();

        // Translating en→en: adapter file doesn't exist, but adapter failure
        // is non-fatal — the pipeline continues with smart fallback which
        // echoes the input text.
        let result = engine.translate("Hello world", "en", "en", TaskOptions::default()).await;
        assert!(result.is_ok(), "translate(en→en) should succeed with fallback: {:?}", result.err());
        let result = result.unwrap();
        assert!(!result.output.is_empty(), "output should not be empty");
    }
}

// ─── Streaming Inference Tests ─────────────────────────────────────

#[cfg(test)]
mod streaming {
    use super::*;

    #[tokio::test]
    async fn test_stream_summarize_multilingual() {
        let (_tmp, mut engine) = setup_test_engine().await;
        let spec = ModelSpec::mt5_small_int8();
        engine.ensure_model(&spec).await.unwrap();

        for (lang, text) in MultilingualCorpus::summarize_inputs().iter().take(3) {
            let opts = TaskOptions { stream: true, ..Default::default() };
            let result = engine.summarize(text, lang, opts).await;
            assert!(result.is_ok(), "stream summarize({}) failed: {:?}", lang, result.err());
            let result = result.unwrap();
            assert_eq!(result.task, Task::Summarize);
            assert!(!result.output.is_empty(), "stream output should not be empty for {}", lang);
        }
    }

    #[tokio::test]
    async fn test_stream_translate() {
        let (_tmp, mut engine) = setup_test_engine().await;
        let spec = ModelSpec::mt5_small_int8();
        engine.ensure_model(&spec).await.unwrap();

        let opts = TaskOptions { stream: true, ..Default::default() };
        let result = engine.translate("Hello world", "en", "vi", opts).await;
        assert!(result.is_ok(), "stream translate failed: {:?}", result.err());
        let result = result.unwrap();
        assert_eq!(result.task, Task::Translate);
        assert!(!result.output.is_empty());
    }
}

// ─── Semantic Search Multilingual Tests ────────────────────────────

#[cfg(test)]
mod semantic_search {
    use super::*;

    #[test]
    fn test_multilingual_text_index_search() {
        let mut index = TextIndex::new();

        // Add multilingual corpus with distinct embeddings
        // Cloud-related docs have similar embeddings (dim 0 high)
        // Security-related docs have similar embeddings (dim 1 high)
        for (id, text, source) in MultilingualCorpus::semantic_search_corpus() {
            let is_cloud = text.to_lowercase().contains("cloud")
                || text.to_lowercase().contains("đám mây")
                || text.to_lowercase().contains("คลาวด์")
                || text.to_lowercase().contains("سحاب")
                || text.to_lowercase().contains("云")
                || text.to_lowercase().contains("nube");
            let embedding = if is_cloud {
                vec![0.9, 0.1, 0.0]
            } else {
                vec![0.1, 0.9, 0.0]
            };
            index.add_text(id, text, embedding, source);
        }

        assert_eq!(index.len(), 9);

        // Query for "cloud computing" — should return cloud docs across all languages
        let cloud_query = vec![0.9, 0.1, 0.0];
        let hits = index.search(&cloud_query, 5);
        assert_eq!(hits.len(), 5);
        // All top hits should be cloud-related
        for hit in &hits {
            assert!(
                hit.id.contains("cloud") || hit.id.contains("1"),
                "hit {} should be cloud-related",
                hit.id
            );
        }

        // Query for "encryption" — should return security docs first
        let security_query = vec![0.1, 0.9, 0.0];
        let hits = index.search(&security_query, 5);
        assert_eq!(hits.len(), 5); // 5 results (3 security + 2 cloud)
        // Top 3 should all be security-related (higher similarity)
        for hit in hits.iter().take(3) {
            assert!(
                hit.id.contains("security") || hit.id.contains("2"),
                "hit {} should be security-related",
                hit.id
            );
        }
        // Security docs should have higher scores than cloud docs
        assert!(hits[2].score > hits[3].score, "security docs should rank higher");
    }

    #[test]
    fn test_semantic_search_cross_language_retrieval() {
        let mut index = TextIndex::new();

        // English cloud doc
        index.add_text(
            "en_cloud",
            "Cloud computing enables on-demand access to computing resources.",
            vec![0.9, 0.1, 0.0],
            None,
        );
        // Vietnamese cloud doc — same semantic meaning
        index.add_text(
            "vi_cloud",
            "Điện toán đám mây cho phép truy cập theo yêu cầu vào tài nguyên máy tính.",
            vec![0.88, 0.12, 0.0], // similar embedding
            None,
        );
        // Unrelated English doc
        index.add_text(
            "en_other",
            "The weather is nice today.",
            vec![0.0, 0.0, 0.9],
            None,
        );

        // Query with cloud-like embedding
        let query = vec![0.9, 0.1, 0.0];
        let hits = index.search(&query, 2);
        assert_eq!(hits.len(), 2);
        // Both cloud docs should be retrieved, with English first (higher similarity)
        assert_eq!(hits[0].id, "en_cloud");
        assert_eq!(hits[1].id, "vi_cloud");
        // The unrelated doc should not be in top 2
        assert!(!hits.iter().any(|h| h.id == "en_other"));
    }

    #[test]
    fn test_text_index_json_roundtrip_multilingual() {
        let mut index = TextIndex::new();
        index.add_text("d1", "Xin chào thế giới", vec![1.0, 0.0], Some("vietnamese.md"));
        index.add_text("d2", "你好世界", vec![0.0, 1.0], Some("chinese.md"));
        index.add_text("d3", "مرحبا بالعالم", vec![0.5, 0.5], Some("arabic.md"));

        let json = index.to_json().unwrap();
        let restored = TextIndex::from_json(&json).unwrap();
        assert_eq!(restored.len(), 3);

        let hits = restored.search(&[1.0, 0.0], 1);
        assert_eq!(hits[0].id, "d1");
        assert_eq!(hits[0].source.as_deref(), Some("vietnamese.md"));
    }

    #[test]
    fn test_semantic_search_empty_index_returns_empty() {
        let index = TextIndex::new();
        let hits = index.search(&[1.0, 0.0, 0.0], 5);
        assert!(hits.is_empty());
    }

    #[test]
    fn test_semantic_search_top_k_limit() {
        let mut index = TextIndex::new();
        for i in 0..20 {
            index.add_text(
                &format!("doc{}", i),
                &format!("Document {}", i),
                vec![i as f32 * 0.1, 1.0 - i as f32 * 0.1],
                None,
            );
        }
        let hits = index.search(&[0.5, 0.5], 5);
        assert_eq!(hits.len(), 5);
        // Results should be sorted by descending score
        for i in 0..hits.len() - 1 {
            assert!(hits[i].score >= hits[i + 1].score, "results should be sorted");
        }
    }
}

// ─── Image Search Tests ─────────────────────────────────────────────

#[cfg(test)]
mod image_search {
    use super::*;

    #[test]
    fn test_image_index_search_with_multilingual_captions() {
        let mut index = ImageIndex::new();
        index.add_image("img_en", "a cat sitting on a mat", vec![1.0, 0.0, 0.0]);
        index.add_image("img_vi", "mèo ngồi trên chiếu", vec![0.95, 0.05, 0.0]);
        index.add_image("img_th", "แม่นั่งอยู่บนพรม", vec![0.9, 0.1, 0.0]);
        index.add_image("img_zh", "一只狗在公园里跑", vec![0.0, 1.0, 0.0]);
        index.add_image("img_ar", "كلب يركض في الحديقة", vec![0.05, 0.95, 0.0]);

        // Query for "cat" — should return cat images across languages
        let cat_query = vec![1.0, 0.0, 0.0];
        let hits = index.search(&cat_query, 3);
        assert_eq!(hits.len(), 3);
        assert_eq!(hits[0].id, "img_en");
        assert_eq!(hits[1].id, "img_vi");
        assert_eq!(hits[2].id, "img_th");
        // Dog images should not be in cat results
        assert!(!hits.iter().any(|h| h.id.contains("dog") || h.id.contains("img_zh") || h.id.contains("img_ar")));
    }

    #[test]
    fn test_image_index_json_roundtrip() {
        let mut index = ImageIndex::new();
        index.add_image("img1", "mèo ngồi trên chiếu", vec![0.8, 0.2]);
        index.add_image("img2", "แม่นั่งอยู่บนพรม", vec![0.2, 0.8]);

        let json = index.to_json().unwrap();
        let restored = ImageIndex::from_json(&json).unwrap();
        assert_eq!(restored.len(), 2);

        let hits = restored.search(&[1.0, 0.0], 1);
        assert_eq!(hits[0].id, "img1");
    }

    #[test]
    fn test_cosine_similarity_edge_cases() {
        // Identical vectors
        assert!((cosine_similarity(&[1.0, 0.0], &[1.0, 0.0]) - 1.0).abs() < 1e-6);
        // Orthogonal
        assert!(cosine_similarity(&[1.0, 0.0], &[0.0, 1.0]).abs() < 1e-6);
        // Opposite
        assert!((cosine_similarity(&[1.0, 0.0], &[-1.0, 0.0]) + 1.0).abs() < 1e-6);
        // Empty
        assert_eq!(cosine_similarity(&[], &[]), 0.0);
        // Different lengths
        assert_eq!(cosine_similarity(&[1.0], &[1.0, 0.0]), 0.0);
        // Zero vectors
        assert_eq!(cosine_similarity(&[0.0, 0.0], &[0.0, 0.0]), 0.0);
    }
}

// ─── Swarm Coordinator Multilingual Tests ──────────────────────────

#[cfg(test)]
mod swarm {
    use super::*;

    fn mock_device(
        id: &str,
        tier: DeviceTier,
        idle: bool,
        models: Vec<&str>,
        battery: Option<u8>,
    ) -> DeviceCapability {
        DeviceCapability {
            device_id: id.to_string(),
            device_name: id.to_string(),
            tier,
            available_models: models.iter().map(|s| s.to_string()).collect(),
            battery_level: battery,
            is_idle: idle,
        }
    }

    #[test]
    fn test_elect_device_multilingual_swarm() {
        let transport = MockTransport;
        let local = mock_device("local", DeviceTier::LowEnd, true, vec!["mt5-small"], Some(50));
        let mut coord = SwarmCoordinator::new(transport, local);

        // Devices with different language capabilities (via available models)
        coord.update_device(mock_device("device_vi", DeviceTier::HighEnd, true, vec!["mt5-small"], Some(85)));
        coord.update_device(mock_device("device_th", DeviceTier::MidRange, true, vec!["mt5-small"], Some(70)));
        coord.update_device(mock_device("device_ar", DeviceTier::HighEnd, false, vec!["mt5-small"], Some(90)));
        coord.update_device(mock_device("device_zh", DeviceTier::MidRange, true, vec!["mt5-small"], Some(60)));

        // Elect for mt5-small — should pick device_vi (HighEnd, idle, highest battery)
        let elected = coord.elect_device("mt5-small").unwrap();
        assert_eq!(elected.device_id, "device_vi");
    }

    #[test]
    fn test_elect_device_prefers_higher_tier_for_heavy_tasks() {
        let transport = MockTransport;
        let local = mock_device("local", DeviceTier::LowEnd, true, vec!["mt5-small"], Some(50));
        let mut coord = SwarmCoordinator::new(transport, local);

        coord.update_device(mock_device("low1", DeviceTier::LowEnd, true, vec!["mt5-small"], Some(95)));
        coord.update_device(mock_device("mid1", DeviceTier::MidRange, true, vec!["mt5-small"], Some(80)));
        coord.update_device(mock_device("high1", DeviceTier::HighEnd, true, vec!["mt5-small"], Some(60)));

        let elected = coord.elect_device("mt5-small").unwrap();
        assert_eq!(elected.device_id, "high1");
    }

    #[test]
    fn test_elect_device_skips_throttled_for_multilingual_task() {
        let transport = MockTransport;
        let local = mock_device("local", DeviceTier::LowEnd, true, vec!["mt5-small"], Some(50));
        let mut coord = SwarmCoordinator::new(transport, local);

        // Throttled device with high battery but low tier
        coord.update_device(mock_device("throttled_dev", DeviceTier::Throttled, true, vec!["mt5-small"], Some(100)));
        coord.update_device(mock_device("normal_dev", DeviceTier::LowEnd, true, vec!["mt5-small"], Some(40)));

        let elected = coord.elect_device("mt5-small").unwrap();
        assert_eq!(elected.device_id, "normal_dev");
    }

    #[test]
    fn test_elect_device_no_match_returns_none() {
        let transport = MockTransport;
        let local = mock_device("local", DeviceTier::LowEnd, true, vec!["mt5-small"], Some(50));
        let mut coord = SwarmCoordinator::new(transport, local);

        coord.update_device(mock_device("dev1", DeviceTier::HighEnd, true, vec!["clip-vit-base-patch32"], Some(90)));

        // Only local device has mt5-small, but elect_device excludes local
        let elected = coord.elect_device("mt5-small");
        // No remote device has the model — should return None
        assert!(elected.is_none());
    }

    #[test]
    fn test_should_volunteer_for_foreign_language_request() {
        let transport = MockTransport;
        let local = mock_device("local", DeviceTier::HighEnd, true, vec!["mt5-small"], Some(85));
        let coord = SwarmCoordinator::new(transport, local);

        let request = InferenceRequest {
            request_id: "req1".to_string(),
            task: Task::Translate,
            input: "Xin chào thế giới".to_string(),
            language: "vi".to_string(),
            target_language: Some("en".to_string()),
            options: TaskOptions::default(),
            requester_id: "remote_device".to_string(),
            timestamp: chrono::Utc::now(),
        };

        assert!(coord.should_volunteer(&request, "mt5-small"));
    }

    #[test]
    fn test_should_not_volunteer_when_busy() {
        let transport = MockTransport;
        let local = mock_device("local", DeviceTier::HighEnd, false, vec!["mt5-small"], Some(85));
        let coord = SwarmCoordinator::new(transport, local);

        let request = InferenceRequest {
            request_id: "req1".to_string(),
            task: Task::Summarize,
            input: "test".to_string(),
            language: "en".to_string(),
            target_language: None,
            options: TaskOptions::default(),
            requester_id: "other".to_string(),
            timestamp: chrono::Utc::now(),
        };

        assert!(!coord.should_volunteer(&request, "mt5-small"));
    }

    #[test]
    fn test_capability_from_profile_preserves_tier() {
        let profile = DeviceProfile {
            tier: DeviceTier::HighEnd,
            acceleration: Acceleration::Metal,
            total_memory_mb: 16384,
            available_memory_mb: 12288,
            cpu_cores: 10,
            has_npu: true,
            npu_tops: Some(15),
            battery_level: Some(85),
            thermal_state: ThermalState::Nominal,
            platform: "macos".to_string(),
            arch: "aarch64".to_string(),
        };

        let cap = capability_from_profile(
            &profile,
            "dev1".to_string(),
            "MacBook Pro".to_string(),
            vec!["mt5-small".to_string()],
            true,
        );

        assert_eq!(cap.tier, DeviceTier::HighEnd);
        assert_eq!(cap.battery_level, Some(85));
        assert_eq!(cap.available_models, vec!["mt5-small"]);
    }

    // Mock transport for testing
    struct MockTransport;

    #[async_trait::async_trait]
    impl SwarmTransport for MockTransport {
        async fn broadcast_capability(&self, _: &DeviceCapability) -> Result<()> { Ok(()) }
        async fn send_request(&self, _: &InferenceRequest) -> Result<()> { Ok(()) }
        async fn send_result(&self, _: &InferenceResult) -> Result<()> { Ok(()) }
        async fn recv_request(&self) -> Result<InferenceRequest> {
            Err(ZkAiError::Swarm("mock".to_string()))
        }
        async fn recv_result(&self) -> Result<InferenceResult> {
            Err(ZkAiError::Swarm("mock".to_string()))
        }
        async fn recv_capability(&self) -> Result<DeviceCapability> {
            Err(ZkAiError::Swarm("mock".to_string()))
        }
    }
}

// ─── Governor Integration Tests ────────────────────────────────────

#[cfg(test)]
mod governor_integration {
    use super::*;

    #[test]
    fn test_governor_config_all_tiers() {
        let high = GovernorConfig::from_tier(&DeviceTier::HighEnd);
        assert_eq!(high.max_cpu_percent, 60);
        assert_eq!(high.timeout, std::time::Duration::from_secs(30));
        assert_eq!(high.max_concurrent, 1);

        let mid = GovernorConfig::from_tier(&DeviceTier::MidRange);
        assert_eq!(mid.max_cpu_percent, 40);
        assert_eq!(mid.timeout, std::time::Duration::from_secs(20));

        let low = GovernorConfig::from_tier(&DeviceTier::LowEnd);
        assert_eq!(low.max_cpu_percent, 30);
        assert_eq!(low.timeout, std::time::Duration::from_secs(15));

        let throttled = GovernorConfig::from_tier(&DeviceTier::Throttled);
        assert_eq!(throttled.max_cpu_percent, 10);
        assert_eq!(throttled.timeout, std::time::Duration::from_secs(10));
        assert_eq!(throttled.min_battery_percent, 100);
    }

    #[test]
    fn test_governor_paused_by_low_battery() {
        let mut gov = ResourceGovernor::new(GovernorConfig::from_tier(&DeviceTier::HighEnd));
        gov.update_battery(15);
        assert!(gov.is_paused());
        assert!(gov.check_resources().is_err());
    }

    #[test]
    fn test_governor_paused_by_thermal_throttle() {
        let mut gov = ResourceGovernor::new(GovernorConfig::from_tier(&DeviceTier::HighEnd));
        gov.update_thermal(ThermalState::Serious);
        assert!(gov.is_paused());
        assert!(gov.check_resources().is_err());
    }

    #[test]
    fn test_governor_resumes_when_conditions_improve() {
        let mut gov = ResourceGovernor::new(GovernorConfig::from_tier(&DeviceTier::HighEnd));
        gov.update_battery(15);
        assert!(gov.is_paused());

        gov.update_battery(80);
        assert!(!gov.is_paused());

        gov.update_thermal(ThermalState::Serious);
        assert!(gov.is_paused());

        gov.update_thermal(ThermalState::Nominal);
        assert!(!gov.is_paused());
    }

    #[test]
    fn test_governor_check_resources_with_permissive_limits() {
        let config = GovernorConfig {
            max_cpu_percent: 100,
            max_memory_percent: 100,
            timeout: std::time::Duration::from_secs(30),
            max_concurrent: 1,
            min_battery_percent: 0,
            max_thermal_state: ThermalState::Critical,
        };
        let gov = ResourceGovernor::new(config);
        assert!(gov.check_resources().is_ok());
    }

    #[tokio::test]
    async fn test_governor_acquire_and_release() {
        let config = GovernorConfig {
            max_cpu_percent: 100,
            max_memory_percent: 100,
            timeout: std::time::Duration::from_secs(30),
            max_concurrent: 1,
            min_battery_percent: 0,
            max_thermal_state: ThermalState::Critical,
        };
        let gov = ResourceGovernor::new(config);
        let permit = gov.acquire().await.unwrap();
        drop(permit);
        // Should be able to acquire again after release
        let permit2 = gov.acquire().await.unwrap();
        drop(permit2);
    }

    #[test]
    fn test_governor_update_config() {
        let mut gov = ResourceGovernor::new(GovernorConfig::from_tier(&DeviceTier::HighEnd));
        gov.update_config(GovernorConfig::from_tier(&DeviceTier::LowEnd));
        assert_eq!(gov.config().max_cpu_percent, 30);
        assert_eq!(gov.config().timeout, std::time::Duration::from_secs(15));
    }
}

// ─── Profiler Integration Tests ────────────────────────────────────

#[cfg(test)]
mod profiler_integration {
    use super::*;

    #[test]
    fn test_compute_tier_high_end_apple_silicon() {
        let profile = DeviceProfile {
            tier: DeviceTier::LowEnd,
            acceleration: Acceleration::CoreML,
            total_memory_mb: 16384,
            available_memory_mb: 12288,
            cpu_cores: 10,
            has_npu: true,
            npu_tops: Some(15),
            battery_level: Some(85),
            thermal_state: ThermalState::Nominal,
            platform: "macos".to_string(),
            arch: "aarch64".to_string(),
        };
        // Re-profile using the profiler's update_power_state
        let mut p = profile.clone();
        DeviceProfiler::update_power_state(&mut p, Some(85), ThermalState::Nominal);
        assert_eq!(p.tier, DeviceTier::HighEnd);
    }

    #[test]
    fn test_compute_tier_throttled_low_battery() {
        let mut profile = DeviceProfile {
            tier: DeviceTier::HighEnd,
            acceleration: Acceleration::Metal,
            total_memory_mb: 16384,
            available_memory_mb: 12288,
            cpu_cores: 10,
            has_npu: true,
            npu_tops: Some(15),
            battery_level: Some(85),
            thermal_state: ThermalState::Nominal,
            platform: "ios".to_string(),
            arch: "aarch64".to_string(),
        };
        DeviceProfiler::update_power_state(&mut profile, Some(15), ThermalState::Nominal);
        assert_eq!(profile.tier, DeviceTier::Throttled);
    }

    #[test]
    fn test_compute_tier_throttled_thermal() {
        let mut profile = DeviceProfile {
            tier: DeviceTier::HighEnd,
            acceleration: Acceleration::Metal,
            total_memory_mb: 16384,
            available_memory_mb: 12288,
            cpu_cores: 10,
            has_npu: true,
            npu_tops: Some(15),
            battery_level: Some(85),
            thermal_state: ThermalState::Nominal,
            platform: "ios".to_string(),
            arch: "aarch64".to_string(),
        };
        DeviceProfiler::update_power_state(&mut profile, Some(85), ThermalState::Critical);
        assert_eq!(profile.tier, DeviceTier::Throttled);
    }

    #[test]
    fn test_from_js_webgpu_high_end() {
        let profile = DeviceProfiler::from_js(true, 8, 8192, Some(90));
        assert_eq!(profile.acceleration, Acceleration::WebGPU);
        assert_eq!(profile.cpu_cores, 8);
        assert_eq!(profile.total_memory_mb, 8192);
    }

    #[test]
    fn test_from_js_no_webgpu_low_end() {
        let profile = DeviceProfiler::from_js(false, 2, 2048, None);
        assert_eq!(profile.acceleration, Acceleration::CpuSimd);
        assert_eq!(profile.cpu_cores, 2);
    }
}

// ─── SimpleRng Tests ───────────────────────────────────────────────

#[cfg(test)]
mod simple_rng_tests {
    use zk_ai_core::simple_rng::SimpleRng;

    #[test]
    fn test_simple_rng_seeded_reproducible() {
        let mut rng1 = SimpleRng::from_seed(42);
        let mut rng2 = SimpleRng::from_seed(42);

        let v1: Vec<u64> = (0..10).map(|_| rng1.next_u64()).collect();
        let v2: Vec<u64> = (0..10).map(|_| rng2.next_u64()).collect();

        assert_eq!(v1, v2, "Same seed should produce same sequence");
    }

    #[test]
    fn test_simple_rng_different_seeds_differ() {
        let mut rng1 = SimpleRng::from_seed(42);
        let mut rng2 = SimpleRng::from_seed(43);

        let v1: Vec<u64> = (0..10).map(|_| rng1.next_u64()).collect();
        let v2: Vec<u64> = (0..10).map(|_| rng2.next_u64()).collect();

        assert_ne!(v1, v2, "Different seeds should produce different sequences");
    }

    #[test]
    fn test_simple_rng_from_entropy() {
        let mut rng = SimpleRng::new();
        let v: u64 = rng.next_u64();
        // Just verify it doesn't panic and produces a value
        let _ = v;
    }

    #[test]
    fn test_simple_rng_f32_range() {
        let mut rng = SimpleRng::from_seed(123);
        for _ in 0..100 {
            let v = rng.next_f32();
            assert!(v >= 0.0 && v < 1.0, "next_f32 should be in [0, 1)");
        }
    }

    #[test]
    fn test_simple_rng_zero_seed_handled() {
        let mut rng = SimpleRng::from_seed(0);
        let v = rng.next_u64();
        assert_ne!(v, 0, "zero seed should not produce zero output");
    }
}

// ─── Model Manager Tests ───────────────────────────────────────────

#[cfg(test)]
mod model_manager_tests {
    use super::*;

    #[test]
    fn test_model_spec_filenames() {
        let mt5 = ModelSpec::mt5_small_int8();
        assert_eq!(mt5.filename(), "mt5-small-1.0.0-int8.onnx");

        let e5 = ModelSpec::e5_small_int8();
        assert_eq!(e5.filename(), "multilingual-e5-small-1.0.0-int8.onnx");

        let clip = ModelSpec::clip_int8();
        assert_eq!(clip.filename(), "clip-vit-base-patch32-1.0.0-int8.onnx");
    }

    #[test]
    fn test_model_spec_cdn_urls() {
        let spec = ModelSpec::mt5_small_int8();
        let url = spec.cdn_url("https://cdn.zkai.dev");
        assert_eq!(url, "https://cdn.zkai.dev/models/mt5-small/1.0.0/int8/model.onnx");
    }

    #[test]
    fn test_model_spec_with_sha256() {
        let spec = ModelSpec::mt5_small_int8()
            .with_sha256("abc123def456");
        assert_eq!(spec.sha256, Some("abc123def456".to_string()));
    }

    #[test]
    fn test_model_spec_verify_integrity_no_hash() {
        let spec = ModelSpec::mt5_small_int8();
        // No hash set — should always pass
        assert!(spec.verify_integrity(b"any data").is_ok());
    }

    #[test]
    fn test_model_spec_verify_integrity_with_hash() {
        use sha2::{Sha256, Digest};
        let data = b"test model data";
        let hash = hex::encode(Sha256::digest(data));
        let spec = ModelSpec::mt5_small_int8().with_sha256(&hash);
        assert!(spec.verify_integrity(data).is_ok());

        let spec_bad = ModelSpec::mt5_small_int8().with_sha256("0000000000000000");
        assert!(spec_bad.verify_integrity(data).is_err());
    }

    #[test]
    fn test_model_cache_config_tier_limits() {
        let high_profile = DeviceProfile {
            tier: DeviceTier::HighEnd,
            ..Default::default()
        };
        let config = ModelCacheConfig::from_profile("/tmp/test", &high_profile);
        assert_eq!(config.max_cache_mb, 2048);

        let mid_profile = DeviceProfile {
            tier: DeviceTier::MidRange,
            ..Default::default()
        };
        let config = ModelCacheConfig::from_profile("/tmp/test", &mid_profile);
        assert_eq!(config.max_cache_mb, 512);

        let low_profile = DeviceProfile {
            tier: DeviceTier::LowEnd,
            ..Default::default()
        };
        let config = ModelCacheConfig::from_profile("/tmp/test", &low_profile);
        assert_eq!(config.max_cache_mb, 150);
    }

    #[test]
    fn test_model_spec_apply_hash_from_manifest() {
        let mut spec = ModelSpec::mt5_small_int8();
        assert!(spec.sha256.is_none());

        let mut manifest = std::collections::HashMap::new();
        manifest.insert(
            "mt5-small-1.0.0-int8.onnx".to_string(),
            "deadbeef".to_string(),
        );
        spec.apply_hash_from_manifest(&manifest);
        assert_eq!(spec.sha256, Some("deadbeef".to_string()));
    }
}

// ─── End-to-End Workflow Tests ─────────────────────────────────────

#[cfg(test)]
mod e2e_workflow {
    use super::*;

    /// Simulate a real-world workflow:
    /// 1. Summarize a meeting transcript (en)
    /// 2. Translate the summary to Vietnamese
    /// 3. Extract key points from the Vietnamese translation
    /// 4. Generate a document from the key points (vi)
    /// 5. Generate slides from the document (vi)
    #[tokio::test]
    async fn test_full_multilingual_workflow_en_to_vi() {
        let (_tmp, mut engine) = setup_test_engine().await;
        let spec = ModelSpec::mt5_small_int8();
        engine.ensure_model(&spec).await.unwrap();

        // Step 1: Summarize English meeting transcript
        let meeting_text = "The quarterly review meeting covered three topics. First, revenue increased by 15% driven by cloud services. Second, the engineering team shipped 12 features including real-time collaboration. Third, customer retention reached 92%. The team agreed to hire 8 more engineers in Q4.";
        let step1 = engine.summarize(meeting_text, "en", TaskOptions::default()).await
            .expect("summarize(en) should succeed");
        assert_eq!(step1.task, Task::Summarize);
        assert!(!step1.output.is_empty());
        println!("Step 1 - Summarize (en): {}", step1.output);

        // Step 2: Translate the summary to Vietnamese
        let step2 = engine.translate(&step1.output, "en", "vi", TaskOptions::default()).await
            .expect("translate(en→vi) should succeed");
        assert_eq!(step2.task, Task::Translate);
        assert!(!step2.output.is_empty());
        println!("Step 2 - Translate (en→vi): {}", step2.output);

        // Step 3: Extract key points from Vietnamese translation
        let step3 = engine.key_points(&step2.output, "vi", TaskOptions::default()).await
            .expect("key_points(vi) should succeed");
        assert_eq!(step3.task, Task::KeyPoints);
        assert!(!step3.output.is_empty());
        println!("Step 3 - Key Points (vi): {}", step3.output);

        // Step 4: Generate a document from the key points in Vietnamese
        let step4 = engine.generate_doc("Báo cáo quý", &step3.output, "vi", TaskOptions::default()).await
            .expect("generate_doc(vi) should succeed");
        assert_eq!(step4.task, Task::GenerateDoc);
        assert!(!step4.output.is_empty());
        println!("Step 4 - Generate Doc (vi): {}", step4.output);

        // Step 5: Generate slides from the document in Vietnamese
        let step5 = engine.generate_slides("Báo cáo quý", &step4.output, "vi", TaskOptions::default()).await
            .expect("generate_slides(vi) should succeed");
        assert_eq!(step5.task, Task::GenerateSlides);
        assert!(!step5.output.is_empty());
        println!("Step 5 - Generate Slides (vi): {}", step5.output);
    }

    /// Simulate a cross-language workflow: Arabic → English → Chinese
    #[tokio::test]
    async fn test_cross_language_workflow_ar_to_zh() {
        let (_tmp, mut engine) = setup_test_engine().await;
        let spec = ModelSpec::mt5_small_int8();
        engine.ensure_model(&spec).await.unwrap();

        // Step 1: Summarize Arabic text
        let arabic_text = "يغطي التقرير الفصلي ثلاثة مواضيع رئيسية: زيادة الإيرادات بنسبة 15% مدفوعة بخدمات السحابة، شحن فريق الهندسة 12 ميزة رئيسية، ووصول معدل الاحتفاظ بالعملاء إلى 92%. وافق الفريق على توظيف 8 مهندسين إضافيين في الربع الرابع.";
        let step1 = engine.summarize(arabic_text, "ar", TaskOptions::default()).await
            .expect("summarize(ar) should succeed");
        assert_eq!(step1.task, Task::Summarize);

        // Step 2: Translate Arabic summary to English
        let step2 = engine.translate(&step1.output, "ar", "en", TaskOptions::default()).await
            .expect("translate(ar→en) should succeed");
        assert_eq!(step2.task, Task::Translate);

        // Step 3: Translate English to Chinese
        let step3 = engine.translate(&step2.output, "en", "zh", TaskOptions::default()).await
            .expect("translate(en→zh) should succeed");
        assert_eq!(step3.task, Task::Translate);

        // Step 4: Generate slides from Chinese translation
        let step4 = engine.generate_slides("季度报告", &step3.output, "zh", TaskOptions::default()).await
            .expect("generate_slides(zh) should succeed");
        assert_eq!(step4.task, Task::GenerateSlides);
        assert!(!step4.output.is_empty());
    }

    /// Test all 6 languages in a round-robin summarization
    #[tokio::test]
    async fn test_all_languages_summarize_round_robin() {
        let (_tmp, mut engine) = setup_test_engine().await;
        let spec = ModelSpec::mt5_small_int8();
        engine.ensure_model(&spec).await.unwrap();

        for (lang, text) in MultilingualCorpus::summarize_inputs() {
            let result = engine.summarize(text, lang, TaskOptions::default()).await
                .expect(&format!("summarize({}) should succeed", lang));
            assert_eq!(result.task, Task::Summarize);
            assert!(result.adapter.is_some());
            let adapter = result.adapter.unwrap();
            assert!(adapter.contains(lang), "adapter should contain language {}", lang);
        }
    }

    /// Test model switching: mt5 → e5 → clip → mt5
    #[tokio::test]
    async fn test_model_switching_workflow() {
        let (_tmp, mut engine) = setup_test_engine().await;

        // Start with mt5 for summarization
        let mt5 = ModelSpec::mt5_small_int8();
        engine.ensure_model(&mt5).await.unwrap();
        let summary = engine.summarize("Test content for summarization", "en", TaskOptions::default()).await;
        assert!(summary.is_ok());

        // Switch to e5 for semantic search
        let e5 = ModelSpec::e5_small_int8();
        engine.ensure_model(&e5).await.unwrap();
        let search = engine.semantic_search("cloud computing", TaskOptions::default()).await;
        assert!(search.is_ok());

        // Switch to clip for image search
        let clip = ModelSpec::clip_int8();
        engine.ensure_model(&clip).await.unwrap();
        let img_search = engine.image_search("a cat on a mat", TaskOptions::default()).await;
        assert!(img_search.is_ok());

        // Switch back to mt5 for translation
        engine.ensure_model(&mt5).await.unwrap();
        let translation = engine.translate("Hello world", "en", "es", TaskOptions::default()).await;
        assert!(translation.is_ok());
    }

    /// Test governor enforcement blocks inference when paused
    #[tokio::test]
    async fn test_governor_blocks_when_paused() {
        let (_tmp, mut engine) = setup_test_engine().await;
        let spec = ModelSpec::mt5_small_int8();
        engine.ensure_model(&spec).await.unwrap();

        // Pause the governor — use Critical thermal since max_thermal_state is Critical
        engine.governor_mut().update_thermal(ThermalState::Critical);
        assert!(engine.governor().is_paused());

        // Inference should fail
        let result = engine.summarize("test", "en", TaskOptions::default()).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, ZkAiError::ResourceLimit(_)));
    }

    /// Test that streaming produces output for multiple languages
    #[tokio::test]
    async fn test_streaming_multilingual_output() {
        let (_tmp, mut engine) = setup_test_engine().await;
        let spec = ModelSpec::mt5_small_int8();
        engine.ensure_model(&spec).await.unwrap();

        let languages = ["en", "vi", "th", "ar", "zh", "es", "fr", "de", "ja", "ko"];
        for lang in &languages {
            let opts = TaskOptions { stream: true, ..Default::default() };
            let result = engine.summarize("Test content for streaming", lang, opts).await;
            assert!(result.is_ok(), "stream summarize({}) should succeed", lang);
            let result = result.unwrap();
            assert!(!result.output.is_empty(), "stream output should not be empty for {}", lang);
        }
    }
}

// ─── Decode Strategy Tests ─────────────────────────────────────────

#[cfg(test)]
mod decode_strategy {
    use super::*;

    #[test]
    fn test_decode_strategy_from_tier() {
        let high = DecodeStrategy::from_tier(&DeviceTier::HighEnd);
        assert!(matches!(high, DecodeStrategy::Beam { width: 4, .. }));

        let mid = DecodeStrategy::from_tier(&DeviceTier::MidRange);
        assert!(matches!(mid, DecodeStrategy::Nucleus { .. }));

        let low = DecodeStrategy::from_tier(&DeviceTier::LowEnd);
        assert!(matches!(low, DecodeStrategy::Greedy));

        let throttled = DecodeStrategy::from_tier(&DeviceTier::Throttled);
        assert!(matches!(throttled, DecodeStrategy::Greedy));
    }

    #[test]
    fn test_inference_config_from_profile() {
        let profile = DeviceProfile {
            tier: DeviceTier::HighEnd,
            acceleration: Acceleration::Metal,
            total_memory_mb: 16384,
            available_memory_mb: 12288,
            cpu_cores: 10,
            has_npu: true,
            npu_tops: Some(15),
            battery_level: Some(85),
            thermal_state: ThermalState::Nominal,
            platform: "macos".to_string(),
            arch: "aarch64".to_string(),
        };

        let config = InferenceConfig::from_profile(&profile);
        assert!(config.max_tokens > 0);
        assert!(matches!(config.decode_strategy, DecodeStrategy::Beam { .. }));
        assert!(config.use_gpu);
        assert!(config.use_npu);
    }
}
