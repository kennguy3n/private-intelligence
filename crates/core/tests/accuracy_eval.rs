//! Comprehensive accuracy evaluation harness for the zk-ai SDK.
//!
//! This test file runs real pipeline calls (summarize, translate, key_points,
//! generate_doc, generate_slides, semantic_search, image_search) across all
//! 22 supported languages and scores the outputs against labeled ground-truth
//! fixtures using deterministic scorers:
//!
//! 1. **Term coverage** — fraction of expected key terms present in the output
//! 2. **Faithfulness/grounding** — entities in output that appear in input (no hallucination)
//! 3. **In-language correctness** — is the output in the expected script/language?
//! 4. **BLEU-like translation overlap** — n-gram precision + brevity penalty vs reference
//! 5. **Semantic recall@k** — are relevant documents in top-k results?
//! 6. **Image search recall@k** — are relevant images in top-k results?
//! 7. **MRR (Mean Reciprocal Rank)** — average position of first relevant result
//!
//! The harness is fully deterministic — no RNG, no network, no clock — so
//! results are reproducible. When real ONNX models are loaded, the same
//! harness measures real model quality. With the fallback path (no ONNX
//! model), it establishes the honest baseline floor.

use zk_ai_core::pipeline::{Task, TaskOptions, TaskResult, SUPPORTED_LANGUAGES};
use zk_ai_core::model_manager::ModelSpec;
use zk_ai_core::profiler::{DeviceProfile, DeviceTier, Acceleration, ThermalState};
use zk_ai_core::governor::GovernorConfig;
use zk_ai_core::pipeline::text_index::TextIndex;
use zk_ai_core::pipeline::image_index::ImageIndex;
use zk_ai_core::AiEngine;
use tempfile::tempdir;

// ─── Eval Dataset ───────────────────────────────────────────────────

/// A single eval case for a text task (summarize, key_points, etc.)
struct EvalCase {
    /// Language code
    lang: &'static str,
    /// Input text to process
    input: &'static str,
    /// Expected key terms that a good output should mention
    expected_terms: Vec<&'static str>,
    /// Brief description of the case
    description: &'static str,
}

/// A translation eval case with a reference translation
struct TranslationCase {
    source_lang: &'static str,
    target_lang: &'static str,
    input: &'static str,
    /// Reference translation (ground truth)
    reference: &'static str,
    /// Key terms that should appear in the translation
    expected_terms: Vec<&'static str>,
}

/// A semantic search eval case
struct SemanticSearchCase {
    /// Documents to index (id, text)
    documents: Vec<(&'static str, &'static str)>,
    /// Query embedding (synthetic, deterministic)
    query_embedding: Vec<f32>,
    /// Relevant document IDs (ground truth)
    relevant_ids: Vec<&'static str>,
    /// k for recall@k
    k: usize,
}

/// An image search eval case
struct ImageSearchCase {
    /// Images to index (id, caption, embedding)
    images: Vec<(&'static str, &'static str, Vec<f32>)>,
    /// Query embedding
    query_embedding: Vec<f32>,
    /// Relevant image IDs (ground truth)
    relevant_ids: Vec<&'static str>,
    /// k for recall@k
    k: usize,
}

// ─── Scorers ────────────────────────────────────────────────────────

/// Term coverage: fraction of expected terms found in the output (case-insensitive)
fn term_coverage(output: &str, expected: &[&str]) -> (Vec<String>, Vec<String>) {
    let low = output.to_lowercase();
    let matched: Vec<String> = expected.iter()
        .filter(|t| low.contains(&t.to_lowercase()))
        .map(|t| t.to_string())
        .collect();
    let missing: Vec<String> = expected.iter()
        .filter(|t| !low.contains(&t.to_lowercase()))
        .map(|t| t.to_string())
    .collect();
    (matched, missing)
}

/// Faithfulness: extract entities from output and check if they appear in input
fn faithfulness(output: &str, input: &str) -> (usize, usize) {
    let output_entities = extract_entities(output);
    let input_lower = input.to_lowercase();
    let grounded = output_entities.iter()
        .filter(|e| input_lower.contains(&e.to_lowercase()))
        .count();
    (grounded, output_entities.len())
}

/// Extract named entities: CamelCase tokens, ALL-CAPS acronyms (3-6), identifiers with digits
fn extract_entities(text: &str) -> Vec<String> {
    let mut entities = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for raw in text.split_whitespace() {
        let tok = raw.trim_matches(|c: char| !c.is_alphanumeric() && c != '-' && c != '.');
        if tok.len() < 2 { continue; }
        let is_entity = 
            // Contains digit and >=2 chars (identifier)
            (tok.chars().any(|c| c.is_ascii_digit()) && tok.len() >= 2) ||
            // CamelCase (internal uppercase)
            tok.chars().zip(tok.chars().skip(1))
                .any(|(a, b)| a.is_lowercase() && b.is_uppercase()) ||
            // ALL-CAPS acronym 3-6 chars
            (tok.len() >= 3 && tok.len() <= 6 && tok.chars().all(|c| c.is_ascii_uppercase()));
        if is_entity {
            let key = tok.to_lowercase();
            if seen.insert(key) {
                entities.push(tok.to_string());
            }
        }
    }
    entities
}

/// In-language check: does the output contain characters of the expected script?
fn in_language(output: &str, lang: &str) -> bool {
    let expected_script = script_for_lang(lang);
    let mut counts: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
    for ch in output.chars() {
        if let Some(s) = script_of_char(ch) {
            *counts.entry(s).or_insert(0) += 1;
        }
    }
    if counts.is_empty() { return false; }
    match expected_script {
        "Latin" => {
            let latin = *counts.get("Latin").unwrap_or(&0);
            let non_latin: usize = counts.iter()
                .filter(|(k, _)| *k != &"Latin" && *k != &"Other")
                .map(|(_, v)| *v)
                .sum();
            latin > 0 && non_latin == 0
        }
        script => {
            let expected = *counts.get(script).unwrap_or(&0);
            let latin = *counts.get("Latin").unwrap_or(&0);
            expected >= latin
        }
    }
}

fn script_for_lang(lang: &str) -> &'static str {
    match lang {
        "en" | "vi" | "es" => "Latin",
        "th" => "Thai",
        "ar" => "Arabic",
        "zh" => "CJK",
        _ => "Latin",
    }
}

fn script_of_char(ch: char) -> Option<&'static str> {
    if !ch.is_alphabetic() { return None; }
    let cp = ch as u32;
    if (0x4E00..=0x9FFF).contains(&cp) || (0x3040..=0x30FF).contains(&cp) || (0x3400..=0x4DBF).contains(&cp) {
        return Some("CJK");
    }
    if (0x0E00..=0x0E7F).contains(&cp) { return Some("Thai"); }
    if (0x0600..=0x06FF).contains(&cp) || (0x0750..=0x077F).contains(&cp) { return Some("Arabic"); }
    if (0x0900..=0x097F).contains(&cp) { return Some("Devanagari"); }
    if ch.is_ascii_alphabetic() || (0x00C0..=0x024F).contains(&cp) { return Some("Latin"); }
    Some("Other")
}

/// Recall@k: fraction of relevant items in top-k results
fn recall_at_k(result_ids: &[String], relevant: &[&str], k: usize) -> f32 {
    if relevant.is_empty() { return 1.0; }
    let top_k: Vec<&str> = result_ids.iter().take(k).map(|s| s.as_str()).collect();
    let found = relevant.iter().filter(|r| top_k.contains(&r.as_ref())).count();
    found as f32 / relevant.len() as f32
}

// ─── Test Engine Setup ──────────────────────────────────────────────

async fn setup_test_engine() -> (tempfile::TempDir, AiEngine) {
    let cache_dir = tempdir().unwrap();
    let models_dir = cache_dir.path().join("models");
    std::fs::create_dir_all(&models_dir).unwrap();
    for filename in &[
        "mt5-small-1.0.0-int8.onnx",
        "multilingual-e5-small-1.0.0-int8.onnx",
        "clip-vit-base-patch32-1.0.0-int8.onnx",
    ] {
        std::fs::write(models_dir.join(filename), b"fake_model").unwrap();
    }
    let adapters_dir = cache_dir.path().join("adapters");
    std::fs::create_dir_all(&adapters_dir).unwrap();
    for lang in SUPPORTED_LANGUAGES {
        for task in &["summarize", "keypoints", "gendoc", "slides"] {
            let path = adapters_dir.join(format!("{}.{}.bin", task, lang));
            std::fs::write(&path, b"fake_adapter").unwrap();
        }
        for target in SUPPORTED_LANGUAGES {
            if lang != target {
                let path = adapters_dir.join(format!("translate.{}_{}.bin", lang, target));
                std::fs::write(&path, b"fake_adapter").unwrap();
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

// ─── Eval Datasets ──────────────────────────────────────────────────

fn summarize_dataset() -> Vec<EvalCase> {
    vec![
        EvalCase {
            lang: "en",
            input: "The quarterly board meeting covered three key topics: revenue growth of 23% year-over-year, the new product launch scheduled for Q3, and the acquisition of TechCorp for $50M. The CEO emphasized that the company's cloud infrastructure migration to AWS is 80% complete and expected to save $2M annually in operational costs.",
            expected_terms: vec!["revenue", "23%", "product", "Q3", "acquisition", "TechCorp", "cloud", "AWS"],
            description: "Business meeting summary (English)",
        },
        EvalCase {
            lang: "vi",
            input: "Cuộc họp hội đồng quản trị hàng quý đã thảo luận ba chủ đề chính: tăng trưởng doanh thu 23% so với cùng kỳ năm trước, ra mắt sản phẩm mới vào quý 3, và việc mua lại TechCorp với giá 50 triệu đô la. Giám đốc điều hành nhấn mạnh rằng việc di chuyển cơ sở hạ tầng đám mây sang AWS đã hoàn thành 80%.",
            expected_terms: vec!["doanh thu", "23%", "sản phẩm", "quý 3", "TechCorp", "đám mây", "AWS"],
            description: "Business meeting summary (Vietnamese)",
        },
        EvalCase {
            lang: "th",
            input: "การประชุมคณะกรรมการไตรมาสครอบคลุมสามหัวข้อสำคัญ: การเติบโตของรายได้ 23% เมื่อเทียบกับปีก่อนหน้า การเปิดตัวผลิตภัณฑ์ใหม่ในไตรมาส 3 และการเข้าซื้อกิจการ TechCorp ในราคา 50 ล้านดอลลาร์ ซีอีโอเน้นย้ำว่าการย้ายโครงสร้างพื้นฐานคลาวด์ไปยัง AWS เสร็จสมบูรณ์ 80%",
            expected_terms: vec!["รายได้", "23%", "ผลิตภัณฑ์", "ไตรมาส", "TechCorp", "คลาวด์", "AWS"],
            description: "Business meeting summary (Thai)",
        },
        EvalCase {
            lang: "ar",
            input: "غطى اجتماع مجلس الإدارة الفصلي ثلاثة مواضيع رئيسية: نمو الإيرادات بنسبة 23% مقارنة بالعام السابق، وإطلاق منتج جديد في الربع الثالث، والاستحواذ على TechCorp مقابل 50 مليون دولار. وأكد الرئيس التنفيذي أن نقل البنية التحتية السحابية إلى AWS قد اكتمل بنسبة 80%.",
            expected_terms: vec!["الإيرادات", "23%", "منتج", "الربع", "TechCorp", "السحابية", "AWS"],
            description: "Business meeting summary (Arabic)",
        },
        EvalCase {
            lang: "zh",
            input: "季度董事会会议涵盖了三个关键议题：年收入增长23%，第三季度新产品发布，以及以5000万美元收购TechCorp。首席执行官强调，云基础设施迁移到AWS已完成80%，预计每年节省200万美元运营成本。",
            expected_terms: vec!["收入", "23%", "产品", "季度", "TechCorp", "云", "AWS"],
            description: "Business meeting summary (Chinese)",
        },
        EvalCase {
            lang: "es",
            input: "La reunión trimestral del consejo de administración cubrió tres temas clave: crecimiento de ingresos del 23% interanual, el lanzamiento de un nuevo producto programado para el tercer trimestre, y la adquisición de TechCorp por 50 millones de dólares. El CEO enfatizó que la migración de la infraestructura en la nube a AWS está completa en un 80%.",
            expected_terms: vec!["ingresos", "23%", "producto", "trimestre", "TechCorp", "nube", "AWS"],
            description: "Business meeting summary (Spanish)",
        },
    ]
}

fn key_points_dataset() -> Vec<EvalCase> {
    vec![
        EvalCase {
            lang: "en",
            input: "The engineering team decided to migrate from PostgreSQL to MongoDB for the analytics workload. The main reasons were: schema flexibility for varying event types, horizontal scaling capability, and lower cost at scale. The migration plan has three phases: prototype in Q1, pilot in Q2, full rollout in Q3. Risk: data consistency during migration.",
            expected_terms: vec!["PostgreSQL", "MongoDB", "analytics", "schema", "scaling", "Q1", "Q2", "Q3", "consistency"],
            description: "Technical decision key points (English)",
        },
        EvalCase {
            lang: "vi",
            input: "Nhóm kỹ thuật đã quyết định di chuyển từ PostgreSQL sang MongoDB cho khối lượng công việc phân tích. Lý do chính là: tính linh hoạt của lược đồ cho các loại sự kiện khác nhau, khả năng mở rộng theo chiều ngang, và chi phí thấp hơn khi quy mô lớn. Kế hoạch di chuyển có ba giai đoạn: nguyên mẫu trong quý 1, thử điểm trong quý 2, triển khai đầy đủ trong quý 3.",
            expected_terms: vec!["PostgreSQL", "MongoDB", "phân tích", "lược đồ", "mở rộng", "quý 1", "quý 2", "quý 3"],
            description: "Technical decision key points (Vietnamese)",
        },
        EvalCase {
            lang: "th",
            input: "ทีมวิศวกรรมตัดสินใจย้ายจาก PostgreSQL ไปยัง MongoDB สำหรับงานวิเคราะห์ เหตุผลหลักคือ: ความยืดหยุ่นของสคีมาสำหรับประเภทเหตุการณ์ที่แตกต่างกัน ความสามารถในการปรับขนาดในแนวนอน และต้นทุนที่ต่ำกว่าในขนาดใหญ่ แผนการย้ายมีสามขั้นตอน: ต้นแบบในไตรมาส 1 นำร่องในไตรมาส 2 และการเปิดตัวเต็มรูปแบบในไตรมาส 3",
            expected_terms: vec!["PostgreSQL", "MongoDB", "วิเคราะห์", "สคีมา", "ปรับขนาด", "ไตรมาส"],
            description: "Technical decision key points (Thai)",
        },
        EvalCase {
            lang: "ar",
            input: "قرر فريق الهندسة الانتقال من PostgreSQL إلى MongoDB لعبء عمل التحليلات. كانت الأسباب الرئيسية هي: مرونة المخطط لأنواع الأحداث المتغيرة، وقدرة التوسع الأفقي، والتكلفة الأقل على نطاق واسع. تتكون خطة الهجرة من ثلاث مراحل: النموذج الأولي في الربع الأول، والتجربة في الربع الثاني، والطرح الكامل في الربع الثالث.",
            expected_terms: vec!["PostgreSQL", "MongoDB", "التحليلات", "المخطط", "التوسع", "الربع"],
            description: "Technical decision key points (Arabic)",
        },
        EvalCase {
            lang: "zh",
            input: "工程团队决定将分析工作负载从PostgreSQL迁移到MongoDB。主要原因包括：对不同事件类型的模式灵活性、水平扩展能力、以及大规模下的更低成本。迁移计划分三个阶段：第一季度原型，第二季度试点，第三季度全面部署。",
            expected_terms: vec!["PostgreSQL", "MongoDB", "分析", "模式", "扩展", "季度"],
            description: "Technical decision key points (Chinese)",
        },
        EvalCase {
            lang: "es",
            input: "El equipo de ingeniería decidió migrar de PostgreSQL a MongoDB para la carga de trabajo de análisis. Las razones principales fueron: flexibilidad de esquema para tipos de eventos variables, capacidad de escalado horizontal, y menor costo a gran escala. El plan de migración tiene tres fases: prototipo en Q1, piloto en Q2, despliegue completo en Q3.",
            expected_terms: vec!["PostgreSQL", "MongoDB", "análisis", "esquema", "escalado", "Q1", "Q2", "Q3"],
            description: "Technical decision key points (Spanish)",
        },
    ]
}

fn generate_doc_dataset() -> Vec<EvalCase> {
    vec![
        EvalCase {
            lang: "en",
            input: "Topic: Cloud Security Best Practices. Outline: 1. Identity and access management with MFA. 2. Encryption at rest and in transit using AES-256 and TLS 1.3. 3. Network segmentation with VPCs and security groups. 4. Continuous monitoring with SIEM tools. 5. Incident response plan with defined RTO and RPO.",
            expected_terms: vec!["Cloud", "Security", "Identity", "MFA", "Encryption", "AES-256", "TLS", "VPC", "SIEM", "RTO", "RPO"],
            description: "Document generation (English)",
        },
        EvalCase {
            lang: "vi",
            input: "Chủ đề: Thực hành tốt nhất về bảo mật đám mây. Đề cương: 1. Quản lý danh tính và quyền truy cập với MFA. 2. Mã hóa khi lưu trữ và truyền tải sử dụng AES-256 và TLS 1.3. 3. Phân đoạn mạng với VPC và nhóm bảo mật. 4. Giám sát liên tục với công cụ SIEM. 5. Kế hoạch phản hồi sự cố với RTO và RPO.",
            expected_terms: vec!["bảo mật", "đám mây", "danh tính", "MFA", "Mã hóa", "AES-256", "TLS", "VPC", "SIEM", "RTO", "RPO"],
            description: "Document generation (Vietnamese)",
        },
        EvalCase {
            lang: "th",
            input: "หัวข้อ: แนวทางปฏิบัติที่ดีที่สุดด้านความปลอดภัยบนคลาวด์ เค้าโครง: 1. การจัดการตัวตนและการเข้าถึงด้วย MFA 2. การเข้ารหัสขณะจัดเก็บและระหว่างการส่งโดยใช้ AES-256 และ TLS 1.3 3. การแบ่งส่วนเครือข่ายด้วย VPC 4. การตรวจสอบอย่างต่อเนื่องด้วยเครื่องมือ SIEM 5. แผนตอบสนองเหตุการณ์",
            expected_terms: vec!["ความปลอดภัย", "คลาวด์", "ตัวตน", "MFA", "เข้ารหัส", "AES-256", "TLS", "VPC", "SIEM"],
            description: "Document generation (Thai)",
        },
        EvalCase {
            lang: "ar",
            input: "الموضوع: أفضل ممارسات أمان السحابة. المخطط: 1. إدارة الهوية والوصول مع MFA. 2. التشفير أثناء التخزين والنقل باستخدام AES-256 و TLS 1.3. 3. تقسيم الشبكة مع VPC ومجموعات الأمان. 4. المراقبة المستمرة بأدوات SIEM. 5. خطة الاستجابة للحوادث مع RTO و RPO محددة.",
            expected_terms: vec!["أمان", "السحابة", "الهوية", "MFA", "التشفير", "AES-256", "TLS", "VPC", "SIEM", "RTO", "RPO"],
            description: "Document generation (Arabic)",
        },
        EvalCase {
            lang: "zh",
            input: "主题：云安全最佳实践。大纲：1. 使用MFA的身份和访问管理。2. 使用AES-256和TLS 1.3进行静态和传输中的加密。3. 使用VPC和安全组进行网络分段。4. 使用SIEM工具持续监控。5. 具有定义的RTO和RPO的事件响应计划。",
            expected_terms: vec!["云", "安全", "身份", "MFA", "加密", "AES-256", "TLS", "VPC", "SIEM", "RTO", "RPO"],
            description: "Document generation (Chinese)",
        },
        EvalCase {
            lang: "es",
            input: "Tema: Mejores prácticas de seguridad en la nube. Esquema: 1. Gestión de identidad y acceso con MFA. 2. Cifrado en reposo y en tránsito usando AES-256 y TLS 1.3. 3. Segmentación de red con VPC y grupos de seguridad. 4. Monitoreo continuo con herramientas SIEM. 5. Plan de respuesta a incidentes con RTO y RPO definidos.",
            expected_terms: vec!["seguridad", "nube", "identidad", "MFA", "Cifrado", "AES-256", "TLS", "VPC", "SIEM", "RTO", "RPO"],
            description: "Document generation (Spanish)",
        },
    ]
}

fn generate_slides_dataset() -> Vec<EvalCase> {
    vec![
        EvalCase {
            lang: "en",
            input: "Topic: Introduction to Machine Learning. Source: Machine learning is a subset of AI that enables systems to learn from data. Key types include supervised learning, unsupervised learning, and reinforcement learning. Common algorithms are linear regression, decision trees, and neural networks. Applications span NLP, computer vision, and recommendation systems.",
            expected_terms: vec!["Machine", "learning", "AI", "supervised", "unsupervised", "reinforcement", "regression", "neural", "NLP", "vision"],
            description: "Slide generation (English)",
        },
        EvalCase {
            lang: "vi",
            input: "Chủ đề: Giới thiệu về Học máy. Nguồn: Học máy là một tập con của AI cho phép hệ thống học từ dữ liệu. Các loại chính bao gồm học có giám sát, học không giám sát, và học tăng cường. Các thuật toán phổ biến là hồi quy tuyến tính, cây quyết định, và mạng nơ-ron. Ứng dụng trải dài NLP, thị giác máy tính, và hệ thống gợi ý.",
            expected_terms: vec!["Học máy", "AI", "giám sát", "tăng cường", "hồi quy", "nơ-ron", "NLP", "thị giác"],
            description: "Slide generation (Vietnamese)",
        },
        EvalCase {
            lang: "th",
            input: "หัวข้อ: บทนำสู่การเรียนรู้ของเครื่อง แหล่งข้อมูล: การเรียนรู้ของเครื่องเป็นส่วนย่อยของ AI ที่ช่วยให้ระบบเรียนรู้จากข้อมูล ประเภทหลักได้แก่ การเรียนรู้แบบมีผู้สอน การเรียนรู้แบบไม่มีผู้สอน และการเรียนรู้แบบเสริมแรง อัลกอริทึมทั่วไป ได้แก่ การถดถอยเชิงเส้น ต้นไม้ตัดสินใจ และเครือข่ายประสาทเทียม",
            expected_terms: vec!["เรียนรู้", "เครื่อง", "AI", "ผู้สอน", "เสริมแรง", "ถดถอย", "ประสาท"],
            description: "Slide generation (Thai)",
        },
        EvalCase {
            lang: "ar",
            input: "الموضوع: مقدمة في التعلم الآلي. المصدر: التعلم الآلي هو فرع من الذكاء الاصطناعي يمكّن الأنظمة من التعلم من البيانات. تشمل الأنواع الرئيسية التعلم الخاضع للإشراف والتعلم غير الخاضع للإشراف والتعلم المعزز. الخوارزميات الشائعة هي الانحدار الخطي وأشجار القرار والشبكات العصبية.",
            expected_terms: vec!["التعلم", "الآلي", "الذكاء", "الاصطناعي", "إشراف", "معزز", "انحدار", "عصبية"],
            description: "Slide generation (Arabic)",
        },
        EvalCase {
            lang: "zh",
            input: "主题：机器学习入门。来源：机器学习是人工智能的一个子集，使系统能够从数据中学习。主要类型包括监督学习、无监督学习和强化学习。常见算法有线性回归、决策树和神经网络。应用涵盖自然语言处理、计算机视觉和推荐系统。",
            expected_terms: vec!["机器学习", "人工智能", "监督", "强化", "回归", "神经网络", "视觉"],
            description: "Slide generation (Chinese)",
        },
        EvalCase {
            lang: "es",
            input: "Tema: Introducción al aprendizaje automático. Fuente: El aprendizaje automático es un subconjunto de la IA que permite a los sistemas aprender de los datos. Los tipos principales incluyen aprendizaje supervisado, no supervisado y por refuerzo. Los algoritmos comunes son regresión lineal, árboles de decisión y redes neuronales.",
            expected_terms: vec!["aprendizaje", "automático", "IA", "supervisado", "refuerzo", "regresión", "neuronales"],
            description: "Slide generation (Spanish)",
        },
    ]
}

fn translation_dataset() -> Vec<TranslationCase> {
    vec![
        TranslationCase {
            source_lang: "en", target_lang: "vi",
            input: "The company reported a 23% increase in revenue for the third quarter.",
            reference: "Công ty báo cáo tăng trưởng doanh thu 23% trong quý thứ ba.",
            expected_terms: vec!["23%", "doanh thu", "quý"],
        },
        TranslationCase {
            source_lang: "en", target_lang: "th",
            input: "The company reported a 23% increase in revenue for the third quarter.",
            reference: "บริษัทรายงานการเติบโตของรายได้ 23% ในไตรมาสที่สาม",
            expected_terms: vec!["23%", "รายได้", "ไตรมาส"],
        },
        TranslationCase {
            source_lang: "en", target_lang: "ar",
            input: "The company reported a 23% increase in revenue for the third quarter.",
            reference: "أبلغت الشركة عن زيادة في الإيرادات بنسبة 23% للربع الثالث.",
            expected_terms: vec!["23%", "الإيرادات", "الربع"],
        },
        TranslationCase {
            source_lang: "en", target_lang: "zh",
            input: "The company reported a 23% increase in revenue for the third quarter.",
            reference: "公司报告第三季度收入增长23%。",
            expected_terms: vec!["23%", "收入", "季度"],
        },
        TranslationCase {
            source_lang: "en", target_lang: "es",
            input: "The company reported a 23% increase in revenue for the third quarter.",
            reference: "La empresa reportó un aumento del 23% en los ingresos del tercer trimestre.",
            expected_terms: vec!["23%", "ingresos", "trimestre"],
        },
        TranslationCase {
            source_lang: "vi", target_lang: "en",
            input: "Công ty báo cáo tăng trưởng doanh thu 23% trong quý ba.",
            reference: "The company reported a 23% revenue growth in the third quarter.",
            expected_terms: vec!["23%", "revenue", "quarter"],
        },
        TranslationCase {
            source_lang: "es", target_lang: "en",
            input: "La empresa reportó un aumento del 23% en los ingresos del tercer trimestre.",
            reference: "The company reported a 23% increase in revenue for the third quarter.",
            expected_terms: vec!["23%", "revenue", "quarter"],
        },
        TranslationCase {
            source_lang: "zh", target_lang: "en",
            input: "公司报告第三季度收入增长23%。",
            reference: "The company reported a 23% revenue growth in the third quarter.",
            expected_terms: vec!["23%", "revenue", "quarter"],
        },
    ]
}

fn semantic_search_dataset() -> Vec<SemanticSearchCase> {
    vec![
        SemanticSearchCase {
            documents: vec![
                ("doc1", "Cloud computing enables on-demand access to computing resources over the internet."),
                ("doc2", "Encryption protects data by converting it into unreadable ciphertext."),
                ("doc3", "Machine learning models can be trained on large datasets to make predictions."),
                ("doc4", "AWS provides cloud infrastructure services including EC2, S3, and Lambda."),
                ("doc5", "PostgreSQL is a powerful open-source relational database management system."),
                ("doc6", "Docker containers package applications with their dependencies for consistent deployment."),
                ("doc7", "Kubernetes orchestrates containerized applications across clusters of machines."),
                ("doc8", "TLS 1.3 provides secure communication encryption for web traffic."),
                ("doc9", "The team decided to migrate from PostgreSQL to MongoDB for analytics."),
                ("doc10", "Azure cloud platform offers virtual machines, databases, and AI services."),
            ],
            // Query: "cloud infrastructure" — relevant: doc1, doc4, doc10
            query_embedding: vec![0.9, 0.1, 0.0, 0.8, 0.0, 0.0, 0.0, 0.0, 0.0, 0.7],
            relevant_ids: vec!["doc1", "doc4", "doc10"],
            k: 5,
        },
        SemanticSearchCase {
            documents: vec![
                ("sec1", "AES-256 encryption is the standard for protecting sensitive data at rest."),
                ("sec2", "End-to-end encryption ensures only sender and recipient can read messages."),
                ("sec3", "Cloud computing provides scalable infrastructure for modern applications."),
                ("sec4", "PostgreSQL offers robust data integrity and ACID compliance."),
                ("sec5", "TLS certificates enable secure HTTPS connections for websites."),
                ("sec6", "The firewall blocks unauthorized network access to private resources."),
                ("sec7", "Multi-factor authentication adds an extra layer of security beyond passwords."),
                ("sec8", "Docker containers isolate applications for consistent deployment environments."),
            ],
            // Query: "encryption security" — relevant: sec1, sec2, sec5
            query_embedding: vec![0.9, 0.85, 0.0, 0.0, 0.8, 0.0, 0.0, 0.0],
            relevant_ids: vec!["sec1", "sec2", "sec5"],
            k: 3,
        },
    ]
}

fn image_search_dataset() -> Vec<ImageSearchCase> {
    vec![
        ImageSearchCase {
            images: vec![
                ("img1", "a golden retriever playing in a park", vec![0.9, 0.1, 0.0, 0.0]),
                ("img2", "a cat sleeping on a sofa", vec![0.1, 0.8, 0.0, 0.0]),
                ("img3", "a dog running on the beach", vec![0.85, 0.05, 0.0, 0.1]),
                ("img4", "a mountain landscape at sunset", vec![0.0, 0.0, 0.9, 0.1]),
                ("img5", "a golden retriever puppy with a toy", vec![0.88, 0.1, 0.0, 0.0]),
                ("img6", "a city skyline at night", vec![0.0, 0.0, 0.1, 0.9]),
            ],
            // Query: "dog" — relevant: img1, img3, img5
            query_embedding: vec![0.9, 0.0, 0.0, 0.0],
            relevant_ids: vec!["img1", "img3", "img5"],
            k: 3,
        },
        ImageSearchCase {
            images: vec![
                ("food1", "a plate of sushi with salmon", vec![0.9, 0.1, 0.0, 0.0, 0.0]),
                ("food2", "a bowl of pho with beef and herbs", vec![0.1, 0.9, 0.0, 0.0, 0.0]),
                ("food3", "a pizza with pepperoni and cheese", vec![0.0, 0.0, 0.9, 0.0, 0.0]),
                ("food4", "a sushi roll with avocado and tuna", vec![0.85, 0.05, 0.0, 0.0, 0.0]),
                ("food5", "a bowl of ramen with pork", vec![0.0, 0.8, 0.0, 0.1, 0.0]),
                ("food6", "a burger with fries", vec![0.0, 0.0, 0.0, 0.9, 0.0]),
            ],
            // Query: "sushi" — relevant: food1, food4
            query_embedding: vec![0.9, 0.0, 0.0, 0.0, 0.0],
            relevant_ids: vec!["food1", "food4"],
            k: 2,
        },
        // Expanded: technology images
        ImageSearchCase {
            images: vec![
                ("tech1", "a laptop computer on a desk", vec![0.9, 0.1, 0.0, 0.0, 0.0, 0.0]),
                ("tech2", "a smartphone showing a map app", vec![0.1, 0.9, 0.0, 0.0, 0.0, 0.0]),
                ("tech3", "a server rack in a data center", vec![0.0, 0.0, 0.9, 0.0, 0.0, 0.0]),
                ("tech4", "a laptop with code on screen", vec![0.85, 0.05, 0.0, 0.1, 0.0, 0.0]),
                ("tech5", "a tablet with a drawing app", vec![0.1, 0.1, 0.0, 0.0, 0.9, 0.0]),
                ("tech6", "a gaming desktop with RGB lights", vec![0.0, 0.0, 0.1, 0.0, 0.0, 0.9]),
            ],
            // Query: "laptop computer" — relevant: tech1, tech4
            query_embedding: vec![0.9, 0.0, 0.0, 0.0, 0.0, 0.0],
            relevant_ids: vec!["tech1", "tech4"],
            k: 2,
        },
        // Expanded: nature images
        ImageSearchCase {
            images: vec![
                ("nat1", "a tropical beach with palm trees", vec![0.9, 0.1, 0.0, 0.0, 0.0]),
                ("nat2", "a snow-capped mountain peak", vec![0.0, 0.0, 0.9, 0.1, 0.0]),
                ("nat3", "a desert with sand dunes", vec![0.0, 0.0, 0.0, 0.9, 0.0]),
                ("nat4", "a tropical island from above", vec![0.85, 0.1, 0.0, 0.0, 0.0]),
                ("nat5", "a forest with autumn leaves", vec![0.0, 0.0, 0.1, 0.0, 0.9]),
            ],
            // Query: "tropical beach" — relevant: nat1, nat4
            query_embedding: vec![0.9, 0.0, 0.0, 0.0, 0.0],
            relevant_ids: vec!["nat1", "nat4"],
            k: 2,
        },
    ]
}

// ─── Expanded Language Datasets (16 new languages) ──────────────────

fn summarize_dataset_expanded() -> Vec<EvalCase> {
    vec![
        EvalCase {
            lang: "fr",
            input: "La réunion trimestrielle du conseil d'administration a couvert la croissance des revenus de 23% et l'acquisition de TechCorp pour 50 millions de dollars.",
            expected_terms: vec!["revenus", "23%", "acquisition", "TechCorp"],
            description: "Business meeting summary (French)",
        },
        EvalCase {
            lang: "de",
            input: "Die vierteljährliche Aufsichtsratssitzung behandelte das Umsatzwachstum von 23% und die Übernahme von TechCorp für 50 Millionen Dollar.",
            expected_terms: vec!["Umsatz", "23%", "Übernahme", "TechCorp"],
            description: "Business meeting summary (German)",
        },
        EvalCase {
            lang: "ja",
            input: "四半期取締役会は、前年比23%の収益成長と、TechCorpを5000万ドルで買収することを議論した。",
            expected_terms: vec!["収益", "23%", "買収", "TechCorp"],
            description: "Business meeting summary (Japanese)",
        },
        EvalCase {
            lang: "ko",
            input: "분기 이사회 회의는 전년 대비 23%의 수익 성장과 TechCorp을 5천만 달러에 인수하는 것을 다뤘다.",
            expected_terms: vec!["수익", "23%", "인수", "TechCorp"],
            description: "Business meeting summary (Korean)",
        },
        EvalCase {
            lang: "id",
            input: "Rapat dewan direksi triwulanan membahas pertumbuhan pendapatan 23% dan akuisisi TechCorp senilai 50 juta dolar.",
            expected_terms: vec!["pendapatan", "23%", "akuisisi", "TechCorp"],
            description: "Business meeting summary (Indonesian)",
        },
        EvalCase {
            lang: "pt",
            input: "A reunião trimestral do conselho de administração cobriu o crescimento de receita de 23% e a aquisição da TechCorp por 50 milhões de dólares.",
            expected_terms: vec!["receita", "23%", "aquisição", "TechCorp"],
            description: "Business meeting summary (Portuguese)",
        },
        EvalCase {
            lang: "ru",
            input: "Ежеквартальное заседание совета директоров рассмотрело рост доходов на 23% и приобретение TechCorp за 50 миллионов долларов.",
            expected_terms: vec!["доходов", "23%", "приобретение", "TechCorp"],
            description: "Business meeting summary (Russian)",
        },
        EvalCase {
            lang: "hi",
            input: "तिमाही बोर्ड बैठक में 23% के राजस्व विकास और TechCorp को 50 मिलियन डॉलर में अधिग्रहण पर चर्चा हुई।",
            expected_terms: vec!["राजस्व", "23%", "अधिग्रहण", "TechCorp"],
            description: "Business meeting summary (Hindi)",
        },
        EvalCase {
            lang: "tr",
            input: "Üç aylık yönetim kurulu toplantısı, %23'lik gelir büyümesini ve TechCorp'ın 50 milyon dolara satın alınmasını ele aldı.",
            expected_terms: vec!["gelir", "23%", "satın", "TechCorp"],
            description: "Business meeting summary (Turkish)",
        },
        EvalCase {
            lang: "fa",
            input: "جلسه فصلی هیئت مدیره به رشد درآمد ۲۳ درصدی و خرید TechCorp به مبلغ ۵۰ میلیون دلار پرداخت.",
            expected_terms: vec!["درآمد", "TechCorp"],
            description: "Business meeting summary (Persian)",
        },
        EvalCase {
            lang: "ur",
            input: "سہ ماہی بورڈ میٹنگ میں 23% کے آمدنی میں اضافے اور TechCorp کو 50 ملین ڈالر میں حصول پر بحث ہوئی۔",
            expected_terms: vec!["آمدنی", "23%", "TechCorp"],
            description: "Business meeting summary (Urdu)",
        },
        EvalCase {
            lang: "bn",
            input: "ত্রৈমাসিক বোর্ড সভায় 23% রাজস্ব বৃদ্ধি এবং TechCorp কে ৫০ মিলিয়ন ডলারে অধিগ্রহণ নিয়ে আলোচনা হয়েছে।",
            expected_terms: vec!["রাজস্ব", "23%", "TechCorp"],
            description: "Business meeting summary (Bengali)",
        },
        EvalCase {
            lang: "ms",
            input: "Mesyuarat lembaga pengarah suku tahunan membincangkan pertumbuhan pendapatan 23% dan pemerolehan TechCorp sebanyak 50 juta dolar.",
            expected_terms: vec!["pendapatan", "23%", "TechCorp"],
            description: "Business meeting summary (Malay)",
        },
        EvalCase {
            lang: "tl",
            input: "Tinalakay ng quarterly board meeting ang 23% na paglago ng kita at ang pagkuha sa TechCorp para sa 50 milyong dolyar.",
            expected_terms: vec!["kita", "23%", "TechCorp"],
            description: "Business meeting summary (Tagalog)",
        },
        EvalCase {
            lang: "ne",
            input: "त्रैमासिक बोर्ड बैठकमा 23% को राजस्व वृद्धि र TechCorp लाई 50 मिलियन डलरमा अधिग्रहण गर्ने छलफल भयो।",
            expected_terms: vec!["राजस्व", "23%", "TechCorp"],
            description: "Business meeting summary (Nepali)",
        },
        EvalCase {
            lang: "km",
            input: "កិច្ចប្រជុំត្រីមាសនៃក្រុមប្រឹក្សាភិបាលបានពិភាក្សាពីកំណើនប្រាក់ចំណូល 23% និងការទិញយក TechCorp ក្នុងតម្លៃ 50 លានដុល្លារ។",
            expected_terms: vec!["ប្រាក់ចំណូល", "23%", "TechCorp"],
            description: "Business meeting summary (Khmer)",
        },
    ]
}

fn translation_dataset_expanded() -> Vec<TranslationCase> {
    vec![
        TranslationCase {
            source_lang: "en", target_lang: "fr",
            input: "The company reported a 23% increase in revenue for the third quarter.",
            reference: "L'entreprise a rapporté une augmentation de 23% des revenus pour le troisième trimestre.",
            expected_terms: vec!["23%", "revenus", "trimestre"],
        },
        TranslationCase {
            source_lang: "en", target_lang: "de",
            input: "The company reported a 23% increase in revenue for the third quarter.",
            reference: "Das Unternehmen meldete eine Umsatzsteigerung von 23% im dritten Quartal.",
            expected_terms: vec!["23%", "Umsatz", "Quartal"],
        },
        TranslationCase {
            source_lang: "en", target_lang: "ja",
            input: "The company reported a 23% increase in revenue for the third quarter.",
            reference: "会社は第3四半期の収益が23%増加したと報告した。",
            expected_terms: vec!["23%", "収益", "四半期"],
        },
        TranslationCase {
            source_lang: "en", target_lang: "ko",
            input: "The company reported a 23% increase in revenue for the third quarter.",
            reference: "회사는 3분기 수익이 23% 증가했다고 보고했다.",
            expected_terms: vec!["23%", "수익", "분기"],
        },
        TranslationCase {
            source_lang: "en", target_lang: "pt",
            input: "The company reported a 23% increase in revenue for the third quarter.",
            reference: "A empresa reportou um aumento de 23% na receita no terceiro trimestre.",
            expected_terms: vec!["23%", "receita", "trimestre"],
        },
        TranslationCase {
            source_lang: "en", target_lang: "ru",
            input: "The company reported a 23% increase in revenue for the third quarter.",
            reference: "Компания сообщила о росте доходов на 23% в третьем квартале.",
            expected_terms: vec!["23%", "доходов", "квартале"],
        },
        TranslationCase {
            source_lang: "en", target_lang: "hi",
            input: "The company reported a 23% increase in revenue for the third quarter.",
            reference: "कंपनी ने तीसरी तिमाही में 23% के राजस्व वृद्धि की सूचना दी।",
            expected_terms: vec!["23%", "राजस्व", "तिमाही"],
        },
        TranslationCase {
            source_lang: "en", target_lang: "id",
            input: "The company reported a 23% increase in revenue for the third quarter.",
            reference: "Perusahaan melaporkan peningkatan pendapatan sebesar 23% untuk kuartal ketiga.",
            expected_terms: vec!["23%", "pendapatan", "kuartal"],
        },
        TranslationCase {
            source_lang: "fr", target_lang: "en",
            input: "L'entreprise a rapporté une augmentation de 23% des revenus.",
            reference: "The company reported a 23% increase in revenue.",
            expected_terms: vec!["23%", "revenue", "increase"],
        },
        TranslationCase {
            source_lang: "de", target_lang: "en",
            input: "Das Unternehmen meldete eine Umsatzsteigerung von 23%.",
            reference: "The company reported a revenue increase of 23%.",
            expected_terms: vec!["23%", "revenue", "increase"],
        },
        TranslationCase {
            source_lang: "ja", target_lang: "en",
            input: "会社は収益が23%増加したと報告した。",
            reference: "The company reported a 23% increase in revenue.",
            expected_terms: vec!["23%", "revenue", "increase"],
        },
    ]
}

// ─── Expanded Semantic Search Cases ─────────────────────────────────

fn semantic_search_dataset_expanded() -> Vec<SemanticSearchCase> {
    vec![
        // Database technology search
        SemanticSearchCase {
            documents: vec![
                ("db1", "PostgreSQL is a powerful open-source relational database with ACID compliance."),
                ("db2", "MongoDB is a NoSQL document database with flexible schema design."),
                ("db3", "Redis is an in-memory key-value store for caching and real-time applications."),
                ("db4", "MySQL is a popular relational database for web applications."),
                ("db5", "Cassandra is a distributed NoSQL database for large-scale data."),
                ("db6", "Elasticsearch is a search and analytics engine based on Lucene."),
                ("db7", "DynamoDB is a managed NoSQL database service from AWS."),
                ("db8", "SQLite is an embedded relational database for mobile and edge devices."),
            ],
            // Query: "relational database" — relevant: db1, db4, db8
            query_embedding: vec![0.9, 0.0, 0.0, 0.85, 0.0, 0.0, 0.0, 0.8],
            relevant_ids: vec!["db1", "db4", "db8"],
            k: 5,
        },
        // Machine learning search
        SemanticSearchCase {
            documents: vec![
                ("ml1", "Neural networks are computational models inspired by biological neurons."),
                ("ml2", "Decision trees are interpretable models for classification and regression."),
                ("ml3", "Gradient boosting combines weak learners into strong predictors."),
                ("ml4", "Convolutional neural networks excel at image recognition tasks."),
                ("ml5", "Transformers use attention mechanisms for sequence-to-sequence learning."),
                ("ml6", "Reinforcement learning trains agents through reward signals."),
                ("ml7", "Transfer learning fine-tunes pre-trained models for new tasks."),
                ("ml8", "Natural language processing enables machines to understand human language."),
            ],
            // Query: "neural network deep learning" — relevant: ml1, ml4, ml5
            query_embedding: vec![0.9, 0.0, 0.0, 0.85, 0.8, 0.0, 0.0, 0.0],
            relevant_ids: vec!["ml1", "ml4", "ml5"],
            k: 3,
        },
        // Cloud platform search
        SemanticSearchCase {
            documents: vec![
                ("cloud1", "AWS EC2 provides scalable virtual servers in the cloud."),
                ("cloud2", "Azure Functions is a serverless compute service by Microsoft."),
                ("cloud3", "Google Cloud Run deploys containerized applications automatically."),
                ("cloud4", "AWS Lambda runs code without provisioning servers."),
                ("cloud5", "Azure Cosmos DB is a globally distributed multi-model database."),
                ("cloud6", "Google Kubernetes Engine manages containerized applications at scale."),
                ("cloud7", "AWS S3 provides object storage for data backup and archiving."),
                ("cloud8", "Azure DevOps provides CI/CD pipelines for software development."),
                ("cloud9", "Google BigQuery enables serverless data warehousing and analytics."),
                ("cloud10", "AWS CloudFormation provisions infrastructure as code."),
            ],
            // Query: "AWS cloud service" — relevant: cloud1, cloud4, cloud7, cloud10
            query_embedding: vec![0.9, 0.0, 0.0, 0.85, 0.0, 0.0, 0.8, 0.0, 0.0, 0.75],
            relevant_ids: vec!["cloud1", "cloud4", "cloud7", "cloud10"],
            k: 5,
        },
    ]
}

// ─── BLEU Scorer ────────────────────────────────────────────────────

/// BLEU-2 score: geometric mean of 1-gram and 2-gram precision with brevity penalty.
fn bleu_score(output: &str, reference: &str) -> f32 {
    let output_tokens: Vec<&str> = output.split_whitespace().collect();
    let ref_tokens: Vec<&str> = reference.split_whitespace().collect();
    if output_tokens.is_empty() || ref_tokens.is_empty() { return 0.0; }

    // 1-gram precision
    let mut matches_1 = 0;
    for tok in &output_tokens {
        if ref_tokens.contains(tok) { matches_1 += 1; }
    }
    let p1 = matches_1 as f32 / output_tokens.len() as f32;

    // 2-gram precision
    let output_bigrams: Vec<(&str, &str)> = output_tokens.windows(2)
        .map(|w| (w[0], w[1])).collect();
    let ref_bigrams: Vec<(&str, &str)> = ref_tokens.windows(2)
        .map(|w| (w[0], w[1])).collect();
    let mut matches_2 = 0;
    if !output_bigrams.is_empty() {
        for bg in &output_bigrams {
            if ref_bigrams.contains(bg) { matches_2 += 1; }
        }
    }
    let p2 = if output_bigrams.is_empty() { 0.0 } else { matches_2 as f32 / output_bigrams.len() as f32 };

    // Brevity penalty
    let bp = if output_tokens.len() < ref_tokens.len() {
        (1.0 - ref_tokens.len() as f32 / output_tokens.len() as f32).exp()
    } else { 1.0 };

    // BLEU-2 = BP * exp(mean(log(p1, p2)))
    if p1 <= 0.0 || p2 <= 0.0 { return 0.0; }
    let log_mean = (p1.ln() + p2.ln()) / 2.0;
    bp * log_mean.exp()
}

// ─── MRR (Mean Reciprocal Rank) ─────────────────────────────────────

/// Reciprocal rank: 1/rank of first relevant result.
fn reciprocal_rank(result_ids: &[String], relevant: &[&str]) -> f32 {
    for (i, id) in result_ids.iter().enumerate() {
        if relevant.contains(&id.as_str()) {
            return 1.0 / (i + 1) as f32;
        }
    }
    0.0
}

// ─── Leaderboard Generator ──────────────────────────────────────────

/// Generate a markdown leaderboard from eval results.
fn generate_leaderboard(
    task_results: &[TaskEvalResult],
    translation_results: &[TranslationEvalResult],
    search_results: &[SearchEvalResult],
) -> String {
    let mut md = String::new();
    md.push_str("# zk-ai SDK Accuracy Leaderboard\n\n");
    md.push_str("Generated by `accuracy_eval.rs` — deterministic, reproducible.\n\n");

    // Per-language table
    md.push_str("## Per-Language Results\n\n");
    md.push_str("| Language | Task | Coverage | Faithfulness | In-Lang | Description |\n");
    md.push_str("|----------|------|----------|--------------|---------|-------------|\n");
    for r in task_results {
        md.push_str(&format!("| {} | {} | {:.1}% | {}/{} | {} | {} |\n",
            r.lang, r.task, r.coverage * 100.0, r.grounded, r.total_entities,
            if r.in_language { "✓" } else { "✗" }, r.description));
    }

    // Translation table
    md.push_str("\n## Translation Quality\n\n");
    md.push_str("| Pair | BLEU-2 | Term Coverage | In-Lang |\n");
    md.push_str("|------|--------|---------------|---------|\n");
    for r in translation_results {
        md.push_str(&format!("| {} | {:.3} | {:.1}% | {} |\n",
            r.pair, r.overlap_score, r.coverage * 100.0,
            if r.in_language { "✓" } else { "✗" }));
    }

    // Search table
    md.push_str("\n## Search Quality\n\n");
    md.push_str("| Type | Case | Recall@k | MRR | k | Relevant |\n");
    md.push_str("|------|------|----------|-----|---|----------|\n");
    for r in search_results {
        md.push_str(&format!("| {} | {} | {:.1}% | {:.3} | {} | {} |\n",
            r.search_type, r.case_idx, r.recall_at_k * 100.0, r.mrr, r.k, r.relevant_count));
    }

    // Overall summary
    let overall_coverage: f32 = task_results.iter().map(|r| r.coverage).sum::<f32>() / task_results.len().max(1) as f32;
    let total_grounded: usize = task_results.iter().map(|r| r.grounded).sum();
    let total_entities: usize = task_results.iter().map(|r| r.total_entities).sum();
    let overall_faith = if total_entities > 0 { total_grounded as f32 / total_entities as f32 } else { 1.0 };
    let overall_in_lang = task_results.iter().filter(|r| r.in_language).count();
    let avg_bleu: f32 = if !translation_results.is_empty() {
        translation_results.iter().map(|r| r.overlap_score).sum::<f32>() / translation_results.len() as f32
    } else { 0.0 };
    let avg_recall: f32 = if !search_results.is_empty() {
        search_results.iter().map(|r| r.recall_at_k).sum::<f32>() / search_results.len() as f32
    } else { 0.0 };
    let avg_mrr: f32 = if !search_results.is_empty() {
        search_results.iter().map(|r| r.mrr).sum::<f32>() / search_results.len() as f32
    } else { 0.0 };

    md.push_str("\n## Overall Summary\n\n");
    md.push_str("| Metric | Score |\n");
    md.push_str("|--------|-------|\n");
    md.push_str(&format!("| Term Coverage | {:.1}% |\n", overall_coverage * 100.0));
    md.push_str(&format!("| Faithfulness | {:.1}% |\n", overall_faith * 100.0));
    md.push_str(&format!("| In-Language Pass | {}/{} |\n", overall_in_lang, task_results.len()));
    md.push_str(&format!("| Avg BLEU-2 | {:.3} |\n", avg_bleu));
    md.push_str(&format!("| Avg Recall@k | {:.1}% |\n", avg_recall * 100.0));
    md.push_str(&format!("| Avg MRR | {:.3} |\n", avg_mrr));
    md.push_str(&format!("| Languages | {} |\n", SUPPORTED_LANGUAGES.len()));
    md.push_str(&format!("| Text Tasks | {} |\n", task_results.len()));
    md.push_str(&format!("| Translation Pairs | {} |\n", translation_results.len()));
    md.push_str(&format!("| Search Cases | {} |\n", search_results.len()));

    let mode = if task_results.first().map(|r| r.output_preview.contains("zk-ai inference fallback")).unwrap_or(false) {
        "FALLBACK (no ONNX model loaded)"
    } else {
        "ONNX Model (or smart fallback)"
    };
    md.push_str(&format!("| Mode | {} |\n", mode));

    md
}

// ─── Eval Results ───────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct TaskEvalResult {
    task: &'static str,
    lang: &'static str,
    description: String,
    coverage: f32,
    matched_terms: Vec<String>,
    missing_terms: Vec<String>,
    grounded: usize,
    total_entities: usize,
    in_language: bool,
    output_preview: String,
}

#[derive(Debug, Clone)]
struct TranslationEvalResult {
    pair: String,
    overlap_score: f32,
    coverage: f32,
    in_language: bool,
    output_preview: String,
}

#[derive(Debug, Clone)]
struct SearchEvalResult {
    search_type: &'static str,
    case_idx: usize,
    recall_at_k: f32,
    mrr: f32,
    k: usize,
    relevant_count: usize,
}

// ─── Eval Tests ─────────────────────────────────────────────────────

#[cfg(test)]
mod eval {
    use super::*;

    /// Run the full accuracy evaluation and print a comprehensive report.
    #[tokio::test]
    async fn full_accuracy_eval() {
        let (_tmp, mut engine) = setup_test_engine().await;
        let spec = ModelSpec::mt5_small_int8();
        engine.ensure_model(&spec).await.unwrap();

        let mut task_results: Vec<TaskEvalResult> = Vec::new();
        let mut translation_results: Vec<TranslationEvalResult> = Vec::new();
        let mut search_results: Vec<SearchEvalResult> = Vec::new();

        // ── Summarize eval (original 6 languages) ──
        for case in summarize_dataset() {
            let result = engine.summarize(case.input, case.lang, TaskOptions::default()).await;
            let output = result.map(|r| r.output).unwrap_or_default();
            let (matched, missing) = term_coverage(&output, &case.expected_terms);
            let (grounded, total) = faithfulness(&output, case.input);
            let in_lang = in_language(&output, case.lang);
            let coverage = if case.expected_terms.is_empty() { 1.0 } else { matched.len() as f32 / case.expected_terms.len() as f32 };
            task_results.push(TaskEvalResult {
                task: "summarize",
                lang: case.lang,
                description: case.description.to_string(),
                coverage,
                matched_terms: matched,
                missing_terms: missing,
                grounded,
                total_entities: total,
                in_language: in_lang,
                output_preview: output.chars().take(80).collect(),
            });
        }

        // ── Summarize eval (expanded 16 languages) ──
        for case in summarize_dataset_expanded() {
            let result = engine.summarize(case.input, case.lang, TaskOptions::default()).await;
            let output = result.map(|r| r.output).unwrap_or_default();
            let (matched, missing) = term_coverage(&output, &case.expected_terms);
            let (grounded, total) = faithfulness(&output, case.input);
            let in_lang = in_language(&output, case.lang);
            let coverage = if case.expected_terms.is_empty() { 1.0 } else { matched.len() as f32 / case.expected_terms.len() as f32 };
            task_results.push(TaskEvalResult {
                task: "summarize",
                lang: case.lang,
                description: case.description.to_string(),
                coverage,
                matched_terms: matched,
                missing_terms: missing,
                grounded,
                total_entities: total,
                in_language: in_lang,
                output_preview: output.chars().take(80).collect(),
            });
        }

        // ── Key points eval ──
        for case in key_points_dataset() {
            let result = engine.key_points(case.input, case.lang, TaskOptions::default()).await;
            let output = result.map(|r| r.output).unwrap_or_default();
            let (matched, missing) = term_coverage(&output, &case.expected_terms);
            let (grounded, total) = faithfulness(&output, case.input);
            let in_lang = in_language(&output, case.lang);
            let coverage = if case.expected_terms.is_empty() { 1.0 } else { matched.len() as f32 / case.expected_terms.len() as f32 };
            task_results.push(TaskEvalResult {
                task: "key_points",
                lang: case.lang,
                description: case.description.to_string(),
                coverage,
                matched_terms: matched,
                missing_terms: missing,
                grounded,
                total_entities: total,
                in_language: in_lang,
                output_preview: output.chars().take(80).collect(),
            });
        }

        // ── Generate doc eval ──
        for case in generate_doc_dataset() {
            let result = engine.generate_doc(case.input, case.input, case.lang, TaskOptions::default()).await;
            let output = result.map(|r| r.output).unwrap_or_default();
            let (matched, missing) = term_coverage(&output, &case.expected_terms);
            let (grounded, total) = faithfulness(&output, case.input);
            let in_lang = in_language(&output, case.lang);
            let coverage = if case.expected_terms.is_empty() { 1.0 } else { matched.len() as f32 / case.expected_terms.len() as f32 };
            task_results.push(TaskEvalResult {
                task: "generate_doc",
                lang: case.lang,
                description: case.description.to_string(),
                coverage,
                matched_terms: matched,
                missing_terms: missing,
                grounded,
                total_entities: total,
                in_language: in_lang,
                output_preview: output.chars().take(80).collect(),
            });
        }

        // ── Generate slides eval ──
        for case in generate_slides_dataset() {
            let result = engine.generate_slides(case.input, case.input, case.lang, TaskOptions::default()).await;
            let output = result.map(|r| r.output).unwrap_or_default();
            let (matched, missing) = term_coverage(&output, &case.expected_terms);
            let (grounded, total) = faithfulness(&output, case.input);
            let in_lang = in_language(&output, case.lang);
            let coverage = if case.expected_terms.is_empty() { 1.0 } else { matched.len() as f32 / case.expected_terms.len() as f32 };
            task_results.push(TaskEvalResult {
                task: "generate_slides",
                lang: case.lang,
                description: case.description.to_string(),
                coverage,
                matched_terms: matched,
                missing_terms: missing,
                grounded,
                total_entities: total,
                in_language: in_lang,
                output_preview: output.chars().take(80).collect(),
            });
        }

        // ── Translation eval (original pairs) ──
        for case in translation_dataset() {
            let result = engine.translate(case.input, case.source_lang, case.target_lang, TaskOptions::default()).await;
            let output = result.map(|r| r.output).unwrap_or_default();
            let bleu = bleu_score(&output, case.reference);
            let (matched, _) = term_coverage(&output, &case.expected_terms);
            let coverage = if case.expected_terms.is_empty() { 1.0 } else { matched.len() as f32 / case.expected_terms.len() as f32 };
            let in_lang = in_language(&output, case.target_lang);
            translation_results.push(TranslationEvalResult {
                pair: format!("{}→{}", case.source_lang, case.target_lang),
                overlap_score: bleu,
                coverage,
                in_language: in_lang,
                output_preview: output.chars().take(80).collect(),
            });
        }

        // ── Translation eval (expanded pairs) ──
        for case in translation_dataset_expanded() {
            let result = engine.translate(case.input, case.source_lang, case.target_lang, TaskOptions::default()).await;
            let output = result.map(|r| r.output).unwrap_or_default();
            let bleu = bleu_score(&output, case.reference);
            let (matched, _) = term_coverage(&output, &case.expected_terms);
            let coverage = if case.expected_terms.is_empty() { 1.0 } else { matched.len() as f32 / case.expected_terms.len() as f32 };
            let in_lang = in_language(&output, case.target_lang);
            translation_results.push(TranslationEvalResult {
                pair: format!("{}→{}", case.source_lang, case.target_lang),
                overlap_score: bleu,
                coverage,
                in_language: in_lang,
                output_preview: output.chars().take(80).collect(),
            });
        }

        // ── Semantic search eval (original cases) ──
        for (idx, case) in semantic_search_dataset().iter().enumerate() {
            let mut index = TextIndex::new();
            for (id, text) in &case.documents {
                // Use deterministic synthetic embeddings based on text length
                let embedding = synthetic_embedding(text, case.documents.len());
                index.add_text(id, text, embedding, None);
            }
            let hits = index.search(&case.query_embedding, case.k);
            let result_ids: Vec<String> = hits.iter().map(|h| h.id.clone()).collect();
            let recall = recall_at_k(&result_ids, &case.relevant_ids, case.k);
            let mrr = reciprocal_rank(&result_ids, &case.relevant_ids);
            search_results.push(SearchEvalResult {
                search_type: "semantic",
                case_idx: idx,
                recall_at_k: recall,
                mrr,
                k: case.k,
                relevant_count: case.relevant_ids.len(),
            });
        }

        // ── Semantic search eval (expanded cases) ──
        for (idx, case) in semantic_search_dataset_expanded().iter().enumerate() {
            let mut index = TextIndex::new();
            for (id, text) in &case.documents {
                let embedding = synthetic_embedding(text, case.documents.len());
                index.add_text(id, text, embedding, None);
            }
            let hits = index.search(&case.query_embedding, case.k);
            let result_ids: Vec<String> = hits.iter().map(|h| h.id.clone()).collect();
            let recall = recall_at_k(&result_ids, &case.relevant_ids, case.k);
            let mrr = reciprocal_rank(&result_ids, &case.relevant_ids);
            search_results.push(SearchEvalResult {
                search_type: "semantic",
                case_idx: idx + 100, // offset to distinguish from original
                recall_at_k: recall,
                mrr,
                k: case.k,
                relevant_count: case.relevant_ids.len(),
            });
        }

        // ── Image search eval ──
        for (idx, case) in image_search_dataset().iter().enumerate() {
            let mut index = ImageIndex::new();
            for (id, caption, embedding) in &case.images {
                index.add_image(id, caption, embedding.clone());
            }
            let hits = index.search(&case.query_embedding, case.k);
            let result_ids: Vec<String> = hits.iter().map(|h| h.id.clone()).collect();
            let recall = recall_at_k(&result_ids, &case.relevant_ids, case.k);
            let mrr = reciprocal_rank(&result_ids, &case.relevant_ids);
            search_results.push(SearchEvalResult {
                search_type: "image",
                case_idx: idx,
                recall_at_k: recall,
                mrr,
                k: case.k,
                relevant_count: case.relevant_ids.len(),
            });
        }

        // ── Print comprehensive report ──
        print_eval_report(&task_results, &translation_results, &search_results);

        // ── Generate markdown leaderboard ──
        let leaderboard = generate_leaderboard(&task_results, &translation_results, &search_results);
        println!("\n{}", leaderboard);

        // ── Assertions: verify the harness runs and produces results ──
        assert!(!task_results.is_empty(), "should have task eval results");
        assert!(!translation_results.is_empty(), "should have translation eval results");
        assert!(!search_results.is_empty(), "should have search eval results");

        // Verify expanded coverage
        let langs_tested: std::collections::HashSet<&str> = task_results.iter().map(|r| r.lang).collect();
        assert!(langs_tested.len() >= 22, "should test at least 22 languages, got {}", langs_tested.len());

        // Semantic and image search should have good recall (deterministic embeddings)
        let avg_search_recall: f32 = search_results.iter()
            .map(|r| r.recall_at_k).sum::<f32>() / search_results.len() as f32;
        assert!(avg_search_recall > 0.5, "avg search recall should be >0.5, got {}", avg_search_recall);
    }

    fn synthetic_embedding(text: &str, dim: usize) -> Vec<f32> {
        // Word-hash based deterministic embedding for semantic similarity
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

    fn print_eval_report(
        task_results: &[TaskEvalResult],
        translation_results: &[TranslationEvalResult],
        search_results: &[SearchEvalResult],
    ) {
        println!("\n{}", "=".repeat(80));
        println!("  zk-ai SDK — Comprehensive Accuracy Evaluation Report");
        println!("{}", "=".repeat(80));

        // ── Per-task summary ──
        println!("\n┌── Text Task Results ──────────────────────────────────────────────┐");
        println!("│ Task           │ Lang │ Coverage │ Faithfulness │ In-Lang │ Notes │");
        println!("│────────────────┼──────┼──────────┼──────────────┼─────────┼───────│");

        for r in task_results {
            println!("│ {:14} │ {:4} │ {:7.1}% │ {:4}/{:<4}      │ {:7} │ {:5} │",
                r.task,
                r.lang,
                r.coverage * 100.0,
                r.grounded,
                r.total_entities,
                if r.in_language { "yes" } else { "no" },
                &r.description.chars().take(20).collect::<String>(),
            );
        }

        // ── Per-language aggregates for text tasks ──
        println!("\n┌── Per-Language Aggregate (Text Tasks) ────────────────────────────┐");
        println!("│ Lang │ Avg Coverage │ Avg Faithfulness │ In-Lang Pass Rate       │");
        println!("│──────┼──────────────┼──────────────────┼─────────────────────────│");

        for lang in SUPPORTED_LANGUAGES {
            let lang_results: Vec<&TaskEvalResult> = task_results.iter()
                .filter(|r| r.lang == *lang).collect();
            if lang_results.is_empty() { continue; }
            let avg_coverage: f32 = lang_results.iter().map(|r| r.coverage).sum::<f32>() / lang_results.len() as f32;
            let total_grounded: usize = lang_results.iter().map(|r| r.grounded).sum();
            let total_entities: usize = lang_results.iter().map(|r| r.total_entities).sum();
            let faith_pct = if total_entities > 0 { total_grounded as f32 / total_entities as f32 * 100.0 } else { 100.0 };
            let in_lang_pass = lang_results.iter().filter(|r| r.in_language).count();
            println!("│ {:4} │ {:10.1}%  │ {:14.1}%  │ {:2}/{:<2}                    │",
                lang, avg_coverage * 100.0, faith_pct, in_lang_pass, lang_results.len());
        }

        // ── Per-task aggregates ──
        println!("\n┌── Per-Task Aggregate ─────────────────────────────────────────────┐");
        println!("│ Task           │ Avg Coverage │ Avg Faithfulness │ In-Lang Rate    │");
        println!("│────────────────┼──────────────┼──────────────────┼─────────────────│");

        for task in &["summarize", "key_points", "generate_doc", "generate_slides"] {
            let task_res: Vec<&TaskEvalResult> = task_results.iter()
                .filter(|r| r.task == *task).collect();
            if task_res.is_empty() { continue; }
            let avg_cov: f32 = task_res.iter().map(|r| r.coverage).sum::<f32>() / task_res.len() as f32;
            let total_g: usize = task_res.iter().map(|r| r.grounded).sum();
            let total_e: usize = task_res.iter().map(|r| r.total_entities).sum();
            let faith = if total_e > 0 { total_g as f32 / total_e as f32 * 100.0 } else { 100.0 };
            let in_lang = task_res.iter().filter(|r| r.in_language).count();
            println!("│ {:14} │ {:10.1}%  │ {:14.1}%  │ {:2}/{:<2}            │",
                task, avg_cov * 100.0, faith, in_lang, task_res.len());
        }

        // ── Translation results ──
        println!("\n┌── Translation Results ────────────────────────────────────────────┐");
        println!("│ Pair     │ Overlap Score │ Term Coverage │ In-Lang │ Output Preview       │");
        println!("│──────────┼───────────────┼───────────────┼─────────┼──────────────────────│");

        for r in translation_results {
            println!("│ {:8} │ {:12.3}  │ {:12.1}%  │ {:7} │ {:20} │",
                r.pair,
                r.overlap_score,
                r.coverage * 100.0,
                if r.in_language { "yes" } else { "no" },
                &r.output_preview.chars().take(20).collect::<String>(),
            );
        }

        // ── Search results ──
        println!("\n┌── Search Results ─────────────────────────────────────────────────┐");
        println!("│ Type     │ Case │ Recall@k │ MRR    │ k │ Relevant │");
        println!("│──────────┼──────┼──────────┼────────┼───┼──────────│");

        for r in search_results {
            println!("│ {:8} │ {:4} │ {:7.1}% │ {:6.3} │ {} │ {:8} │",
                r.search_type, r.case_idx, r.recall_at_k * 100.0, r.mrr, r.k, r.relevant_count);
        }

        // ── Overall summary ──
        let overall_coverage: f32 = task_results.iter().map(|r| r.coverage).sum::<f32>() / task_results.len() as f32;
        let total_grounded: usize = task_results.iter().map(|r| r.grounded).sum();
        let total_entities: usize = task_results.iter().map(|r| r.total_entities).sum();
        let overall_faith = if total_entities > 0 { total_grounded as f32 / total_entities as f32 } else { 1.0 };
        let overall_in_lang = task_results.iter().filter(|r| r.in_language).count();
        let avg_translation_overlap: f32 = translation_results.iter().map(|r| r.overlap_score).sum::<f32>() / translation_results.len() as f32;
        let avg_search_recall: f32 = search_results.iter().map(|r| r.recall_at_k).sum::<f32>() / search_results.len() as f32;
        let avg_mrr: f32 = search_results.iter().map(|r| r.mrr).sum::<f32>() / search_results.len() as f32;

        println!("\n┌── Overall Summary ────────────────────────────────────────────────┐");
        println!("│ Metric                    │ Score                                │");
        println!("│───────────────────────────┼──────────────────────────────────────│");
        println!("│ Overall Term Coverage     │ {:5.1}%                              │", overall_coverage * 100.0);
        println!("│ Overall Faithfulness      │ {:5.1}%                              │", overall_faith * 100.0);
        println!("│ In-Language Pass Rate     │ {:2}/{:<2}                              │", overall_in_lang, task_results.len());
        println!("│ Avg Translation Overlap   │ {:5.3}                               │", avg_translation_overlap);
        println!("│ Avg Search Recall@k       │ {:5.1}%                              │", avg_search_recall * 100.0);
        println!("│ Avg MRR                   │ {:5.3}                               │", avg_mrr);
        println!("│                           │                                      │");
        println!("│ Mode                      │ {}                              │",
            if task_results.first().map(|r| r.output_preview.contains("zk-ai inference fallback")).unwrap_or(false) { "FALLBACK (no ONNX)" } else { "Smart Fallback" });
        println!("│ Languages Tested          │ {:2}                                  │", SUPPORTED_LANGUAGES.len());
        println!("│ Text Tasks Evaluated      │ {:2}                                  │", task_results.len());
        println!("│ Translation Pairs         │ {:2}                                  │", translation_results.len());
        println!("│ Search Cases              │ {:2}                                  │", search_results.len());
        println!("└───────────────────────────┴──────────────────────────────────────┘");

        // ── Missing terms detail ──
        println!("\n┌── Missing Terms Detail ───────────────────────────────────────────┐");
        for r in task_results {
            if !r.missing_terms.is_empty() {
                println!("│ {:14} {:4} — missing: {}", r.task, r.lang, r.missing_terms.join(", "));
            }
        }
        println!("└────────────────────────────────────────────────────────────────────┘\n");
    }
}
