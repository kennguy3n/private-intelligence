use kinshield::{KinShieldEngine, Channel};
use std::io::Read;

fn init_tracing() {
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::from_default_env();
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .compact()
        .init();
}

struct EvalRow {
    text: String,
    expected_label: String,
    language: String,
}

fn load_eval_csv(path: &str) -> Vec<EvalRow> {
    let mut file = std::fs::File::open(path).expect("failed to open eval csv");
    let mut content = String::new();
    file.read_to_string(&mut content).expect("failed to read");

    let mut reader = csv::Reader::from_reader(content.as_bytes());
    let mut rows = Vec::new();

    for record in reader.records() {
        let record = match record {
            Ok(r) => r,
            Err(e) => {
                eprintln!("WARN: skipping malformed CSV row: {e}");
                continue;
            }
        };
        if record.len() < 4 {
            continue;
        }
        let text = record.get(1).unwrap_or_default().trim().to_string();
        let expected_label = record.get(2).unwrap_or_default().trim().to_string();
        let language = record.get(3).unwrap_or_default().trim().to_string();

        if text.is_empty() {
            continue;
        }

        rows.push(EvalRow {
            text,
            expected_label,
            language,
        });
    }
    rows
}

fn detect_language(text: &str, declared: &str) -> &'static str {
    if !declared.is_empty() {
        return match declared {
            "vi" => "vi",
            "en" => "en",
            "th" => "th",
            "id" => "id",
            "ms" => "ms",
            "tl" => "tl",
            "km" => "km",
            "zh" | "zh-CN" | "zh-TW" => "zh",
            _ => "en",
        };
    }
    // Auto-detect: check for Vietnamese characters/words
    let lower = text.to_lowercase();
    let vi_markers = [
        "tài khoản", "xác nhận", "khẩn cấp", "ngân hàng", "vui lòng",
        "đăng nhập", "mật khẩu", "ảo", "khoản", "nghi ngờ", "ảnh",
        "anh ", "chị ", "em ", "và", "không", "được", "với",
        "đầu tư", "lợi nhuận", "cam kết", "trợ cấp", "bạn",
        "mình", "chào", "xin lỗi", "nhầm", "cơ hội", "vốn",
        "đăng ký", "tháng", "triệu", "nghìn", "ngày",
        "thông báo", "xác minh", "bảo mật", "từ",
        // Unaccented variants (common in SMS)
        "tai khoan", "xac nhan", "khan cap", "ngan hang", "vui long",
        "dang nhap", "mat khau", "khoan", "ban ", "minh ", "chao ",
        "dau tu", "loi nhuan", "cam ket", "tro cap",
        "co hoi", "von", "dang ky", "thang", "trieu", "nghin",
        "thong bao", "xac minh", "bao mat", "khong", "duoc",
        "tuyen", "ctv", "luong", "hoa hong", "kiem tien",
        "trung giai", "nhan thuong", "khuyen mai",
        "chuyen khoan", "gui tien", "nap tien", "thanh toan",
        "ho tro", "uy quyen", "chap hanh", "canh sat",
        "tien dien", "ho gia dinh", "dong gop", "quyen gop",
        "ung ho", "bao lu", "dong bao", "mien trung",
        "chuc mung", "khach hang than thiet",
        "vnd", "viet nam", "sai gon", "ha noi",
    ];
    let vi_count = vi_markers.iter().filter(|m| lower.contains(*m)).count();
    if vi_count >= 2 {
        return "vi";
    }
    "en"
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    init_tracing();

    let eval_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| {
            "samples/kinshield/data/kinshield-ota-20260709-004-data/sms/sms_eval_sets.csv"
                .to_string()
        });

    println!("Loading eval dataset from: {}", eval_path);
    let rows = load_eval_csv(&eval_path);
    println!("Loaded {} eval rows", rows.len());

    let cache_dir = std::env::temp_dir().join("kinshield-eval-cache");
    std::fs::create_dir_all(&cache_dir)?;

    println!("Initializing KinShield engine...");
    let mut engine = KinShieldEngine::new(&cache_dir).await?;
    println!("Engine ready. Running detection...\n");

    let mut results: Vec<(String, String, u8, Option<&'static str>, &'static str)> = Vec::new();
    let mut all_indicators: Vec<Vec<String>> = Vec::new();

    for (i, row) in rows.iter().enumerate() {
        let lang = detect_language(&row.text, &row.language);
        let channel = Channel::Sms;

        match engine.detect(&row.text, channel, lang, None).await {
            Ok(result) => {
                let predicted = if result.risk_bucket >= 4 {
                    "scam"
                } else if result.risk_bucket >= 3 {
                    "suspicious"
                } else {
                    "safe"
                };
                let scam_type_str = result.scam_type.map(|t| t.as_str());
                let inds: Vec<String> = result.indicators.iter().map(|h| format!("{:?}:{:?}", h.id, h.strength)).collect();
                all_indicators.push(inds);
                results.push((
                    row.expected_label.clone(),
                    predicted.to_string(),
                    result.risk_bucket,
                    scam_type_str,
                    lang,
                ));
            }
            Err(e) => {
                eprintln!("ERROR on row {i}: {e}");
                all_indicators.push(vec![]);
                results.push((row.expected_label.clone(), "error".to_string(), 0, None, lang));
            }
        }

        if (i + 1) % 100 == 0 {
            print!("\r  Processed {}/{} rows...", i + 1, rows.len());
            use std::io::Write;
            std::io::stdout().flush()?;
        }
    }
    println!("\n");

    // Compute metrics
    let total = results.len();

    // Debug: print false positives
    if std::env::var("DEBUG_FP").is_ok() {
        println!("\n--- FALSE POSITIVES (safe → scam) ---\n");
        for (i, row) in rows.iter().enumerate() {
            let (_, pred, bucket, scam_type, lang) = &results[i];
            if row.expected_label == "safe" && pred == "scam" {
                let indicators_str = all_indicators[i].join(", ");
                println!("[{i}] bucket={bucket} lang={lang} type={scam_type:?}\n  text: {}\n  indicators: {}\n", row.text.chars().take(120).collect::<String>(), indicators_str);
            }
        }
    }

    // Debug: print false negatives
    if std::env::var("DEBUG_FN").is_ok() {
        println!("\n--- FALSE NEGATIVES (scam → safe) ---\n");
        for (i, row) in rows.iter().enumerate() {
            let (_, pred, bucket, scam_type, lang) = &results[i];
            if row.expected_label == "scam" && pred == "safe" {
                let indicators_str = all_indicators[i].join(", ");
                println!("[{i}] bucket={bucket} lang={lang} type={scam_type:?}\n  text: {}\n  indicators: {}\n", row.text.chars().take(120).collect::<String>(), indicators_str);
            }
        }
    }

    let tp = results.iter().filter(|(exp, pred, _, _, _)| exp == "scam" && pred == "scam").count();
    let fp = results.iter().filter(|(exp, pred, _, _, _)| exp == "safe" && pred == "scam").count();
    let tn = results.iter().filter(|(exp, pred, _, _, _)| exp == "safe" && pred == "safe").count();
    let fn_ = results.iter().filter(|(exp, pred, _, _, _)| exp == "scam" && pred == "safe").count();
    let suspicious = results.iter().filter(|(_, pred, _, _, _)| pred == "suspicious").count();
    let errors = results.iter().filter(|(_, pred, _, _, _)| pred == "error").count();

    let accuracy = (tp + tn) as f64 / total as f64 * 100.0;
    let precision = if tp + fp > 0 { tp as f64 / (tp + fp) as f64 * 100.0 } else { 0.0 };
    let recall = if tp + fn_ > 0 { tp as f64 / (tp + fn_) as f64 * 100.0 } else { 0.0 };
    let f1 = if precision + recall > 0.0 { 2.0 * precision * recall / (precision + recall) } else { 0.0 };
    let fp_rate = if fp + tn > 0 { fp as f64 / (fp + tn) as f64 * 100.0 } else { 0.0 };

    // Per-language breakdown
    let mut lang_stats: std::collections::HashMap<&str, (usize, usize, usize, usize)> = std::collections::HashMap::new();
    for (exp, pred, _, _, lang) in &results {
        let entry = lang_stats.entry(lang).or_insert((0, 0, 0, 0));
        if exp == "scam" && (pred == "scam" || pred == "suspicious") {
            entry.0 += 1; // detected
        } else if exp == "scam" {
            entry.1 += 1; // missed
        } else if exp == "safe" && (pred == "scam" || pred == "suspicious") {
            entry.2 += 1; // false positive
        } else {
            entry.3 += 1; // correctly safe
        }
    }

    // Risk bucket distribution
    let mut bucket_dist = [0usize; 6];
    for (_, _, bucket, _, _) in &results {
        if *bucket < 6 {
            bucket_dist[*bucket as usize] += 1;
        }
    }

    // Scam type distribution for detected scams
    let mut scam_types: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
    for (exp, pred, _, st, _) in &results {
        if exp == "scam" && pred == "scam" {
            if let Some(s) = st {
                *scam_types.entry(s).or_insert(0) += 1;
            }
        }
    }

    println!("═══════════════════════════════════════════════════════════");
    println!("  KinShield Local Algorithm Evaluation Results");
    println!("  Dataset: kinshield-ota-20260709-004 (SMS eval sets)");
    println!("═══════════════════════════════════════════════════════════\n");

    println!("── Overall Metrics ──");
    println!("  Total samples:     {}", total);
    println!("  Scam samples:      {}", results.iter().filter(|(e,_,_,_,_)| e == "scam").count());
    println!("  Safe samples:      {}", results.iter().filter(|(e,_,_,_,_)| e == "safe").count());
    println!();
    println!("  True Positives:    {} (scam → scam)", tp);
    println!("  True Negatives:    {} (safe → safe)", tn);
    println!("  False Positives:   {} (safe → scam)", fp);
    println!("  False Negatives:   {} (scam → safe)", fn_);
    println!("  Suspicious:        {} (risk=3, not counted as TP or FP)", suspicious);
    println!("  Errors:            {}", errors);
    println!();
    println!("  Accuracy:          {:.2}%", accuracy);
    println!("  Precision:         {:.2}%", precision);
    println!("  Recall:            {:.2}%", recall);
    println!("  F1 Score:          {:.2}%", f1);
    println!("  False Positive Rate: {:.2}%", fp_rate);
    println!();

    println!("── Risk Bucket Distribution ──");
    for b in 1..=5 {
        let label = match b { 1 => "Benign", 2 => "Low", 3 => "Suspicious", 4 => "Likely Scam", 5 => "Very Likely Scam", _ => "?" };
        let count = bucket_dist[b];
        let pct = count as f64 / total as f64 * 100.0;
        let bar = "█".repeat((pct / 2.0) as usize);
        println!("  Bucket {}: {:<15} {:>5} ({:5.1}%) {}", b, label, count, pct, bar);
    }
    println!();

    println!("── Per-Language Performance ──");
    println!("  {:<6} {:>8} {:>8} {:>8} {:>8} {:>10} {:>10}", "Lang", "Detected", "Missed", "FalseP", "Correct", "Recall%", "F1%");
    let mut lang_vec: Vec<_> = lang_stats.iter().collect();
    lang_vec.sort_by(|a, b| a.0.cmp(b.0));
    for (lang, (detected, missed, falsep, correct)) in lang_vec {
        let total_scam = detected + missed;
        let recall_pct = if total_scam > 0 { *detected as f64 / total_scam as f64 * 100.0 } else { 0.0 };
        let precision_pct = if *detected + *falsep > 0 { *detected as f64 / (*detected + *falsep) as f64 * 100.0 } else { 0.0 };
        let f1_pct = if precision_pct + recall_pct > 0.0 { 2.0 * precision_pct * recall_pct / (precision_pct + recall_pct) } else { 0.0 };
        println!("  {:<6} {:>8} {:>8} {:>8} {:>8} {:>9.1}% {:>9.1}%", lang, detected, missed, falsep, correct, recall_pct, f1_pct);
    }
    println!();

    // Per-channel breakdown
    println!("── Per-Channel Performance ──");
    println!("  {:<12} {:>8} {:>8} {:>8} {:>8} {:>10}", "Channel", "Detected", "Missed", "FalseP", "Correct", "Recall%");
    let scam_as_susp = results.iter().filter(|(e,p,_,_,_)| e=="scam" && p=="suspicious").count();
    let safe_as_susp = results.iter().filter(|(e,p,_,_,_)| e=="safe" && p=="suspicious").count();
    let channel_str = "sms"; // currently only SMS channel
    let ch_detected = tp + scam_as_susp;
    let ch_missed = fn_;
    let ch_falsep = fp + safe_as_susp;
    let ch_correct = tn;
    let ch_recall = if ch_detected + ch_missed > 0 { ch_detected as f64 / (ch_detected + ch_missed) as f64 * 100.0 } else { 0.0 };
    println!("  {:<12} {:>8} {:>8} {:>8} {:>8} {:>9.1}%", channel_str, ch_detected, ch_missed, ch_falsep, ch_correct, ch_recall);
    println!();

    // Per-scam-type breakdown (detected vs missed)
    println!("── Per-Scam-Type Detection (detected vs missed) ──");
    let mut type_stats: std::collections::HashMap<&str, (usize, usize)> = std::collections::HashMap::new();
    for (i, _row) in rows.iter().enumerate() {
        let (_, pred, _, scam_type, _) = &results[i];
        let detected = pred == "scam" || pred == "suspicious";
        // Use the expected label's scam type if available in the CSV, otherwise use predicted
        let st = scam_type.unwrap_or("unknown");
        let entry = type_stats.entry(st).or_insert((0, 0));
        if detected {
            entry.0 += 1;
        } else {
            entry.1 += 1;
        }
    }
    let mut type_vec: Vec<_> = type_stats.iter().collect();
    type_vec.sort_by(|a, b| b.1.cmp(a.1));
    println!("  {:<25} {:>10} {:>10} {:>10}", "Scam Type", "Detected", "Missed", "Total");
    for (st, (det, miss)) in type_vec {
        println!("  {:<25} {:>10} {:>10} {:>10}", st, det, miss, det + miss);
    }
    println!();

    println!("── Scam Type Classification (TP only) ──");
    let mut sorted_types: Vec<_> = scam_types.iter().collect();
    sorted_types.sort_by(|a, b| b.1.cmp(a.1));
    for (st, count) in sorted_types {
        println!("  {:<25} {}", st, count);
    }
    println!();

    // Confusion matrix with suspicious as a separate category
    println!("── Confusion Matrix (scam vs safe, suspicious shown separately) ──");
    let scam_as_scam = tp;
    let scam_as_safe = fn_;
    let safe_as_scam = fp;
    let safe_as_safe = tn;

    println!("  {:<20} {:>10} {:>12} {:>10}", "", "Pred Scam", "Pred Susp", "Pred Safe");
    println!("  {:<20} {:>10} {:>12} {:>10}", "Actual Scam", scam_as_scam, scam_as_susp, scam_as_safe);
    println!("  {:<20} {:>10} {:>12} {:>10}", "Actual Safe", safe_as_scam, safe_as_susp, safe_as_safe);
    println!();

    // If we count suspicious as scam (conservative)
    let tp_conservative = tp + scam_as_susp;
    let fp_conservative = fp + safe_as_susp;
    let recall_c = tp_conservative as f64 / (tp_conservative + fn_) as f64 * 100.0;
    let precision_c = tp_conservative as f64 / (tp_conservative + fp_conservative) as f64 * 100.0;
    let f1_c = if precision_c + recall_c > 0.0 { 2.0 * precision_c * recall_c / (precision_c + recall_c) } else { 0.0 };

    println!("── Conservative Mode (suspicious → scam) ──");
    println!("  Recall:    {:.2}% ({} of {} scams detected)", recall_c, tp_conservative, tp_conservative + fn_);
    println!("  Precision: {:.2}% ({} true, {} false)", precision_c, tp_conservative, fp_conservative);
    println!("  F1 Score:  {:.2}%", f1_c);
    println!();

    println!("── Summary ──");
    println!("  • The local algorithm correctly identifies {:.0}% of scams with {:.0}% precision.", recall, precision);
    println!("  • {:.0}% false positive rate on benign messages.", fp_rate);
    println!("  • {} messages ({:.1}%) classified as suspicious (bucket 3) —", suspicious, suspicious as f64 / total as f64 * 100.0);
    println!("    these are borderline cases where user feedback is most valuable.");
    if recall_c > recall {
        println!("  • In conservative mode (suspicious → scam), recall rises to {:.0}% but precision drops to {:.0}%.", recall_c, precision_c);
    }
    println!("  • Scam type classification works for {} detected scams, covering {} families.", tp, scam_types.len());
    println!();

    engine.shutdown().await?;
    Ok(())
}
