//! Indicator ontology — 29 fixed, versioned scam indicators.
//!
//! Each indicator has: id, category, description, and multi-language
//! keyword sets for detection. Indicator strength is quantized to
//! Low, Medium, High (3-level).

use serde::{Deserialize, Serialize};

/// Indicator strength level (3-level quantization).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IndicatorStrength {
    Low,
    Medium,
    High,
}

impl IndicatorStrength {
    pub fn as_str(&self) -> &'static str {
        match self {
            IndicatorStrength::Low => "low",
            IndicatorStrength::Medium => "medium",
            IndicatorStrength::High => "high",
        }
    }

    /// Numeric weight for scoring.
    pub fn weight(&self) -> f32 {
        match self {
            IndicatorStrength::Low => 0.3,
            IndicatorStrength::Medium => 0.6,
            IndicatorStrength::High => 1.0,
        }
    }
}

impl std::fmt::Display for IndicatorStrength {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Indicator category for grouping.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IndicatorCategory {
    Psychological,
    Financial,
    Credential,
    Technical,
    Sender,
    Social,
    ECommerce,
    Lottery,
    Employment,
    Lure,
    Contact,
    Pii,
}

/// Indicator identifier (25 fixed indicators).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IndicatorId {
    Urgency,
    FinancialRequest,
    CredentialRequest,
    RemoteAccess,
    SenderAnomaly,
    PromiseHighReturn,
    AuthorityClaim,
    ThreatLegal,
    ThreatAccount,
    RomanceGrooming,
    DeliveryLure,
    PrizeLure,
    JobOffer,
    CharityAppeal,
    CryptoScheme,
    GiftCard,
    LinkSuspicious,
    PhoneCallback,
    PersonalInfoRequest,
    BankTransfer,
    VerificationRequest,
    LimitedTimeOffer,
    FreeGift,
    FamilyEmergency,
    TaxPenalty,
    Sextortion,
    RecoveryScam,
    GovernmentBenefitLure,
    FakeMarketplace,
    // New indicators for emerging scam patterns
    QRCodeScan,
    WrongNumberPivot,
    SubscriptionTrap,
    DeepfakeImpersonation,
}

impl IndicatorId {
    /// Stable string identifier for decision trace.
    pub fn as_str(&self) -> &'static str {
        match self {
            IndicatorId::Urgency => "urgency",
            IndicatorId::FinancialRequest => "financial_request",
            IndicatorId::CredentialRequest => "credential_request",
            IndicatorId::RemoteAccess => "remote_access",
            IndicatorId::SenderAnomaly => "sender_anomaly",
            IndicatorId::PromiseHighReturn => "promise_high_return",
            IndicatorId::AuthorityClaim => "authority_claim",
            IndicatorId::ThreatLegal => "threat_legal",
            IndicatorId::ThreatAccount => "threat_account",
            IndicatorId::RomanceGrooming => "romance_grooming",
            IndicatorId::DeliveryLure => "delivery_lure",
            IndicatorId::PrizeLure => "prize_lure",
            IndicatorId::JobOffer => "job_offer",
            IndicatorId::CharityAppeal => "charity_appeal",
            IndicatorId::CryptoScheme => "crypto_scheme",
            IndicatorId::GiftCard => "gift_card",
            IndicatorId::LinkSuspicious => "link_suspicious",
            IndicatorId::PhoneCallback => "phone_callback",
            IndicatorId::PersonalInfoRequest => "personal_info_request",
            IndicatorId::BankTransfer => "bank_transfer",
            IndicatorId::VerificationRequest => "verification_request",
            IndicatorId::LimitedTimeOffer => "limited_time_offer",
            IndicatorId::FreeGift => "free_gift",
            IndicatorId::FamilyEmergency => "family_emergency",
            IndicatorId::TaxPenalty => "tax_penalty",
            IndicatorId::Sextortion => "sextortion",
            IndicatorId::RecoveryScam => "recovery_scam",
            IndicatorId::GovernmentBenefitLure => "government_benefit_lure",
            IndicatorId::FakeMarketplace => "fake_marketplace",
            IndicatorId::QRCodeScan => "qr_code_scan",
            IndicatorId::WrongNumberPivot => "wrong_number_pivot",
            IndicatorId::SubscriptionTrap => "subscription_trap",
            IndicatorId::DeepfakeImpersonation => "deepfake_impersonation",
        }
    }

    /// Category for grouping.
    pub fn category(&self) -> IndicatorCategory {
        match self {
            IndicatorId::Urgency => IndicatorCategory::Psychological,
            IndicatorId::FinancialRequest => IndicatorCategory::Financial,
            IndicatorId::CredentialRequest => IndicatorCategory::Credential,
            IndicatorId::RemoteAccess => IndicatorCategory::Technical,
            IndicatorId::SenderAnomaly => IndicatorCategory::Sender,
            IndicatorId::PromiseHighReturn => IndicatorCategory::Financial,
            IndicatorId::AuthorityClaim => IndicatorCategory::Psychological,
            IndicatorId::ThreatLegal => IndicatorCategory::Psychological,
            IndicatorId::ThreatAccount => IndicatorCategory::Psychological,
            IndicatorId::RomanceGrooming => IndicatorCategory::Social,
            IndicatorId::DeliveryLure => IndicatorCategory::ECommerce,
            IndicatorId::PrizeLure => IndicatorCategory::Lottery,
            IndicatorId::JobOffer => IndicatorCategory::Employment,
            IndicatorId::CharityAppeal => IndicatorCategory::Social,
            IndicatorId::CryptoScheme => IndicatorCategory::Financial,
            IndicatorId::GiftCard => IndicatorCategory::Financial,
            IndicatorId::LinkSuspicious => IndicatorCategory::Technical,
            IndicatorId::PhoneCallback => IndicatorCategory::Contact,
            IndicatorId::PersonalInfoRequest => IndicatorCategory::Pii,
            IndicatorId::BankTransfer => IndicatorCategory::Financial,
            IndicatorId::VerificationRequest => IndicatorCategory::Credential,
            IndicatorId::LimitedTimeOffer => IndicatorCategory::Psychological,
            IndicatorId::FreeGift => IndicatorCategory::Lure,
            IndicatorId::FamilyEmergency => IndicatorCategory::Social,
            IndicatorId::TaxPenalty => IndicatorCategory::Financial,
            IndicatorId::Sextortion => IndicatorCategory::Social,
            IndicatorId::RecoveryScam => IndicatorCategory::Financial,
            IndicatorId::GovernmentBenefitLure => IndicatorCategory::Lure,
            IndicatorId::FakeMarketplace => IndicatorCategory::ECommerce,
            IndicatorId::QRCodeScan => IndicatorCategory::Technical,
            IndicatorId::WrongNumberPivot => IndicatorCategory::Social,
            IndicatorId::SubscriptionTrap => IndicatorCategory::Financial,
            IndicatorId::DeepfakeImpersonation => IndicatorCategory::Technical,
        }
    }

    /// All indicators as a slice.
    pub fn all() -> &'static [IndicatorId] {
        &[
            IndicatorId::Urgency,
            IndicatorId::FinancialRequest,
            IndicatorId::CredentialRequest,
            IndicatorId::RemoteAccess,
            IndicatorId::SenderAnomaly,
            IndicatorId::PromiseHighReturn,
            IndicatorId::AuthorityClaim,
            IndicatorId::ThreatLegal,
            IndicatorId::ThreatAccount,
            IndicatorId::RomanceGrooming,
            IndicatorId::DeliveryLure,
            IndicatorId::PrizeLure,
            IndicatorId::JobOffer,
            IndicatorId::CharityAppeal,
            IndicatorId::CryptoScheme,
            IndicatorId::GiftCard,
            IndicatorId::LinkSuspicious,
            IndicatorId::PhoneCallback,
            IndicatorId::PersonalInfoRequest,
            IndicatorId::BankTransfer,
            IndicatorId::VerificationRequest,
            IndicatorId::LimitedTimeOffer,
            IndicatorId::FreeGift,
            IndicatorId::FamilyEmergency,
            IndicatorId::TaxPenalty,
            IndicatorId::Sextortion,
            IndicatorId::RecoveryScam,
            IndicatorId::GovernmentBenefitLure,
            IndicatorId::FakeMarketplace,
            IndicatorId::QRCodeScan,
            IndicatorId::WrongNumberPivot,
            IndicatorId::SubscriptionTrap,
            IndicatorId::DeepfakeImpersonation,
        ]
    }

    /// Parse from string identifier.
    pub fn from_str(s: &str) -> Option<Self> {
        Self::all().iter().find(|i| i.as_str() == s).copied()
    }

    /// Human-readable label.
    pub fn label(&self) -> &'static str {
        match self {
            IndicatorId::Urgency => "Urgency",
            IndicatorId::FinancialRequest => "Financial Request",
            IndicatorId::CredentialRequest => "Credential Request",
            IndicatorId::RemoteAccess => "Remote Access",
            IndicatorId::SenderAnomaly => "Sender Anomaly",
            IndicatorId::PromiseHighReturn => "Promise High Return",
            IndicatorId::AuthorityClaim => "Authority Claim",
            IndicatorId::ThreatLegal => "Legal Threat",
            IndicatorId::ThreatAccount => "Account Threat",
            IndicatorId::RomanceGrooming => "Romance Grooming",
            IndicatorId::DeliveryLure => "Delivery Lure",
            IndicatorId::PrizeLure => "Prize Lure",
            IndicatorId::JobOffer => "Job Offer",
            IndicatorId::CharityAppeal => "Charity Appeal",
            IndicatorId::CryptoScheme => "Crypto Scheme",
            IndicatorId::GiftCard => "Gift Card Request",
            IndicatorId::LinkSuspicious => "Suspicious Link",
            IndicatorId::PhoneCallback => "Phone Callback",
            IndicatorId::PersonalInfoRequest => "Personal Info Request",
            IndicatorId::BankTransfer => "Bank Transfer Request",
            IndicatorId::VerificationRequest => "Verification Request",
            IndicatorId::LimitedTimeOffer => "Limited Time Offer",
            IndicatorId::FreeGift => "Free Gift",
            IndicatorId::FamilyEmergency => "Family Emergency",
            IndicatorId::TaxPenalty => "Tax Penalty",
            IndicatorId::Sextortion => "Sextortion",
            IndicatorId::RecoveryScam => "Recovery Scam",
            IndicatorId::GovernmentBenefitLure => "Government Benefit Lure",
            IndicatorId::FakeMarketplace => "Fake Marketplace",
            IndicatorId::QRCodeScan => "QR Code Scan",
            IndicatorId::WrongNumberPivot => "Wrong Number Pivot",
            IndicatorId::SubscriptionTrap => "Subscription Trap",
            IndicatorId::DeepfakeImpersonation => "Deepfake Impersonation",
        }
    }

    /// Multi-language keywords for this indicator.
    /// Returns (language_code, keywords) pairs.
    pub fn keywords(&self) -> IndicatorKeywords {
        match self {
            IndicatorId::Urgency => IndicatorKeywords {
                indicator: *self,
                en: &[
                    "urgent", "immediately", "asap", "act now", "right away",
                    "time-sensitive", "emergency", "without delay", "at once",
                    "don't wait", "hurry", "expires", "deadline",
                    "within 24 hours", "within 48 hours", "last chance",
                    "final notice", "action required", "response required",
                    // Additional urgency variants
                    "within 2 hours", "within 12 hours", "before midnight",
                    "last warning", "final warning", "final reminder",
                    "overdue", "past due", "late payment",
                    "do not ignore", "do not disregard",
                    "must respond", "must act", "must complete",
                    "failure to", "non-compliance",
                    "immediate action", "prompt action",
                    "delay will", "delay may result",
                ],
                vi: &[
                    "khẩn cấp", "gấp lắm", "ngay lập tức", "gấp", "nhanh lên",
                    "trong vòng", "còn hạn", "sắp hết hạn", "mau chóng", "đừng chờ",
                    // Unaccented variants (common in SMS)
                    "khan cap", "gap lam", "ngay lap tuc", "gap", "nhanh len",
                    "nap het han", "mau chung", "dung cho",
                    "trong vong", "con han", "sap het han",
                ],
                th: &[
                    "ด่วน", "เร่งด่วน", "ทันที", "ภายใน", "หมดเวลา",
                    "รีบ", "เร็วๆ", "อายุสั้น", "รีบด่วน",
                    // Additional urgency
                    "ภายใน 24 ชั่วโมง", "ภายใน 48 ชั่วโมง", "โอกาสสุดท้าย",
                    "แจ้งเตือนครั้งสุดท้าย", "ต้องดำเนินการ", "ห้ามเพิกเฉย",
                    "เร่งดำเนินการ", "หมดเขต", "กำหนดเวลา",
                ],
                id: &[
                    "segera", "darurat", "penting", "sekarang", "cepat",
                    "batas waktu", "berakhir", "segera lah",
                    // Additional urgency
                    "dalam 24 jam", "dalam 48 jam", "kesempatan terakhir",
                    "peringatan terakhir", "harus segera", "jangan abaikan",
                    "segera lakukan", "terlambat", "waktu habis",
                ],
                ms: &[
                    "segera", "kecemasan", "penting", "sekarang", "cepat",
                    "tarikh tamat", "tamat",
                    // Additional urgency
                    "dalam 24 jam", "dalam 48 jam", "peluang terakhir",
                    "amaran terakhir", "mesti segera", "jangan abaikan",
                    "segera bertindak", "lewat", "masa tamat",
                ],
                tl: &[
                    "urgent", "agad", "napakabilis", "panahon", "malapit na",
                    "hurry", "deadline", "expiry",
                    // Additional urgency
                    "within 24 hours", "within 48 hours", "huling pagkakataon",
                    "huling babala", "kailangan agad", "wag balewalain",
                    "agad kumilos", "late na", "matatapos na",
                ],
                km: &[
                    "បន្ទាន់", "លឿន", "ឥឡូវនេះ", "ក្នុងរយៈ", "ផុតកំណត់",
                    // Additional urgency
                    "ក្នុង 24 ម៉ោង", "ក្នុង 48 ម៉ោង", "ឱកាសចុងក្រោយ",
                    "ការព្រមានចុងក្រោយ", "ត្រូវធ្វើបន្ទាន់", "កុំមើលរំលង",
                ],
                zh: &["紧急", "立即", "马上", "赶快", "截止", "到期"],
                other: &[],
            },
            IndicatorId::FinancialRequest => IndicatorKeywords {
                indicator: *self,
                en: &[
                    "send money", "transfer money", "wire money",
                    "pay now", "send funds", "make a payment", "deposit",
                    "transfer funds", "send cash", "wire transfer",
                    "pay a fee", "clearance fee", "customs fee", "processing fee",
                    "release fee", "fee to release", "pay $", "pay to",
                    "payment required", "outstanding balance", "overdue",
                    "receive payments", "forward payments",
                    // Loan/approval keywords
                    "loan", "approved", "approval", "instant approval",
                    "no collateral", "no guarantor", "easy loan", "fast loan",
                    "cash loan", "personal loan", "credit approval",
                    "loan approved", "pre-approved", "lulus", "pinjaman",
                    // Overpayment/refund scam
                    "credited by mistake", "arrange the return",
                    "return the money", "refund the difference",
                    "credited in error", "wrongly credited",
                ],
                vi: &[
                    "chuyển tiền", "gửi tiền", "thanh toán", "nạp tiền",
                    "chuyển khoản", "gửi ngay", "nộp tiền",
                    "phí hải quan", "phí xử lý", "phí giải ngân",
                    "thanh toán phí", "nộp phí",
                    "phí hồ sơ", "phí đăng ký",
                    // Loan keywords
                    "vay", "khoản vay", "duyệt vay", "vay nhanh",
                    "vay tín chấp", "vay không cần thế chấp",
                    // Unaccented
                    "chuyen tien", "gui tien", "thanh toan", "nap tien",
                    "chuyen khoan", "gui ngay", "nop tien",
                    "phi hai quan", "phi xu ly", "phi giai ngan",
                    "thanh toan phi", "nop phi",
                    "khoan vay", "duyet vay", "vay nhanh",
                    "vay tin chap", "vay khong can the chap",
                ],
                th: &[
                    "โอนเงิน", "ส่งเงิน", "จ่ายเงิน", "โอนเงินเข้า",
                    "เก็บเงิน", "ชำระเงิน",
                    // Loan keywords
                    "สินเชื่อ", "อนุมัติ", "กู้เงิน", "สินเชื่อส่วนบุคคล",
                    "อนุมัติเร็ว",
                    // Additional financial request
                    "ค่าธรรมเนียม", "ค่าดำเนินการ", "ค่าขนส่ง",
                    "วางเงินค้ำประกัน", "ชำระค่าปรับ",
                ],
                id: &[
                    "kirim uang", "transfer uang", "bayar", "transfer dana",
                    "kirim dana", "pembayaran",
                    // Loan keywords
                    "pinjaman", "disetujui", "persetujuan", "tanpa agunan",
                    "pinjaman cepat", "kredit",
                    // Additional financial request
                    "biaya administrasi", "biaya proses", "biaya kirim",
                    "bayar denda", "bayar biaya", "transfer sekarang",
                ],
                ms: &[
                    "hantar wang", "pindah wang", "bayar", "pindahan dana",
                    "bayaran", "kirim duit",
                    // Loan keywords
                    "pinjaman", "diluluskan", "kelulusan", "tanpa penjamin",
                    "pinjaman cepat", "kredit",
                    // Additional financial request
                    "fi pentadbiran", "fi proses", "fi penghantaran",
                    "bayar denda", "bayar fi", "pindah sekarang",
                ],
                tl: &[
                    "magpadala ng pera", "bayad", "transfer", "padala",
                    "ipadala ang pera", "kabayaran",
                    // Loan keywords
                    "utang", "loan", "approved", "walang collateral",
                    "payday loan",
                    // Additional financial request
                    "bayad na", "processing fee", "admin fee",
                    "bayad ang multa", "ilipat ang pera",
                ],
                km: &[
                    "ផ្ញើប្រាក់", "ផ្ទេរប្រាក់", "បង់ប្រាក់", "បង់ថ្លៃ",
                    // Loan keywords
                    "ប្រាក់កម្ចី", "អនុម័ត", "ឥណទាន",
                    // Additional financial request
                    "ថ្លៃចំណាយ", "ថ្លៃដំណើរការ", "បង់ប្រាក់ពិន័យ",
                ],
                zh: &["转账", "汇款", "付款", "打钱", "支付", "贷款", "批准", "无抵押", "快速放款"],
                other: &[],
            },
            IndicatorId::CredentialRequest => IndicatorKeywords {
                indicator: *self,
                en: &[
                    "password", "otp", "verification code", "passcode",
                    "one-time password", "2fa code", "security code",
                    "enter your password", "confirm your password",
                    "enter your pin", "forward the code", "send the code", "send the otp",
                    "forward the otp", "share the code", "send us the code",
                    "code you just received", "6-digit code",
                    "share this code", "share the otp",
                ],
                vi: &[
                    "mật khẩu", "mã otp", "mã xác nhận", "mã bảo mật",
                    "nhập mật khẩu", "mã pin",
                    "gửi mã", "forward mã", "mã 6 số",
                    "xác thực", "chia sẻ mã",
                    // Unaccented
                    "mat khau", "ma otp", "ma xac nhan", "ma bao mat",
                    "nhap mat khau", "ma pin",
                    "gui ma", "forward ma", "ma 6 so",
                    "xac thuc", "chia se ma",
                ],
                th: &[
                    "รหัสผ่าน", "รหัส otp", "รหัสยืนยัน", "รหัสลับ",
                    "กรอกรหัสผ่าน", "รหัส pin",
                    // Additional credential request
                    "รหัส 6 หลัก", "รหัสยืนยันตัวตน", "รหัสความปลอดภัย",
                    "แชร์รหัส", "ส่งรหัส", "ห้ามแชร์รหัส",
                ],
                id: &[
                    "kata sandi", "kode otp", "kode verifikasi", "kode keamanan",
                    "masukkan kata sandi", "pin",
                    // Additional credential request
                    "kode 6 digit", "kode verifikasi identitas", "bagikan kode",
                    "kirim kode", "jangan bagikan kode",
                ],
                ms: &[
                    "kata laluan", "kod otp", "kod pengesahan", "kod keselamatan",
                    "masukkan kata laluan", "pin",
                    // Additional credential request
                    "kod 6 digit", "kod pengesahan identiti", "kongsi kod",
                    "hantar kod", "jangan kongsi kod",
                ],
                tl: &[
                    "password", "otp", "verification code", "passcode",
                    "pumasok ng password", "code",
                    // Additional credential request
                    "6-digit code", "security code", "ibahagi ang code",
                    "ipadala ang code", "wag ibahagi ang code",
                ],
                km: &[
                    "ពាក្យសម្ងាត់", "កូដ otp", "កូដផ្ទៀងផ្ទាត់", "កូដសុវត្ថិភាព",
                    // Additional credential request
                    "កូដ 6 ខ្ទង់", "កូដផ្ទៀងផ្ទាត់អត្តសញ្ញាណ", "ចែករំលែកកូដ",
                    "ផ្ញើកូដ", "កុំចែករំលែកកូដ",
                ],
                zh: &["密码", "验证码", "动态码", "安全码", "一次性密码"],
                other: &[],
            },
            IndicatorId::RemoteAccess => IndicatorKeywords {
                indicator: *self,
                en: &[
                    "install this app", "remote access", "anydesk", "teamviewer",
                    "screen sharing", "allow access", "grant access",
                    "download this software", "run this program",
                ],
                vi: &[
                    "cài đặt ứng dụng", "truy cập từ xa", "cho phép truy cập",
                    "tải ứng dụng này", "chia sẻ màn hình",
                ],
                th: &[
                    "ติดตั้งแอป", "เข้าถึงระยะไกล", "อนุญาตเข้าถึง",
                    "ดาวน์โหลดแอปนี้", "แชร์หน้าจอ",
                ],
                id: &[
                    "instal aplikasi", "akses jarak jauh", "izinkan akses",
                    "unduh aplikasi ini", "berbagi layar",
                ],
                ms: &[
                    "pasang aplikasi", "akses jauh", "benarkan akses",
                    "muat turun aplikasi", "kongsi skrin",
                ],
                tl: &[
                    "i-install ang app", "remote access", "payagan ang access",
                    "i-download ito", "screen sharing",
                ],
                km: &[
                    "ដំឡើងកម្មវិធី", "ការចូលប្រើពីចម្ងាយ", "អនុញ្ញាតចូលប្រើ",
                ],
                zh: &["安装应用", "远程访问", "允许访问", "下载软件", "屏幕共享"],
                other: &[],
            },
            IndicatorId::SenderAnomaly => IndicatorKeywords {
                indicator: *self,
                en: &[
                    "dear customer", "dear user", "dear valued customer",
                    "your bank", "your account", "notice from",
                    "official notification", "important notice",
                    "dear member", "valued member", "dear client",
                    "important message", "account holder",
                ],
                vi: &[
                    "thân gửi khách hàng", "ngân hàng của bạn", "tài khoản của bạn",
                    "thông báo từ", "thông báo chính thức",
                    "ngân hàng nhà nước", "vietcombank", "techcombank",
                    "bidv", "mb bank", "agribank", "vietinbank",
                    "acb", "tpbank", "vpbank",
                    // Unaccented variants
                    "ngan hang", "tai khoan cua ban", "thong bao",
                    "ngan hang nha nuoc",
                ],
                th: &[
                    "เรียนลูกค้า", "ธนาคารของคุณ", "บัญชีของคุณ",
                    "แจ้งจาก", "แจ้งอย่างเป็นทางการ",
                ],
                id: &[
                    "pelanggan yang terhormat", "bank anda", "akun anda",
                    "pemberitahuan dari", "notifikasi resmi",
                ],
                ms: &[
                    "pelanggan yang dihormati", "bank anda", "akaun anda",
                    "pemberitahuan dari", "notis rasmi",
                ],
                tl: &[
                    "dear customer", "mahal na customer", "iyong bank",
                    "abiso mula", "opisyal na abiso",
                ],
                km: &[
                    "អ្នកអតិថិជនជាទីស្រលាញ់", "ធនាគាររបស់អ្នក", "គណនីរបស់អ្នក",
                ],
                zh: &["尊敬的客户", "您的银行", "您的账户", "通知", "官方通知"],
                other: &[],
            },
            IndicatorId::PromiseHighReturn => IndicatorKeywords {
                indicator: *self,
                en: &[
                    "guaranteed return", "risk-free", "high return",
                    "double your money", "passive income", "easy money",
                    "100% profit", "no risk", "guaranteed profit",
                    "guaranteed 30%", "roi", "returns in", "profit guaranteed",
                    "capital protection", "annual yield",
                    "pre-ipo", "pre-ipo shares", "pool funds",
                    "investment opportunity", "exclusive allocation",
                    "high yield", "monthly return", "lãi suất cao",
                    "investment club", "guaranteed 8%", "8% annual",
                    "30% returns", "5x return", "lợi nhuận gấp",
                    "annual returns", "consistent returns",
                    "20% annual", "50% apy", "double your",
                    "fund has delivered", "fund delivered",
                    "ipo allocation", "serious investors",
                    "exclusive ipo", "brokerage",
                    "digital currency investment", "government-backed",
                    "regulatory freeze", "investment portfolio",
                    "bond investment matured", "reinvest now",
                    // Additional investment lure patterns
                    "grow your savings", "let your money work",
                    "financial freedom", "wealth building",
                    "retire early", "multiply your savings",
                    "insider tip", "insider information",
                    "signal group", "trading signals",
                    "copy my trades", "follow my trades",
                    "managed account", "account management",
                    "pamm account", "social trading",
                ],
                vi: &[
                    "lợi nhuận đảm bảo", "không rủi ro", "thu nhập thụ động",
                    "tiền dễ kiếm", "lãi suất cao", "đảm bảo lợi nhuận",
                    "cam kết", "lợi nhuận cam kết", "đầu tư vàng",
                    "vốn tối thiểu", "chứng khoán", "đầu tư tiền ảo",
                    "cơ hội đầu tư", "rút vốn linh hoạt", "lãi suất cố định",
                    // Unaccented
                    "cam ket", "loi nhuan cam ket", "dau tu vang",
                    "von toi thieu", "chung khoan",
                    "dau tu", "loi nhuan", "co phieu", "trai phieu",
                    "lai suat cao", "lai suat co dinh", "rut von linh hoat",
                    "co hoi dau tu", "dau tu tien ao",
                    // Stock tips / insider info
                    "sắp bùng nổ", "sap bung no", "phân tích nội bộ",
                    "phan tich noi bo", "danh mục khuyến nghị",
                    "danh muc khuyen nghi", "chuyên gia",
                    "chuyen gia", "đầu tư vip", "dau tu vip",
                    "cổ phiếu chưa niêm yết", "co phieu chua niem yet",
                    "otc", "ipo", "ưu đãi giá", "uu dai gia",
                    "dự kiến giá ipo", "du kien gia ipo",
                    "bùng nổ", "bung no",
                    // Bond/reinvest
                    "trái phiếu đáo hạn", "trai phieu dao han",
                    "đầu tư lại", "dau tu lai",
                    // Extra income / task scams
                    "thu nhập thêm", "thu nhap them",
                    "làm nhiệm vụ", "lam nhiem vu",
                    "hoàn thành nhiệm vụ", "hoan thanh nhiem vu",
                    // Business partnership / investment lure
                    "hợp tác kinh doanh", "hop tac kinh doanh",
                    "siêu lợi nhuận", "sieu loi nhuan",
                    "đối tác đầu tư", "doi tac dau tu",
                    "cơ hội hợp tác", "co hoi hop tac",
                ],
                th: &[
                    "ผลตอบแทนรับประกัน", "ไม่มีความเสี่ยง", "รายได้เฉื่อย",
                    "เงินง่าย", "กำไรสูง", "รับประกันกำไร",
                ],
                id: &[
                    "keuntungan dijamin", "tanpa risiko", "pendapatan pasif",
                    "uang mudah", "keuntungan tinggi", "untung pasti",
                ],
                ms: &[
                    "pulangan dijamin", "tiada risiko", "pendapatan pasif",
                    "duit mudah", "keuntungan tinggi", "untung pasti",
                ],
                tl: &[
                    "guaranteed return", "walang risk", "passive income",
                    "easy money", "malaking tubo", "tiyak na kita",
                ],
                km: &[
                    "ប្រាក់ចំណូលរកបានជាក់លាក់", "គ្មានហានិករ", "ប្រាក់ចំណូលអកម្ម",
                ],
                zh: &["保证回报", "零风险", "高收益", "被动收入", "稳赚不赔"],
                other: &[],
            },
            IndicatorId::AuthorityClaim => IndicatorKeywords {
                indicator: *self,
                en: &[
                    "this is the police", "from the government", "from the bank",
                    "official", "on behalf of", "this is microsoft",
                    "this is apple", "from the tax office",
                    "calling from", "police department", "fraud department",
                    "security team", "i'm from", "we are from",
                    "investigation", "law enforcement",
                    // Brand impersonation
                    "apple security", "apple update", "google security",
                    "microsoft security", "garena security", "steam security",
                    "account security update", "security update",
                    "subscription update", "your subscription",
                    "confirm your subscription", "account suspended",
                    "account deactivated", "account locked", "account blocked",
                    "account compromised", "suspicious activity",
                    "unauthorized access", "unusual activity",
                ],
                vi: &[
                    "công an", "chính phủ", "ngân hàng nhà nước",
                    "cơ quan chức năng", "đại diện", "tổng cục thuế",
                    "cảnh sát", "điện lực", "cấp nước",
                    "viễn thông", "tổng cục hải quan",
                    // Unaccented
                    "cong an", "chinh phu", "co quan chuc nang",
                    "canh sat", "dien luc", "cap nuoc",
                    "vien thong", "tong cuc hai quan",
                    // Brand impersonation
                    "bảo mật", "cập nhật bảo mật", "tài khoản bị khóa",
                    "tài khoản bị đình chỉ", "hoạt động đáng ngờ",
                ],
                th: &[
                    "ตำรวจ", "รัฐบาล", "ธนาคารแห่งประเทศ",
                    "เจ้าหน้าที่", "ในนามของ", "กรมสรรพากร",
                    // Brand impersonation
                    "การรักษาความปลอดภัย", "อัปเดตความปลอดภัย",
                    "บัญชีถูกระงับ", "บัญชีถูกล็อก", "กิจกรรมผิดปกติ",
                ],
                id: &[
                    "polisi", "pemerintah", "bank indonesia",
                    "pejabat resmi", "atas nama", "direktorat pajak",
                    // Brand impersonation
                    "keamanan", "pembaruan keamanan", "akun diblokir",
                    "akun dinonaktifkan", "aktivitas mencurigakan",
                ],
                ms: &[
                    "polis", "kerajaan", "bank negara",
                    "pegawai rasmi", "atas nama", "lembaga hasil",
                    // Brand impersonation
                    "keselamatan", "kemas kini keselamatan", "akaun disekat",
                    "akaun dinyahaktifkan", "aktiviti mencurigakan",
                ],
                tl: &[
                    "pulis", "gobyerno", "bangko",
                    "opisyal", "sa ngalan ng", "bureau of internal revenue",
                    // Brand impersonation
                    "seguridad", "update sa seguridad", "na-block ang account",
                    "na-deactivate", "nakakahinuhang aktibidad",
                ],
                km: &[
                    "នគរបាល", "រដ្ឋាភិបាល", "ធនាគារជាតិ",
                    // Brand impersonation
                    "សន្តិសុខ", "ការអាប់ដេតសន្តិសុខ",
                    "គណនីត្រូវបានចាក់សោ", "សកម្មភាពសង្ស័យ",
                ],
                zh: &["警察", "政府", "银行", "官方", "代表", "税务局", "安全更新", "账户被锁", "账户被停用", "可疑活动"],
                other: &[],
            },
            IndicatorId::ThreatLegal => IndicatorKeywords {
                indicator: *self,
                en: &[
                    "legal action", "lawsuit", "arrest", "warrant",
                    "court order", "criminal charges", "police will come",
                    "you will be arrested", "prosecution",
                ],
                vi: &[
                    "khởi kiện", "bắt giữ", "lệnh bắt", "truy cứu trách nhiệm",
                    "đưa ra tòa", "công an sẽ đến",
                ],
                th: &[
                    "ดำเนินคดี", "จับกุม", "หมายจับ", "ฟ้องร้อง",
                    "ขึ้นศาล", "ตำรวจจะมา",
                ],
                id: &[
                    "tuntutan hukum", "penangkapan", "surat perintah",
                    "tuntutan pidana", "ke pengadilan", "polisi akan datang",
                ],
                ms: &[
                    "tindakan undang-undang", "tangkap", "waran tangkap",
                    "tuduhan jenayah", "ke mahkamah", "polis akan datang",
                ],
                tl: &[
                    "demanda", "aresto", "warrant", "kaso",
                    "korte", "dadalhin sa korte",
                ],
                km: &[
                    "វិវាទច្បាប់", "ចាប់ខ្លួន", "ផ្ដាច់កាត់", "នីតិកម្ម",
                ],
                zh: &["起诉", "逮捕", "搜查令", "刑事指控", "上法庭", "法办"],
                other: &[],
            },
            IndicatorId::ThreatAccount => IndicatorKeywords {
                indicator: *self,
                en: &[
                    "account suspended", "account closed", "account deactivated",
                    "service terminated", "account locked", "will be blocked",
                    "permanently disabled", "account will be deleted",
                    "unusual activity", "unauthorized access", "suspicious transaction",
                    "unrecognized device", "suspicious activity", "suspended due to",
                    "account has been suspended", "permanently locked",
                    "will be suspended", "will be closed", "will be terminated",
                    "account will be frozen", "will be frozen",
                    "account flagged", "suspicious login",
                    "sim swap", "sim card swap", "number transfer",
                    "port out request", "sim swap request",
                ],
                vi: &[
                    "tài khoản bị khóa", "tài khoản bị đóng", "ngừng hoạt động",
                    "tài khoản bị chặn", "khóa vĩnh viễn",
                    // Unaccented variants
                    "tai khoan bi khoa", "tai khoan bi dong", "khoa vinh vien",
                    "đăng nhập lạ", "giao dịch bất thường", "phát hiện bất thường",
                    "tạm khóa", "bị đánh cắp",
                ],
                th: &[
                    "บัญชีถูกระงับ", "บัญชีถูกปิด", "ยกเลิกบริการ",
                    "บัญชีถูกล็อค", "บล็อกถาวร",
                ],
                id: &[
                    "akun ditangguhkan", "akun ditutup", "layanan dihentikan",
                    "akun dikunci", "blokir permanen",
                ],
                ms: &[
                    "akaun digantung", "akaun ditutup", "perkhidmatan dihentikan",
                    "akaun dikunci", "sekat kekal",
                ],
                tl: &[
                    "account suspended", "account closed", "service terminated",
                    "account locked", "block permanently",
                ],
                km: &[
                    "គណនីត្រូវបានផ្អាក", "គណនីត្រូវបានបិទ", "បញ្ឈប់សេវាកម្ម",
                ],
                zh: &["账户暂停", "账户关闭", "服务终止", "账户锁定", "永久封禁"],
                other: &[],
            },
            IndicatorId::RomanceGrooming => IndicatorKeywords {
                indicator: *self,
                en: &[
                    "i love you", "fall in love", "my darling", "my love",
                    "soulmate", "destiny brought us", "i've never felt this way",
                    "we are meant to be", "sweetheart",
                ],
                vi: &[
                    "anh yêu em", "em yêu anh", "tình yêu", "định mệnh",
                    "người yêu ơi", "một đời một người",
                ],
                th: &[
                    "รักคุณ", "หลงรัก", "ชะตาชีวิต", "คนรัก",
                    "เนื้อคู่", "รักแท้",
                ],
                id: &[
                    "aku cinta padamu", "jatuh cinta", "jodoh", "sayang",
                    "belahan jiwa", "cinta sejati",
                ],
                ms: &[
                    "saya sayang awak", "jatuh cinta", "jodoh", "sayang",
                    "belahan jiwa", "cinta sejati",
                ],
                tl: &[
                    "mahal kita", "iniibig kita", "tadhana", "sweetheart",
                    "soulmate", "minamahal",
                ],
                km: &[
                    "អាណាចំរុះ", "ស្នេហ៍", "ចំណុះវាសនា", "សង្សារ",
                ],
                zh: &["我爱你", "坠入爱河", "命中注定", "亲爱的", "灵魂伴侣"],
                other: &[],
            },
            IndicatorId::DeliveryLure => IndicatorKeywords {
                indicator: *self,
                en: &[
                    "reschedule delivery", "package held",
                    "delivery failed", "delivery issue", "delivery problem",
                    "shipping issue",
                    "update your address", "address update", "held at customs",
                    "customs fee", "clearance fee", "release your parcel",
                    "delivery pending", "package waiting",
                    "redelivery fee", "parcel held", "package held at",
                    "delivery on hold", "shipment held",
                    "insurance claim", "verification fee",
                    "replacement", "documentation confirmation",
                    "could not be delivered", "confirm your address",
                ],
                vi: &[
                    "gói hàng", "giao hàng", "kiện hàng", "theo dõi đơn hàng",
                    "lên lịch lại", "giao hàng thất bại",
                    "phí hải quan", "kiện hàng bị giữ", "cập nhật địa chỉ",
                    // Unaccented
                    "goi hang", "giao hang", "kien hang", "theo doi don hang",
                    "len lich lai", "giao hang that bai",
                    "phi hai quan", "kien hang bi giu", "cap nhat dia chi",
                ],
                th: &[
                    "พัสดุ", "จัดส่ง", "พัสดุภาค", "ติดตามพัสดุ",
                    "นัดหมายใหม่", "จัดส่งล้มเหลว",
                    // Additional delivery lure
                    "พัสดุติดค้าง", "ค่าธรรมเนียมศุลกากร", "ด่านศุลกากร",
                    "อัปเดตที่อยู่", "ค่าจัดส่งใหม่", "เก็บที่สาขา",
                ],
                id: &[
                    "paket", "pengiriman", "lacak paket", "jadwal ulang",
                    "pengiriman gagal", "kurir",
                    // Additional delivery lure
                    "paket tertahan", "biaya bea cukai", "paket ditahan",
                    "perbarui alamat", "biaya kirim ulang", "ambil di kantor",
                ],
                ms: &[
                    "pekese", "penghantaran", "jejak pesanan", "jadual semula",
                    "penghantaran gagal", "kurier",
                    // Additional delivery lure
                    "pakej tertahan", "fi kastam", "pakej ditahan",
                    "kemas kini alamat", "fi hantar semula", "ambil di pejabat",
                ],
                tl: &[
                    "package", "delivery", "parcel", "tracking",
                    "reschedule", "delivery failed", "courier",
                    // Additional delivery lure
                    "nai-hold ang package", "customs fee", "na-detain ang parcel",
                    "update address", "redelivery fee", "pick up sa branch",
                ],
                km: &[
                    "កញ្ចប់", "ការដឹកជញ្ជូន", "តាមដានការបញ្ជូន", "បរាជ័យ",
                    // Additional delivery lure
                    "កញ្ចប់ត្រូវបានកាន់កាប់", "ថ្លៃគយ", "បន្ទាប់ផ្ទះ",
                    "ធ្វើបច្ចុប្បន្នភាពអាសយដ្ឋាន", "ថ្លៃដឹកជញ្ជូនឡើងវិញ",
                ],
                zh: &["包裹", "快递", "派送", "追踪", "重新安排", "派送失败"],
                other: &[],
            },
            IndicatorId::PrizeLure => IndicatorKeywords {
                indicator: *self,
                en: &[
                    "you've won", "congratulations", "winner", "prize",
                    "lottery", "sweepstakes", "lucky draw", "selected to win",
                    "claim your prize", "cashback reward", "claim at",
                    "free credit", "redeem now", "trúng thưởng", "hoàn tiền",
                    "you've accumulated enough", "claim your reward",
                ],
                vi: &[
                    "bạn đã thắng", "chúc mừng", "trúng thưởng", "xổ số",
                    "giải thưởng", "quay số trúng thưởng",
                    "trúng giải", "nhận thưởng", "khuyến mãi",
                    // Unaccented
                    "ban da thang", "chuc mung", "trung thuong", "xo so",
                    "giai thuong", "quay so trung thuong",
                    "trung giai", "nhan thuong", "khuyen mai",
                ],
                th: &[
                    "คุณได้รับรางวัล", "ยินดีด้วย", "ถูกรางวัล", "ลอตเตอรี่",
                    "รางวัล", "จับรางวัล",
                    // Additional prize lure
                    "คูปังงาน", "รับรางวัล", "เครดิตฟรี", "แลกของรางวัล",
                    "โบนัส", "สิทธิพิเศษ",
                ],
                id: &[
                    "anda menang", "selamat", "undian", "lotre",
                    "hadiah", "beruntung",
                    // Additional prize lure
                    "voucher", "klaim hadiah", "kredit gratis", "tukar hadiah",
                    "bonus", "spesial",
                ],
                ms: &[
                    "anda menang", "tahniah", "undi", "loteri",
                    "hadiah", "bertuah",
                    // Additional prize lure
                    "baucar", "tuntut hadiah", "kredit percuma", "tukar hadiah",
                    "bonus", "istimewa",
                ],
                tl: &[
                    "panalo ka", "congratulations", "premyo", "lottery",
                    "sweepstakes", "lucky draw",
                    // Additional prize lure
                    "voucher", "claim premyo", "free credit", "palit premyo",
                    "bonus", "espesyal",
                ],
                km: &[
                    "អ្នកឈ្នះ", "អបអរសាទរ", "រង្វាន់", "ឆ្នោត",
                    // Additional prize lure
                    "វ៉ៅច័រ", "ទទួលរង្វាន់", "ឥតគិតថ្លៃ", "ប្តូររង្វាន់",
                ],
                zh: &["中奖", "恭喜", "奖品", "彩票", "抽奖", "幸运"],
                other: &[],
            },
            IndicatorId::JobOffer => IndicatorKeywords {
                indicator: *self,
                en: &[
                    "work from home", "easy job", "earn money", "part-time job",
                    "no experience needed", "high salary", "task completion",
                    "data entry", "click ads", "commission",
                    "product reviewer", "mystery shopper",
                    "flexible hours", "no formal requirements",
                    "thu nhập", "CTV online", "việc làm tại nhà",
                    "remote product", "hiring remote", "$200/review",
                    "limited positions", "apply now",
                    "recruiter", "opening for", "contract role",
                    "data annotation", "admin assistant",
                    "finance analyst", "digital marketing role",
                    "great fit", "send your cv", "linkedin profile",
                    "$3,500/month", "$8,000/month",
                    "social media manager", "fintech startup",
                    "$4,000/month", "software license",
                    // Task scam patterns
                    "extra income", "simple tasks", "complete tasks",
                    "write review", "per day", "per task",
                    "hire people", "task scam",
                ],
                vi: &[
                    "làm việc tại nhà", "việc làm dễ", "kiếm tiền",
                    "việc bán thời gian", "không cần kinh nghiệm",
                    "CTV", "hoa hồng", "thu nhập",
                    "xử lý đơn hàng", "khảo sát online",
                    "viết review", "nhận ngay", "thu nhập siêu",
                    "tuyển gấp", "nhân viên nhập liệu",
                    // Unaccented
                    "lam viec tai nha", "viec lam de", "kiem tien",
                    "viec ban thoi gian", "khong can kinh nghiem",
                    "hoa hong", "thu nhap",
                    "xu ly don hang", "khao sat online",
                    "viet review", "nhan ngay", "thu nhap sieu",
                    "tuyen gap", "nhan vien nhap lieu",
                    // Additional Vietnamese job scam patterns
                    "quan ly fanpage", "lương cao", "luong cao",
                    "viec lam remote", "ho tro xin grant",
                ],
                th: &[
                    "ทำงานที่บ้าน", "งานง่าย", "หาเงิน", "งานพาร์ทไทม์",
                    "ไม่ต้องมีประสบการณ์",
                ],
                id: &[
                    "kerja dari rumah", "kerja mudah", "cari uang",
                    "kerja paruh waktu", "tanpa pengalaman",
                ],
                ms: &[
                    "kerja dari rumah", "kerja mudah", "cari duit",
                    "kerja sambilan", "tanpa pengalaman",
                ],
                tl: &[
                    "work from home", "trabaho", "kita", "part-time",
                    "no experience needed", "easy job",
                ],
                km: &[
                    "ធ្វើការនៅផ្ទះ", "ការងារងាយ", "រកលុយ", "ការងារពេកវេនា",
                ],
                zh: &["在家工作", "轻松赚钱", "兼职", "无需经验", "高薪"],
                other: &[],
            },
            IndicatorId::CharityAppeal => IndicatorKeywords {
                indicator: *self,
                en: &[
                    "donate", "donation", "charity", "help victims",
                    "disaster relief", "support our cause", "every dollar helps",
                    "fundraiser",
                ],
                vi: &[
                    "quyên góp", "từ thiện", "giúp nạn nhân", "cứu trợ",
                    "ủng hộ", "mỗi đồng đều quý",
                    "đồng bào", "bão lũ", "lũ lụt",
                    "đóng góp", "mọi đóng góp", "miền Trung",
                    // Unaccented
                    "quyen gop", "tu thien", "giup nan nhan", "cuu tro",
                    "ung ho", "dong bao", "bao lu", "lu lut",
                    "dong gop", "moi dong gop", "mien trung",
                ],
                th: &[
                    "บริจาค", "การกุศล", "ช่วยเหลือผู้ประสบภัย", "บรรเทาทุกข์",
                    "สนับสนุน",
                ],
                id: &[
                    "donasi", "amal", "bantu korban", "bantuan bencana",
                    "dukung kami",
                ],
                ms: &[
                    "derma", "kebajikan", "bantu mangsa", "bantuan bencana",
                    "sokong kami",
                ],
                tl: &[
                    "donate", "donasyon", "tulong", "kawanggawa",
                    "biktima", "relief",
                ],
                km: &[
                    "បរិច្ចារ", "សប្បុរសធម៌", "ជួយនរការរងគ្រោះ", "ជួយទុក្ខធុរៈ",
                ],
                zh: &["捐款", "慈善", "救助", "赈灾", "献爱心"],
                other: &[],
            },
            IndicatorId::CryptoScheme => IndicatorKeywords {
                indicator: *self,
                en: &[
                    "crypto", "bitcoin", "ethereum", "forex", "trading",
                    "mining", "nft", "token sale", "ico", "defi",
                    "blockchain investment",
                    // Modern crypto/web3 scam vocabulary
                    "staking", "airdrop", "yield farming", "liquidity pool",
                    "web3", "ai trading bot", "auto trading", "copy trading",
                    "mint", "nft mint", "presale", "token presale",
                    "solanac", "solana", "usdt", "usdc", "binance",
                    "metaverse", "play to earn", "p2e", "gamefi",
                    "smart contract", "wallet connect", "seed phrase",
                    "recovery phrase", "private key", "connect wallet",
                ],
                vi: &[
                    "tiền ảo", "bitcoin", "forex", "đầu tư tiền điện tử",
                    "khai thác", "token", "ico",
                ],
                th: &[
                    "คริปโต", "บิตคอยน์", "forex", "เทรด", "ขุด",
                    "โทเคน", "ico",
                    // Additional crypto
                    "สตาร์คิง", "เอียร์ดรอป", "nft", "web3",
                    "วอลเล็ต", "กระเป๋าเงินดิจิทัล", "เชื่อมต่อวอลเล็ต",
                ],
                id: &[
                    "kripto", "bitcoin", "forex", "trading", "menambang",
                    "token", "ico",
                    // Additional crypto
                    "staking", "airdrop", "nft", "web3",
                    "wallet", "dompet digital", "hubungkan wallet",
                ],
                ms: &[
                    "kripto", "bitcoin", "forex", "trading", "lombong",
                    "token", "ico",
                    // Additional crypto
                    "staking", "airdrop", "nft", "web3",
                    "wallet", "dompet digital", "sambung wallet",
                ],
                tl: &[
                    "crypto", "bitcoin", "forex", "trading", "mining",
                    "token", "ico",
                ],
                km: &[
                    "គ្រីបតូ", "ប៊ីតកូអ៊ីន", "forex", "ជួញដូរ",
                ],
                zh: &["加密货币", "比特币", "以太坊", "外汇", "交易", "挖矿"],
                other: &[],
            },
            IndicatorId::GiftCard => IndicatorKeywords {
                indicator: *self,
                en: &[
                    "gift card", "steam card", "google play card",
                    "itunes card", "amazon card", "apple gift card",
                    "buy gift cards", "pay with gift card",
                ],
                vi: &[
                    "thẻ quà tặng", "thẻ steam", "thẻ google play",
                    "thẻ itunes", "thẻ cào",
                ],
                th: &[
                    "บัตรของขวัญ", "สตีมการ์ด", "google play",
                    "itunes card", "บัตรเติมเงิน",
                ],
                id: &[
                    "kartu hadiah", "steam card", "google play card",
                    "itunes card", "beli kartu hadiah",
                ],
                ms: &[
                    "kad hadiah", "steam card", "google play card",
                    "itunes card", "beli kad hadiah",
                ],
                tl: &[
                    "gift card", "steam card", "google play",
                    "itunes card", "buy gift card",
                ],
                km: &[
                    "កាតអំណោយ", "កាត steam", "google play",
                ],
                zh: &["礼品卡", "Steam卡", "Google Play卡", "充值卡"],
                other: &[],
            },
            IndicatorId::LinkSuspicious => IndicatorKeywords {
                indicator: *self,
                en: &[
                    "bit.ly", "tinyurl", "shorte.st", "cutt.ly",
                    "click here", "visit this link", "check this out",
                ],
                vi: &[
                    "bấm vào đây", "truy cập link", "xem tại đây",
                    "nhấp vào liên kết",
                ],
                th: &[
                    "คลิกที่นี่", "เข้าชมลิงก์", "ดูที่นี่",
                    "คลิกลิงก์",
                ],
                id: &[
                    "klik di sini", "kunjungi link", "lihat di sini",
                    "klik link",
                ],
                ms: &[
                    "klik di sini", "lawati pautan", "lihat di sini",
                    "klik pautan",
                ],
                tl: &[
                    "click here", "puntahan", "tingnan ito",
                    "click link",
                ],
                km: &[
                    "ចុចនៅទីនេះ", "ចូលទៅកាន់តំណ", "មើលនៅទីនេះ",
                ],
                zh: &["点击这里", "访问链接", "查看这里", "点击链接"],
                other: &[],
            },
            IndicatorId::PhoneCallback => IndicatorKeywords {
                indicator: *self,
                en: &[
                    "call this number", "call now", "call us",
                    "contact us at", "dial", "phone number",
                    "hotline", "call back", "please call",
                ],
                vi: &[
                    "gọi số này", "gọi ngay", "liên hệ số",
                    "đường dây nóng", "gọi lại",
                ],
                th: &[
                    "โทรหมายเลขนี้", "โทรเลย", "ติดต่อ",
                    "สายด่วน", "โทรกลับ",
                ],
                id: &[
                    "hubungi nomor ini", "telepon sekarang", "hubungi kami",
                    "hotline", "telepon balik",
                ],
                ms: &[
                    "hubungi nombor ini", "telefon sekarang", "hubungi kami",
                    "hotline", "telefon balik",
                ],
                tl: &[
                    "tawagan ito", "tumawag na", "contact",
                    "hotline", "tawag balik",
                ],
                km: &[
                    "ហៅលេខនេះ", "ហៅឥឡូវនេះ", "ទាក់ទង",
                ],
                zh: &["拨打此号码", "立即致电", "联系我们", "热线", "回拨"],
                other: &[],
            },
            IndicatorId::PersonalInfoRequest => IndicatorKeywords {
                indicator: *self,
                en: &[
                    "full name", "date of birth", "home address",
                    "id number", "passport", "social security",
                    "national id", "identity card",
                ],
                vi: &[
                    "họ và tên", "ngày sinh", "địa chỉ",
                    "số cmnd", "cccd", "hộ chiếu",
                ],
                th: &[
                    "ชื่อเต็ม", "วันเกิด", "ที่อยู่",
                    "เลขบัตรประชาชน", "หนังสือเดินทาง",
                ],
                id: &[
                    "nama lengkap", "tanggal lahir", "alamat",
                    "nomor ktp", "paspor", "nik",
                ],
                ms: &[
                    "nama penuh", "tarikh lahir", "alamat",
                    "nombor kad pengenalan", "pasport",
                ],
                tl: &[
                    "buong pangalan", "petsa ng kapanganakan", "tirahan",
                    "id number", "passport",
                ],
                km: &[
                    "ឈ្មោះពេញ", "ថ្ងៃខែឆ្នាំកំណើត", "អាសយដ្ឋាន",
                    "លេខអត្តសញ្ញាណប័ណ្ឌ",
                ],
                zh: &["全名", "出生日期", "家庭住址", "身份证号", "护照"],
                other: &[],
            },
            IndicatorId::BankTransfer => IndicatorKeywords {
                indicator: *self,
                en: &[
                    "transfer to this account", "wire to", "account details",
                    "send to this account", "deposit to", "transfer funds to",
                    "chuyển vào số", "chuyển đến số",
                ],
                vi: &[
                    "số tài khoản", "chuyển vào tài khoản",
                    "chuyển đến số", "thông tin tài khoản",
                ],
                th: &[
                    "เลขบัญชี", "โอนเข้าบัญชี", "โอนไปยัง",
                    "รายละเอียดบัญชี",
                ],
                id: &[
                    "nomor rekening", "transfer ke rekening",
                    "transfer ke", "detail rekening",
                ],
                ms: &[
                    "nombor akaun", "pindah ke akaun",
                    "pindah ke", "butiran akaun",
                ],
                tl: &[
                    "account number", "transfer to account",
                    "bank details", "ilipat sa account",
                ],
                km: &[
                    "លេខគណនី", "ផ្ទេរទៅគណនី", "ព័ត៌មានគណនី",
                ],
                zh: &["银行账号", "转账至账户", "账户信息", "汇款至"],
                other: &[],
            },
            IndicatorId::VerificationRequest => IndicatorKeywords {
                indicator: *self,
                en: &[
                    "verify your identity", "confirm your identity",
                    "verify your account", "confirm your account",
                    "update your information", "validate your details",
                    "complete verification",
                    "verify now", "secure your account", "re-verify",
                    "update your details", "confirm your details",
                    "verify at", "confirm at", "secure at",
                    "update your payment", "update billing", "update your card",
                    "confirm your information", "verify your details",
                    // Reactivation keywords
                    "reactivate", "reactivation", "reactivate now",
                    "reactivate your", "activate your", "activation required",
                    "re-activate", "restore access", "regain access",
                    "unlock your", "unblock your",
                ],
                vi: &[
                    "xác minh danh tính", "xác nhận tài khoản",
                    "cập nhật thông tin", "xác thực",
                    "xác minh otp", "xác minh số điện thoại",
                    "bảo mật tài khoản", "xác nhận ngay",
                    // Unaccented variants
                    "xac minh danh tinh", "xac nhan tai khoan",
                    "cap nhat thong tin", "xac thuc",
                    "bao mat tai khoan", "xac nhan ngay",
                    // Reactivation
                    "kích hoạt lại", "mở khóa lại", "kích hoạt",
                    "mở khóa tài khoản",
                ],
                th: &[
                    "ยืนยันตัวตน", "ยืนยันบัญชี",
                    "อัปเดตข้อมูล", "ตรวจสอบ",
                    // Reactivation
                    "เปิดใช้งานอีกครั้ง", "ปลดล็อก", "เปิดบัญชี",
                ],
                id: &[
                    "verifikasi identitas", "konfirmasi akun",
                    "perbarui informasi", "verifikasi",
                    // Reactivation
                    "aktivasi", "aktifkan", "aktifkan kembali", "buka blokir",
                ],
                ms: &[
                    "sahkan identiti", "sahkan akaun",
                    "kemas kini maklumat", "pengesahan",
                    // Reactivation
                    "aktifkan", "aktif semula", "buka sekatan",
                ],
                tl: &[
                    "verify identity", "confirm account",
                    "update information", "verify",
                    // Reactivation
                    "aktibuhin", "reactivate", "activate", "buksan",
                ],
                km: &[
                    "ផ្ទៀងផ្ទាត់អត្តសញ្ញាណ", "បញ្ជាក់គណនី",
                    "ធ្វើបច្ចុប្បន្នភាពព័ត៌មាន",
                    // Reactivation
                    "បើកដំណើរការឡើងវិញ", "ដោះសោ",
                ],
                zh: &["验证身份", "确认账户", "更新信息", "实名认证", "重新激活", "解锁", "恢复"],
                other: &[],
            },
            IndicatorId::LimitedTimeOffer => IndicatorKeywords {
                indicator: *self,
                en: &[
                    "only today", "expires in", "last chance",
                    "limited time", "while supplies last",
                    "offer ends", "countdown", "24 hours only",
                    "today only",
                ],
                vi: &[
                    "chỉ hôm nay", "hết hạn trong", "cơ hội cuối",
                    "thời gian có hạn", "chỉ còn",
                ],
                th: &[
                    "วันนี้เท่านั้น", "หมดเขตใน", "โอกาสสุดท้าย",
                    "เวลาจำกัด", "เหลือเพียง",
                ],
                id: &[
                    "hari ini saja", "berakhir dalam", "kesempatan terakhir",
                    "waktu terbatas", "tersisa",
                ],
                ms: &[
                    "hari ini sahaja", "tamat dalam", "peluang terakhir",
                    "masa terhad", "tinggal",
                ],
                tl: &[
                    "today only", "expires in", "last chance",
                    "limited time", "natitira na",
                ],
                km: &[
                    "តែថ្ងៃនេះ", "ផុតកំណត់ក្នុង", "ឱកាសចុងក្រោយ",
                ],
                zh: &["仅限今日", "即将到期", "最后机会", "限时优惠", "仅剩"],
                other: &[],
            },
            IndicatorId::FreeGift => IndicatorKeywords {
                indicator: *self,
                en: &[
                    "free gift", "free trial", "no obligation",
                    "complimentary", "free sample", "no cost",
                    "no strings attached", "absolutely free",
                ],
                vi: &[
                    "quà tặng miễn phí", "dùng thử miễn phí",
                    "không nghĩa vụ", "hoàn toàn miễn phí",
                ],
                th: &[
                    "ของแถมฟรี", "ทดลองใช้ฟรี",
                    "ไม่มีข้อผูกมัด", "ฟรีอย่างแท้จริง",
                ],
                id: &[
                    "hadiah gratis", "uji coba gratis",
                    "tanpa kewajiban", "benar-benar gratis",
                ],
                ms: &[
                    "hadiah percuma", "percubaan percuma",
                    "tanpa obligasi", "percuma sepenuhnya",
                ],
                tl: &[
                    "free gift", "free trial", "no obligation",
                    "libreng regalo", "walang bayad",
                ],
                km: &[
                    "អំណោយឥតគិតថ្លៃ", "សាកល្បងឥតគិតថ្លៃ",
                ],
                zh: &["免费礼物", "免费试用", "无义务", "完全免费"],
                other: &[],
            },
            IndicatorId::FamilyEmergency => IndicatorKeywords {
                indicator: *self,
                en: &[
                    "your son", "your daughter", "your child",
                    "in the hospital", "in jail", "need money for",
                    "emergency surgery", "medical bills", "bail money",
                    "grandchild", "family member",
                ],
                vi: &[
                    "con bạn", "nằm viện", "bị bắt", "cần tiền",
                    "phẫu thuật khẩn cấp", "viện phí", "tiền bảo lãnh",
                ],
                th: &[
                    "ลูกของคุณ", "อยู่โรงพยาบาล", "ถูกจับ",
                    "ต้องการเงิน", "ผ่าตัดด่วน", "ค่ารักษา",
                ],
                id: &[
                    "anak anda", "dirawat", "ditangkap",
                    "butuh uang", "operasi darurat", "biaya medis",
                ],
                ms: &[
                    "anak anda", "dimasukkan ke hospital", "ditangkap",
                    "perlukan wang", "pembedahan kecemasan", "kos perubatan",
                ],
                tl: &[
                    "anak mo", "sa hospital", "nakakulong",
                    "kailangan ng pera", "emergency", "bayad sa ospital",
                ],
                km: &[
                    "កូនរបស់អ្នក", "នៅមន្ទីរពេទ្យ", "ត្រូវបានចាប់ខ្លួន",
                ],
                zh: &["你的儿子", "你的女儿", "住院", "需要钱", "紧急手术", "保释金"],
                other: &[],
            },
            IndicatorId::TaxPenalty => IndicatorKeywords {
                indicator: *self,
                en: &[
                    "tax penalty", "unpaid taxes", "tax evasion",
                    "irs", "tax authority", "outstanding tax",
                    "tax refund", "property tax",
                    // Toll/fine/penalty keywords
                    "toll", "toll fee", "toll fine", "unpaid toll",
                    "road toll", "erp", "electronic road pricing",
                    "summons", "traffic fine", "traffic summons",
                    "compound", "penalty fee", "violation", "overdue fine",
                    // Customs/duty keywords
                    "customs fee", "customs duty", "clearance fee",
                    "import duty", "customs charge", "customs payment",
                    "duty fee", "customs clearance",
                ],
                vi: &[
                    "thuế", "nợ thuế", "trốn thuế",
                    "cơ quan thuế", "thuế quá hạn", "hoàn thuế",
                    // Toll/fine/penalty
                    "phí cầu đường", "phí thông hành", "phạt nguội",
                    "tiền phạt", "vi phạm giao thông", "trọng tài",
                    // Customs/duty
                    "phí hải quan", "thuế nhập khẩu", "phí thông quan",
                ],
                th: &[
                    "ภาษี", "ภาษีค้างชำระ", "หนีภาษี",
                    "กรมสรรพากร", "ภาษีเกินกำหนด", "คืนภาษี",
                    // Toll/fine/penalty
                    "ค่าผ่านทาง", "ค่าทางด่วน", "ใบสั่ง",
                    "ค่าปรับ", "จราจร",
                    // Customs/duty
                    "ค่าภาษีศุลกากร", "ค่าธรรมเนียมศุลกากร", "ภาษีนำเข้า",
                ],
                id: &[
                    "pajak", "pajak tertunggak", "menghindar pajak",
                    "otoritas pajak", "pajak terlambat", "pengembalian pajak",
                    // Toll/fine/penalty
                    "tol", "denda tilang", "pelanggaran", "tilang", "denda",
                    // Customs/duty
                    "biaya bea cukai", "pajak impor", "bea masuk",
                ],
                ms: &[
                    "cukai", "cukai tertunggak", "mengelak cukai",
                    "lembaga hasil", "cukai lewat", "bayaran balik cukai",
                    // Toll/fine/penalty
                    "tol", "saman", "denda", "kompaun", "trafik",
                    // Customs/duty
                    "fi kastam", "cukai import", "kastam",
                ],
                tl: &[
                    "buhis", "unpaid tax", "tax evasion",
                    "tax authority", "tax refund",
                    // Toll/fine/penalty
                    "tol", "multa", "violation", "fine", "summons",
                    // Customs/duty
                    "customs", "duty", "buwis", "adwana",
                ],
                km: &[
                    "ពន្ធ", "ពន្ធដែកសង", "គេចពន្ធ",
                    // Toll/fine/penalty
                    "ថ្លៃស្ពាន", "ការពិន័យ", "បទល្មើស",
                    // Customs/duty
                    "ពន្ធគយ", "ការគយ",
                ],
                zh: &["税务", "欠税", "逃税", "税务局", "退税", "过路费", "罚款", "违章", "通行费", "海关费", "关税", "清关费"],
                other: &[],
            },
            IndicatorId::Sextortion => IndicatorKeywords {
                indicator: *self,
                en: &[
                    "sensitive video", "camera footage", "sensitive photos",
                    "we have your video", "recorded you", "webcam",
                    "explicit content", "camera access", "front camera",
                    "recorded through your camera", "hacked your camera",
                    "private video of you", "nude photos",
                    // Additional sextortion variants
                    "unseen photos", "private photos", "leaked photos",
                    "leaked video", "expose you", "public exposure",
                    "publish your", "share your video", "send to your contacts",
                    "send to your friends", "your contacts", "your friends will see",
                    "your family will see", "browsing history", "private messages",
                    "chat history", "webcam footage",
                ],
                vi: &[
                    "video nhạy cảm", "camera", "quay lén",
                    "hình ảnh nhạy cảm", "đã quay bạn",
                    // Unaccented
                    "video nhay cam", "hinh anh nhay cam", "da quay ban",
                    // Additional
                    "ảnh nhạy cảm", "video nhạy cảm", "rò rỉ",
                    "đăng lên mạng", "gửi cho người thân",
                ],
                th: &[
                    "วิดีโอละเอียดอ่อน", "กล้อง", "ถ่ายลับ",
                    // Additional
                    "รูปส่วนตัว", "วิดีโอลับ", "เผยแพร่", "ส่งให้เพื่อน",
                ],
                id: &[
                    "video sensitif", "kamera", "rekaman rahasia",
                    // Additional
                    "foto pribadi", "video pribadi", "bocor", "sebarkan",
                    "kirim ke kontak",
                ],
                ms: &[
                    "video sensitif", "kamera", "rakaman sulit",
                    // Additional
                    "foto peribadi", "video peribadi", "bocor", "sebarkan",
                    "hantar ke kontak",
                ],
                tl: &[
                    "sensitive video", "camera", "hidden cam",
                    // Additional
                    "pribadong larawan", "private video", "ikalat",
                    "ipadala sa kontak",
                ],
                km: &[
                    "វីដេអូរំភើប", "កាមេរ៉ា",
                    // Additional
                    "រូបភាពឯកជន", "វីដេអូឯកជន", "ផ្សព្វផ្សាយ",
                ],
                zh: &["敏感视频", "摄像头", "偷拍", "私密照片", "泄露视频", "发给你联系人"],
                other: &[],
            },
            IndicatorId::RecoveryScam => IndicatorKeywords {
                indicator: *self,
                en: &[
                    "recovery team", "refund team", "get your money back",
                    "victim of scam", "help you recover", "reclaim your funds",
                    "we can help you get back", "lost funds recovery",
                    "asset recovery", "funds recovery service",
                    "have you been scammed", "recover your losses",
                    "tracing your stolen funds",
                    "investment fraud recovery", "free consultation",
                    "helped many victims", "lawyer specializing",
                    "specializing in fraud", "reclaim funds",
                ],
                vi: &[
                    "truy thu", "hoàn tiền", "bị lừa đảo",
                    "thu hồi tiền", "đòi lại tiền",
                    "truy hồi", "nhận tiền", "đóng phí",
                    "phí xử lý", "vụ lừa đảo",
                    // Unaccented
                    "truy thu", "hoan tien", "bi lua dao", "thu hoi tien",
                    "truy hoi", "nhan tien", "dong phi", "phi xu ly",
                    "vu lua dao",
                ],
                th: &[
                    "ทีมกู้คืน", "คืนเงิน", "ถูกหลอกลวง",
                ],
                id: &[
                    "tim pemulihan", "pengembalian dana", "korban penipuan",
                ],
                ms: &[
                    "pasukan pemulihan", "pulih dana", "mangsa penipuan",
                ],
                tl: &[
                    "recovery team", "refund", "na-scam",
                ],
                km: &[
                    "ក្រុមការពារ", "ប្រាក់ត្រឡប់",
                ],
                zh: &["追回", "退款团队", "被骗", "资金回收"],
                other: &[],
            },
            IndicatorId::GovernmentBenefitLure => IndicatorKeywords {
                indicator: *self,
                en: &[
                    "you qualify for", "pre-approved for grant",
                    "assistance scheme", "comcare assistance",
                    "enhanced housing grant", "government payout",
                    "you are eligible for", "subsidy", "relief fund",
                    "government assistance", "financial aid",
                    "gst voucher", "payout to you", "cash payout",
                    "support payment", "cost of living",
                    "community support grant", "selected for",
                    "special top-up", "credit for",
                ],
                vi: &[
                    "bạn đủ điều kiện", "trợ cấp", "hỗ trợ chính phủ",
                    "bhxh", "an sinh xã hội", "trợ cấp thất nghiệp",
                    "bộ lđtbxh", "gói an sinh", "nhận trợ cấp",
                    // Unaccented
                    "ban du dieu kien", "tro cap", "ho tro chinh phu",
                    "an sinh xa hoi", "tro cap that nghiep",
                    "bo ldtbxh", "goi an sinh", "nhan tro cap",
                ],
                th: &[
                    "คุณมีสิทธิ์", "เงินช่วยเหลือ", "เงินอุดหนุน",
                ],
                id: &[
                    "anda memenuhi syarat", "bantuan", "subsidi",
                ],
                ms: &[
                    "anda layak", "bantuan", "subsidi",
                ],
                tl: &[
                    "you qualify", "assistance", "subsidy",
                ],
                km: &[
                    "អ្នកមានសិទ្ធិ", "ជំនួយ",
                ],
                zh: &["你有资格", "政府补助", "补贴"],
                other: &[],
            },
            IndicatorId::FakeMarketplace => IndicatorKeywords {
                indicator: *self,
                en: &[
                    "brand new sealed", "retail price", "limited stock",
                    "brand new in box", "unopened", "factory sealed",
                    "below retail", "below cost", "wholesale price",
                    "authentic guaranteed", "original brand",
                ],
                vi: &[
                    "hàng mới nguyên hộp", "giá sỉ", "còn ít hàng",
                    // Unaccented
                    "hang moi nguyen hop", "gia si", "con it hang",
                ],
                th: &[
                    "ของใหม่ในกล่อง", "ราคาส่ง", "สต็อกจำกัด",
                ],
                id: &[
                    "baru segel", "harga grosir", "stok terbatas",
                ],
                ms: &[
                    "baru tersegel", "harga borong", "stok terhad",
                ],
                tl: &[
                    "brand new sealed", "wholesale", "limited stock",
                ],
                km: &[
                    "ថ្មីក្នុងប្រអប់", "តម្លៃរាយ",
                ],
                zh: &["全新未拆", "批发价", "库存有限"],
                other: &[],
            },

            IndicatorId::QRCodeScan => IndicatorKeywords {
                indicator: *self,
                en: &[
                    "qr code", "scan qr", "scan to pay", "scan this code",
                    "scan here", "quishing", "scan to receive",
                    "scan to claim", "scan to verify",
                ],
                vi: &[
                    "mã qr", "quét mã qr", "quét để thanh toán",
                    "quét mã nhận thưởng",
                ],
                th: &[
                    "คิวอาร์โค้ด", "สแกน qr", "สแกนจ่ายเงิน",
                ],
                id: &[
                    "kode qr", "pindai qr", "scan qr", "pindai untuk bayar",
                ],
                ms: &[
                    "kod qr", "imbas qr", "imbas untuk bayar",
                ],
                tl: &[
                    "qr code", "i-scan ang qr", "scan para bayad",
                ],
                km: &[
                    "កូដ qr", "ស្កេន qr",
                ],
                zh: &["二维码", "扫码", "扫码支付"],
                other: &[],
            },

            IndicatorId::WrongNumberPivot => IndicatorKeywords {
                indicator: *self,
                en: &[
                    "wrong number", "is this", "who is this",
                    "you seem nice", "got your number by mistake",
                    "sorry wrong number", "let's be friends",
                ],
                vi: &[
                    "số nhầm rồi", "bạn là ai", "nhầm số",
                    "làm quen nhé", "được số này do nhầm",
                ],
                th: &[
                    "ผิดเบอร์", "คุณเป็นใคร", "เบอร์ผิด",
                    "มาเป็นเพื่อนกันไหม", "ได้เบอร์มาจากการกดผิด",
                ],
                id: &[
                    "salah nomor", "ini siapa", "nomor salah",
                    "ajak kenalan", "dapat nomor karena salah klik",
                ],
                ms: &[
                    "salah nombor", "ini siapa", "nombor salah",
                    "jom berkawan", "dapat nombor sebab salah tekan",
                ],
                tl: &[
                    "maling numero", "sino ka", "mali ang numero",
                    "magkaibigan tayo", "nakuha ko ang numero mula sa pagkakamali",
                ],
                km: &[
                    "ខុសលេខ", "អ្នកជានរណា", "លេខខុស",
                ],
                zh: &["加错号了", "你是谁", "交个朋友吧", "号码加错了"],
                other: &[],
            },

            IndicatorId::SubscriptionTrap => IndicatorKeywords {
                indicator: *self,
                en: &[
                    "free trial", "trial ends", "auto-renew", "auto renew",
                    "recurring payment", "monthly charge", "cancel anytime",
                    "subscription activated", "membership fee",
                    "trial expires", "will be charged", "renewal fee",
                ],
                vi: &[
                    "dùng thử miễn phí", "tự động gia hạn", "phí hàng tháng",
                    "phí thành viên", "gia hạn tự động",
                ],
                th: &[
                    "ทดลองใช้ฟรี", "ต่ออายุอัตโนมัติ", "ค่ารายเดือน",
                    "ค่าสมาชิก", "ต่ออายุอัตโนมัติ",
                ],
                id: &[
                    "uji coba gratis", "perpanjang otomatis", "biaya bulanan",
                    "biaya keanggotaan", "diperpanjang otomatis",
                ],
                ms: &[
                    "percubaan percuma", "diperbaharui secara automatik", "caj bulanan",
                    "yuran keahlian", "pembaharuan automatik",
                ],
                tl: &[
                    "free trial", "auto-renew", "monthly charge",
                    "membership fee", "awtomatik na mag-renew",
                ],
                km: &[
                    "ទាក់ទងនឹងសេវាកម្ម", "ការបន្តស្វ័យប្រវត្តិ", "តម្លៃប្រចាំខែ",
                ],
                zh: &["免费试用", "自动续费", "月费", "会员费", "续订"],
                other: &[],
            },

            IndicatorId::DeepfakeImpersonation => IndicatorKeywords {
                indicator: *self,
                en: &[
                    "ai voice clone", "voice synthesis", "deepfake video",
                    "ai generated voice", "cloned voice", "voice clone",
                    "this is not a recording", "live video call",
                    "video verification", "face verification",
                ],
                vi: &[
                    "giọng nói ai", "video deepfake", "xác thực bằng video",
                    "giọng nói nhân bản",
                ],
                th: &[
                    "เลียนเสียง ai", "วิดีโอ deepfake", "ยืนยันด้วยวิดีโอ",
                ],
                id: &[
                    "kloning suara ai", "video deepfake", "verifikasi video",
                ],
                ms: &[
                    "klon suara ai", "video deepfake", "pengesahan video",
                ],
                tl: &[
                    "clone ng boses ai", "deepfake video", "beripikasyon gamit ang video",
                ],
                km: &[
                    "ការចម្លងសំឡេង ai", "វីដេអូ deepfake",
                ],
                zh: &["AI语音克隆", "深度伪造视频", "视频验证"],
                other: &[],
            },
        }
    }

    /// Whether this indicator is a high-value indicator that should
    /// enforce a minimum risk bucket when detected at High strength.
    pub fn is_high_value(&self) -> bool {
        matches!(
            self,
            IndicatorId::CredentialRequest
                | IndicatorId::RemoteAccess
                | IndicatorId::BankTransfer
                | IndicatorId::Sextortion
                | IndicatorId::RecoveryScam
                | IndicatorId::PromiseHighReturn
                | IndicatorId::ThreatAccount
        )
    }

    /// User-facing explanation of why this indicator is suspicious.
    /// Used in detection results to help users understand the risk.
    pub fn explanation(&self) -> &'static str {
        match self {
            IndicatorId::Urgency => "The message creates artificial urgency to pressure you into acting before you can think clearly.",
            IndicatorId::FinancialRequest => "The message asks you to send or transfer money, which is a common scam tactic.",
            IndicatorId::CredentialRequest => "The message requests your password, OTP, or verification code. Legitimate services never ask for these.",
            IndicatorId::RemoteAccess => "The message asks you to install software or grant remote access to your device. This is a classic tech support scam.",
            IndicatorId::SenderAnomaly => "The sender impersonates an institution but uses generic greetings instead of your name or account details.",
            IndicatorId::PromiseHighReturn => "The message promises guaranteed or risk-free high returns, which is unrealistic and typical of investment fraud.",
            IndicatorId::AuthorityClaim => "The sender claims to be from an official organization (police, government, bank) to create false authority.",
            IndicatorId::ThreatLegal => "The message threatens legal action, arrest, or prosecution to intimidate you into complying.",
            IndicatorId::ThreatAccount => "The message claims your account will be suspended or closed to create urgency and fear.",
            IndicatorId::RomanceGrooming => "The sender expresses unusually strong romantic feelings early in the relationship, a common romance scam pattern.",
            IndicatorId::DeliveryLure => "The message claims a package delivery issue and asks you to click a link or pay a fee.",
            IndicatorId::PrizeLure => "The message claims you have won a prize or lottery you never entered, then asks for fees to claim it.",
            IndicatorId::JobOffer => "The message offers easy work-from-home jobs with high pay and no experience needed, a common task scam pattern.",
            IndicatorId::CharityAppeal => "The message appeals for donations to a cause that may not be legitimate, especially after disasters.",
            IndicatorId::CryptoScheme => "The message promotes cryptocurrency, forex, or trading schemes with unrealistic promises.",
            IndicatorId::GiftCard => "The message asks for payment via gift cards, which is a major red flag. Legitimate organizations never request gift card payments.",
            IndicatorId::LinkSuspicious => "The message contains a shortened or suspicious link that may lead to a phishing site.",
            IndicatorId::PhoneCallback => "The message urges you to call a phone number, which may connect you to scammers posing as support agents.",
            IndicatorId::PersonalInfoRequest => "The message requests sensitive personal information like your full name, date of birth, or ID number.",
            IndicatorId::BankTransfer => "The message provides bank account details and asks you to transfer money to a specific account.",
            IndicatorId::VerificationRequest => "The message asks you to verify your identity or account through a link, which may be a phishing attempt.",
            IndicatorId::LimitedTimeOffer => "The message creates false scarcity with a limited-time offer to pressure immediate action.",
            IndicatorId::FreeGift => "The message offers free gifts or trials with no obligation, a common lure to collect personal information.",
            IndicatorId::FamilyEmergency => "The message claims a family member is in trouble and needs money urgently. Always verify through another channel.",
            IndicatorId::TaxPenalty => "The message claims you have unpaid taxes or penalties and threatens consequences if you don't pay immediately.",
            IndicatorId::Sextortion => "The message claims to have sensitive or explicit photos/videos of you and threatens to release them unless you pay.",
            IndicatorId::RecoveryScam => "The message claims to be from a recovery service that can help you get back money you lost to a previous scam — this is itself a scam.",
            IndicatorId::GovernmentBenefitLure => "The message claims you qualify for a government grant, assistance scheme, or payout that you never applied for.",
            IndicatorId::FakeMarketplace => "The message offers branded products at suspiciously low prices with claims of being brand new and sealed, a common marketplace scam.",
            IndicatorId::QRCodeScan => "The message asks you to scan a QR code, which may direct you to a malicious payment or phishing site.",
            IndicatorId::WrongNumberPivot => "The sender claims to have reached you by mistake and tries to start a conversation, a common tactic in pig butchering and romance scams.",
            IndicatorId::SubscriptionTrap => "The message mentions a free trial or subscription with hidden recurring charges that are difficult to cancel.",
            IndicatorId::DeepfakeImpersonation => "The message involves AI-generated voice or video impersonation, used to trick you into believing you are speaking to a real person.",
        }
    }

    /// Contribution rank for display ordering (1 = highest contribution to risk).
    /// Higher-value indicators get lower rank numbers.
    pub fn contribution_rank(&self) -> u8 {
        match self {
            IndicatorId::CredentialRequest => 1,
            IndicatorId::RemoteAccess => 2,
            IndicatorId::BankTransfer => 3,
            IndicatorId::GiftCard => 4,
            IndicatorId::FinancialRequest => 5,
            IndicatorId::ThreatLegal => 6,
            IndicatorId::ThreatAccount => 7,
            IndicatorId::FamilyEmergency => 8,
            IndicatorId::AuthorityClaim => 9,
            IndicatorId::Urgency => 10,
            IndicatorId::PromiseHighReturn => 11,
            IndicatorId::CryptoScheme => 12,
            IndicatorId::LinkSuspicious => 13,
            IndicatorId::VerificationRequest => 14,
            IndicatorId::DeliveryLure => 15,
            IndicatorId::PrizeLure => 16,
            IndicatorId::RomanceGrooming => 17,
            IndicatorId::JobOffer => 18,
            IndicatorId::CharityAppeal => 19,
            IndicatorId::PhoneCallback => 20,
            IndicatorId::PersonalInfoRequest => 21,
            IndicatorId::SenderAnomaly => 22,
            IndicatorId::LimitedTimeOffer => 23,
            IndicatorId::FreeGift => 24,
            IndicatorId::TaxPenalty => 25,
            IndicatorId::Sextortion => 5,
            IndicatorId::RecoveryScam => 10,
            IndicatorId::GovernmentBenefitLure => 20,
            IndicatorId::FakeMarketplace => 22,
            IndicatorId::QRCodeScan => 15,
            IndicatorId::WrongNumberPivot => 20,
            IndicatorId::SubscriptionTrap => 18,
            IndicatorId::DeepfakeImpersonation => 10,
        }
    }
}

impl std::fmt::Display for IndicatorId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Multi-language keyword set for an indicator.
pub struct IndicatorKeywords {
    pub indicator: IndicatorId,
    pub en: &'static [&'static str],
    pub vi: &'static [&'static str],
    pub th: &'static [&'static str],
    pub id: &'static [&'static str],
    pub ms: &'static [&'static str],
    pub tl: &'static [&'static str],
    pub km: &'static [&'static str],
    pub zh: &'static [&'static str],
    pub other: &'static [&'static str],
}

impl IndicatorKeywords {
    /// Get keywords for a specific language code.
    pub fn for_language(&self, lang: &str) -> &'static [&'static str] {
        match lang {
            "en" => self.en,
            "vi" => self.vi,
            "th" => self.th,
            "id" => self.id,
            "ms" => self.ms,
            "tl" => self.tl,
            "km" => self.km,
            "zh" => self.zh,
            _ => self.other,
        }
    }

    /// Get keywords for all languages (for multi-language detection).
    pub fn all_keywords(&self) -> Vec<&'static str> {
        let mut all = Vec::new();
        all.extend_from_slice(self.en);
        all.extend_from_slice(self.vi);
        all.extend_from_slice(self.th);
        all.extend_from_slice(self.id);
        all.extend_from_slice(self.ms);
        all.extend_from_slice(self.tl);
        all.extend_from_slice(self.km);
        all.extend_from_slice(self.zh);
        all
    }
}

/// A detected indicator with its strength.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndicatorHit {
    pub id: IndicatorId,
    pub strength: IndicatorStrength,
    /// Number of keyword matches that triggered this indicator.
    pub match_count: usize,
}

/// A detected indicator with explanation and contribution rank for user-facing output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndicatorHitExplained {
    pub id: IndicatorId,
    pub strength: IndicatorStrength,
    pub match_count: usize,
    /// User-facing explanation of why this indicator is suspicious.
    pub explanation: String,
    /// Contribution rank (1 = highest contribution to risk).
    pub contribution_rank: u8,
}

impl IndicatorHit {
    /// Convert to an explained variant with user-facing metadata.
    pub fn explained(&self) -> IndicatorHitExplained {
        IndicatorHitExplained {
            id: self.id,
            strength: self.strength,
            match_count: self.match_count,
            explanation: self.id.explanation().to_string(),
            contribution_rank: self.id.contribution_rank(),
        }
    }
}

/// Ontology version identifier.
pub const ONTOLOGY_VERSION: &str = "1.2.0";
