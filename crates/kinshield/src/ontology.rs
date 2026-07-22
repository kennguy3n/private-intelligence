//! Indicator ontology — 25 fixed, versioned scam indicators.
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
                ],
                vi: &[
                    "khẩn cấp", "gấp lắm", "ngay lập tức", "gấp", "nhanh lên",
                    "trong vòng", "còn hạn", "sắp hết hạn", "mau chóng", "đừng chờ",
                    // Unaccented variants (common in SMS)
                    "khan cap", "gap lam", "ngay lap tuc", "nap het han", "mau chung",
                ],
                th: &[
                    "ด่วน", "เร่งด่วน", "ทันที", "ภายใน", "หมดเวลา",
                    "รีบ", "เร็วๆ", "อายุสั้น", "รีบด่วน",
                ],
                id: &[
                    "segera", "darurat", "penting", "sekarang", "cepat",
                    "batas waktu", "berakhir", "segera lah",
                ],
                ms: &[
                    "segera", "kecemasan", "penting", "sekarang", "cepat",
                    "tarikh tamat", "tamat",
                ],
                tl: &[
                    "urgent", "agad", "napakabilis", "panahon", "malapit na",
                    "hurry", "deadline", "expiry",
                ],
                km: &[
                    "បន្ទាន់", "លឿន", "ឥឡូវនេះ", "ក្នុងរយៈ", "ផុតកំណត់",
                ],
                zh: &["紧急", "立即", "马上", "赶快", "截止", "到期"],
                other: &[],
            },
            IndicatorId::FinancialRequest => IndicatorKeywords {
                indicator: *self,
                en: &[
                    "send money", "transfer money", "wire money", "payment",
                    "pay now", "send funds", "make a payment", "deposit",
                    "transfer funds", "send cash", "wire transfer",
                ],
                vi: &[
                    "chuyển tiền", "gửi tiền", "thanh toán", "nạp tiền",
                    "chuyển khoản", "gửi ngay", "nộp tiền",
                ],
                th: &[
                    "โอนเงิน", "ส่งเงิน", "จ่ายเงิน", "โอนเงินเข้า",
                    "เก็บเงิน", "ชำระเงิน",
                ],
                id: &[
                    "kirim uang", "transfer uang", "bayar", "transfer dana",
                    "kirim dana", "pembayaran",
                ],
                ms: &[
                    "hantar wang", "pindah wang", "bayar", "pindahan dana",
                    "bayaran", "kirim duit",
                ],
                tl: &[
                    "magpadala ng pera", "bayad", "transfer", "padala",
                    "ipadala ang pera", "kabayaran",
                ],
                km: &[
                    "ផ្ញើប្រាក់", "ផ្ទេរប្រាក់", "បង់ប្រាក់", "បង់ថ្លៃ",
                ],
                zh: &["转账", "汇款", "付款", "打钱", "支付"],
                other: &[],
            },
            IndicatorId::CredentialRequest => IndicatorKeywords {
                indicator: *self,
                en: &[
                    "password", "otp", "pin", "verification code", "passcode",
                    "one-time password", "2fa code", "security code",
                    "enter your password", "confirm your password",
                ],
                vi: &[
                    "mật khẩu", "mã otp", "mã xác nhận", "mã bảo mật",
                    "nhập mật khẩu", "mã pin",
                ],
                th: &[
                    "รหัสผ่าน", "รหัส otp", "รหัสยืนยัน", "รหัสลับ",
                    "กรอกรหัสผ่าน", "รหัส pin",
                ],
                id: &[
                    "kata sandi", "kode otp", "kode verifikasi", "kode keamanan",
                    "masukkan kata sandi", "pin",
                ],
                ms: &[
                    "kata laluan", "kod otp", "kod pengesahan", "kod keselamatan",
                    "masukkan kata laluan", "pin",
                ],
                tl: &[
                    "password", "otp", "verification code", "passcode",
                    "pumasok ng password", "code",
                ],
                km: &[
                    "ពាក្យសម្ងាត់", "កូដ otp", "កូដផ្ទៀងផ្ទាត់", "កូដសុវត្ថិភាព",
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
                ],
                vi: &[
                    "thân gửi khách hàng", "ngân hàng của bạn", "tài khoản của bạn",
                    "thông báo từ", "thông báo chính thức",
                    // Unaccented variants
                    "ngan hang", "tai khoan cua ban", "thong bao",
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
                ],
                vi: &[
                    "lợi nhuận đảm bảo", "không rủi ro", "thu nhập thụ động",
                    "tiền dễ kiếm", "lãi suất cao", "đảm bảo lợi nhuận",
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
                ],
                vi: &[
                    "công an", "chính phủ", "ngân hàng nhà nước",
                    "cơ quan chức năng", "đại diện", "tổng cục thuế",
                ],
                th: &[
                    "ตำรวจ", "รัฐบาล", "ธนาคารแห่งประเทศ",
                    "เจ้าหน้าที่", "ในนามของ", "กรมสรรพากร",
                ],
                id: &[
                    "polisi", "pemerintah", "bank indonesia",
                    "pejabat resmi", "atas nama", "direktorat pajak",
                ],
                ms: &[
                    "polis", "kerajaan", "bank negara",
                    "pegawai rasmi", "atas nama", "lembaga hasil",
                ],
                tl: &[
                    "pulis", "gobyerno", "bangko",
                    "opisyal", "sa ngalan ng", "bureau of internal revenue",
                ],
                km: &[
                    "នគរបាល", "រដ្ឋាភិបាល", "ធនាគារជាតិ",
                ],
                zh: &["警察", "政府", "银行", "官方", "代表", "税务局"],
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
                ],
                vi: &[
                    "tài khoản bị khóa", "tài khoản bị đóng", "ngừng hoạt động",
                    "tài khoản bị chặn", "khóa vĩnh viễn",
                    // Unaccented variants
                    "tai khoan bi khoa", "tai khoan bi dong", "khoa vinh vien",
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
                    "package", "delivery", "parcel", "shipment",
                    "tracking", "reschedule delivery", "package held",
                    "delivery failed", "courier",
                ],
                vi: &[
                    "gói hàng", "giao hàng", "kiện hàng", "theo dõi đơn hàng",
                    "lên lịch lại", "giao hàng thất bại",
                ],
                th: &[
                    "พัสดุ", "จัดส่ง", "พัสดุภาค", "ติดตามพัสดุ",
                    "นัดหมายใหม่", "จัดส่งล้มเหลว",
                ],
                id: &[
                    "paket", "pengiriman", "lacak paket", "jadwal ulang",
                    "pengiriman gagal", "kurir",
                ],
                ms: &[
                    "pekese", "penghantaran", "jejak pesanan", "jadual semula",
                    "penghantaran gagal", "kurier",
                ],
                tl: &[
                    "package", "delivery", "parcel", "tracking",
                    "reschedule", "delivery failed", "courier",
                ],
                km: &[
                    "កញ្ចប់", "ការដឹកជញ្ជូន", "តាមដានការបញ្ជូន", "បរាជ័យ",
                ],
                zh: &["包裹", "快递", "派送", "追踪", "重新安排", "派送失败"],
                other: &[],
            },
            IndicatorId::PrizeLure => IndicatorKeywords {
                indicator: *self,
                en: &[
                    "you've won", "congratulations", "winner", "prize",
                    "lottery", "sweepstakes", "lucky draw", "selected to win",
                    "claim your prize",
                ],
                vi: &[
                    "bạn đã thắng", "chúc mừng", "trúng thưởng", "xổ số",
                    "giải thưởng", "quay số trúng thưởng",
                ],
                th: &[
                    "คุณได้รับรางวัล", "ยินดีด้วย", "ถูกรางวัล", "ลอตเตอรี่",
                    "รางวัล", "จับรางวัล",
                ],
                id: &[
                    "anda menang", "selamat", "undian", "lotre",
                    "hadiah", "beruntung",
                ],
                ms: &[
                    "anda menang", "tahniah", "undi", "loteri",
                    "hadiah", "bertuah",
                ],
                tl: &[
                    "panalo ka", "congratulations", "premyo", "lottery",
                    "sweepstakes", "lucky draw",
                ],
                km: &[
                    "អ្នកឈ្នះ", "អបអរសាទរ", "រង្វាន់", "ឆ្នោត",
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
                ],
                vi: &[
                    "làm việc tại nhà", "việc làm dễ", "kiếm tiền",
                    "việc bán thời gian", "không cần kinh nghiệm",
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
                ],
                vi: &[
                    "tiền ảo", "bitcoin", "forex", "đầu tư tiền điện tử",
                    "khai thác", "token", "ico",
                ],
                th: &[
                    "คริปโต", "บิตคอยน์", "forex", "เทรด", "ขุด",
                    "โทเคน", "ico",
                ],
                id: &[
                    "kripto", "bitcoin", "forex", "trading", "menambang",
                    "token", "ico",
                ],
                ms: &[
                    "kripto", "bitcoin", "forex", "trading", "lombong",
                    "token", "ico",
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
                    "itunes card", "voucher",
                ],
                ms: &[
                    "kad hadiah", "steam card", "google play card",
                    "itunes card", "voucher",
                ],
                tl: &[
                    "gift card", "steam card", "google play",
                    "itunes card", "voucher",
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
                    "bit.ly", "tinyurl", "t.co", "shorte.st", "cutt.ly",
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
                    "hotline", "call back",
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
                    "bank account", "account number", "routing number",
                    "swift code", "iban", "transfer to this account",
                    "wire to", "account details",
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
                ],
                vi: &[
                    "xác minh danh tính", "xác nhận tài khoản",
                    "cập nhật thông tin", "xác thực",
                    // Unaccented variants
                    "xac minh danh tinh", "xac nhan tai khoan",
                    "cap nhat thong tin", "xac thuc",
                ],
                th: &[
                    "ยืนยันตัวตน", "ยืนยันบัญชี",
                    "อัปเดตข้อมูล", "ตรวจสอบ",
                ],
                id: &[
                    "verifikasi identitas", "konfirmasi akun",
                    "perbarui informasi", "verifikasi",
                ],
                ms: &[
                    "sahkan identiti", "sahkan akaun",
                    "kemas kini maklumat", "pengesahan",
                ],
                tl: &[
                    "verify identity", "confirm account",
                    "update information", "verify",
                ],
                km: &[
                    "ផ្ទៀងផ្ទាត់អត្តសញ្ញាណ", "បញ្ជាក់គណនី",
                    "ធ្វើបច្ចុប្បន្នភាពព័ត៌មាន",
                ],
                zh: &["验证身份", "确认账户", "更新信息", "实名认证"],
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
                ],
                vi: &[
                    "thuế", "nợ thuế", "trốn thuế",
                    "cơ quan thuế", "thuế quá hạn", "hoàn thuế",
                ],
                th: &[
                    "ภาษี", "ภาษีค้างชำระ", "หนีภาษี",
                    "กรมสรรพากร", "ภาษีเกินกำหนด", "คืนภาษี",
                ],
                id: &[
                    "pajak", "pajak tertunggak", "menghindar pajak",
                    "otoritas pajak", "pajak terlambat", "pengembalian pajak",
                ],
                ms: &[
                    "cukai", "cukai tertunggak", "mengelak cukai",
                    "lembaga hasil", "cukai lewat", "bayaran balik cukai",
                ],
                tl: &[
                    "buhis", "unpaid tax", "tax evasion",
                    "tax authority", "tax refund",
                ],
                km: &[
                    "ពន្ធ", "ពន្ធដែកសង", "គេចពន្ធ",
                ],
                zh: &["税务", "欠税", "逃税", "税务局", "退税"],
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
                | IndicatorId::GiftCard
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
pub const ONTOLOGY_VERSION: &str = "1.0.0";
