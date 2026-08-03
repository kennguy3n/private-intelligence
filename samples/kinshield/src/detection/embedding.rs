//! Embedding-based semantic indicator detection.
//!
//! Uses zk-ai-core's e5-small model for semantic detection of indicators
//! that are difficult to capture with keywords alone (e.g., romance
//! grooming, authority claim). Uses multi-prototype k-NN with per-indicator
//! thresholds for broad semantic coverage.

use zk_ai_core::AiEngine;
use zk_ai_core::cosine_similarity;
use crate::ontology::{IndicatorId, IndicatorHit, IndicatorStrength};
use crate::channel::Channel;
use std::collections::HashMap;

/// Per-indicator embedding configuration.
struct EmbeddingConfig {
    threshold: f32,
    high_threshold: f32,
    prototypes: &'static [&'static str],
}

fn embedding_config(indicator: IndicatorId) -> Option<EmbeddingConfig> {
    let (threshold, high_threshold, prototypes) = match indicator {
        IndicatorId::RomanceGrooming => (0.88, 0.92, &[
            "I have fallen in love with you after just a few days of chatting. You are my soulmate. I want to visit you but I need money for flights and visa fees. Can you send me money?",
            "We met on the dating app and I feel a deep connection with you. Fate brought us together. I want to meet you in person but I need help with travel expenses. Can you send money for the flight?",
            "You are the most wonderful person I've ever met online. We are meant to be together. I'm working on an oil rig and can't access my bank. Can you help me with some money until I get back?",
            "My darling, I've never felt this way about anyone. I want to come visit you but my funds are frozen. If you could help with the visa fee and flight, I'll pay you back when we meet.",
            // Short-message variants
            "I love you so much darling. Can you send me some money for my flight? I want to meet you.",
            "Baby I need help. My funds are frozen and I can't access my account. Can you send $500?",
            // Multilingual variants
            "Em yêu anh nhiều lắm. Anh muốn qua thăm em nhưng cần tiền vé máy bay. Em gửi tiền giúp anh nhé.",
            "Anh yêu em, em là định mệnh của anh. Anh đang trên giàn khoan không lấy được tiền. Em giúp anh chút tiền nhé.",
            "คุณคือคนที่ฉันรัก อยากไปพบคุณแต่ไม่มีเงินค่าตั๋ว ช่วยโอนเงินให้หน่อยได้ไหม",
            "Aku jatuh cinta padamu. Bantu aku biaya tiket pesawat untuk bertemumu ya sayang.",
            "Mahal kita, tadhana ang pagtatagpo natin. Pakisuyo nga pera pang eroplano para makita kita.",
        ][..]),

        IndicatorId::AuthorityClaim => (0.88, 0.92, &[
            "This is an official call from the police department. I am a government official. We are calling on behalf of the tax authority regarding your outstanding tax payments.",
            "Hello, this is officer Tan from the Singapore Police Force. We are investigating a case involving your bank account. You need to cooperate with our investigation immediately.",
            "This is the immigration department calling. There is an issue with your visa status. You need to transfer funds to a safe account for verification purposes.",
            "I am calling from the anti-money laundering unit. Your identity has been linked to a criminal case. You must follow our instructions to clear your name.",
            // Short-message variants
            "This is the police. Your account is under investigation. Call this number now.",
            "Officer Lee here. We found your ID in a criminal case. Cooperate or face arrest.",
            // Multilingual variants
            "Tôi là công an. Tài khoản của bạn đang liên quan đến vụ rửa tiền. Hãy hợp tác ngay.",
            "นี่คือตำรวจ บัญชีของคุณอยู่ในการสอบสวน โทรมาที่เบอร์นี้ทันที",
            "Ini dari kepolisian. Rekening Anda terlibat kasus pencucian uang. Segera hubungi kami.",
            "Nasa pulisya kami. May kaso laban sa account mo. Tumawag kaagad dito.",
        ][..]),

        IndicatorId::PromiseHighReturn => (0.89, 0.93, &[
            "Join our investment group for guaranteed high returns. Professional traders will manage your funds with zero risk. You can double your money in just one week. Minimum investment is only $100.",
            "Earn 50% APY on your Bitcoin through our staking platform. Zero risk, guaranteed returns. Join our Telegram group to start earning passive income from crypto today.",
            "Pre-IPO shares available for exclusive allocation. 3x returns expected within 6 months. Pool funds with our investment club for access. Capital protection guaranteed.",
            "Make 20% annual returns with our forex automated trading system. No experience needed. Professional traders manage everything. Withdraw your profits anytime.",
            "Real estate investment opportunity with 15% guaranteed yield. Limited units available. Invest now for passive income. No risk, capital fully protected.",
            // Short-message variants
            "Double your money in 7 days. Zero risk. DM me to join.",
            "Guaranteed 30% monthly return. No experience needed. Click link to start.",
            // Multilingual variants
            "Đầu tư lợi nhuận 30%/tháng, cam kết không rủi ro. Gửi tiền tối thiểu 500k là bắt đầu kiếm tiền.",
            "ลงทุนรับผลตอบแทน 30% ต่อเดือน ปลอดภัย 100% คลิกเริ่มต้นได้เลย",
            "Investasi pasti untung 30% per bulan, tanpa risiko. Mulai dari 500rb saja.",
            "PASTI ANG 30% KITA PER BUWAN. WALANG RISK. MAG-CLICK NA!",
        ][..]),

        IndicatorId::CharityAppeal => (0.88, 0.92, &[
            "Urgent appeal: victims of the recent disaster urgently need your help. Please donate now to provide food, water, and shelter. Every dollar goes directly to helping the victims.",
            "We are raising funds for orphaned children. Your donation can provide meals and education. Please send money via bank transfer or gift cards to help these children in need.",
            // Short-message variants
            "Please donate for flood victims. Every dollar helps. Bank transfer details below.",
            "Help orphaned children. Send money via bank transfer or gift cards.",
            // Multilingual variants
            "Khẩn cấp: nạn nhân bão lũ cần sự giúp đỡ. Mọi đóng góp xin gửi về số tài khoản dưới.",
            "ช่วยบริจาคเพื่อผู้ประสบภัยน้ำท่วม ทุกบาทมีค่า โอนเงินได้ที่เลขบัญชีด้านล่าง",
            "Bantu korban banjir dengan donasi Anda. Transfer ke rekening berikut.",
        ][..]),

        IndicatorId::FamilyEmergency => (0.89, 0.93, &[
            "Mom, I'm in the hospital. I had an accident and need emergency surgery. Please send money for the medical bills right away. Don't tell dad. This is urgent.",
            "Dad, your son has been in a car accident. He needs surgery immediately. Please send $5000 to this hospital account right now. Don't call back, just send the money.",
            "Grandma, I'm in trouble. I got arrested and need bail money. Please don't tell mom. Send money through Western Union right away. I'm using a friend's phone.",
            // Short-message variants
            "Mom it's urgent. I'm in hospital. Send money now. Don't tell dad.",
            "Grandma I got arrested. Need bail money. Don't tell anyone. Send Western Union.",
            // Multilingual variants
            "Mẹ ơi con nằm viện rồi, cần tiền phẫu thuật gấp. Gửi tiền ngay mẹ. Đừng báo bố.",
            "คุณย่า หนูโดนจับ ต้องเงินประกัน ส่งเงินมาด่วน อย่าบอกแม่นะ",
            "Ibu saya di rumah sakit butuh uang operasi. Kirim uang sekarang. Jangan bilang ayah.",
        ][..]),

        IndicatorId::JobOffer => (0.88, 0.92, &[
            "We saw your LinkedIn profile and would like to offer you a data annotation role. Work from home, flexible hours, $200 per review. No experience needed. Apply now, limited positions available.",
            "Hiring remote product reviewers. Earn $500/day by completing simple tasks. No formal requirements. Commission-based with high salary. Contact us on WhatsApp to start.",
            "Easy work from home job! Earn money by clicking ads and completing surveys. Part-time, no experience needed. Pay a small registration fee to get started. High salary guaranteed.",
            // Short-message variants
            "Earn $200/review from home. No experience. DM to apply. Limited spots.",
            "Work from home, $500/day. Simple tasks. WhatsApp to start.",
            // Multilingual variants
            "Làm việc tại nhà, thu nhập 500k/ngày. Không cần kinh nghiệm. Nhắn tin để bắt đầu.",
            "ทำงานที่บ้าน รายได้ 500 บาท/วัน ไม่ต้องมีประสบการณ์ ทัยแอปเริ่มได้เลย",
            "Kerja dari rumah, penghasilan 500rb/hari. Tanpa pengalaman. Chat untuk mulai.",
        ][..]),

        IndicatorId::DeliveryLure => (0.88, 0.92, &[
            "Your package could not be delivered. Click here to reschedule delivery or update your address. A small redelivery fee applies.",
            "Your parcel is being held at our facility. Please pay the customs clearance fee to release your package for final delivery.",
            "Your international package is held at customs. Pay the customs duty fee to release your package. Click here to pay and arrange delivery.",
            "Your parcel could not be delivered due to incomplete address. Please update your delivery details and pay the redelivery fee. Track your package here.",
            // Short-message variants
            "Package held. Pay $2 customs fee to release. Click link.",
            "Delivery failed. Update address and pay redelivery fee here.",
            // Multilingual variants
            "Kiện hàng của bạn bị giữ tại hải quan. Vui lòng trả phí thông quan để nhận hàng. Bấm vào link.",
            "พัสดุของคุณถูกค้างที่ศุลกากร กรุณาชำระค่าธรรมเนียมเพื่อรับพัสดุ คลิกที่นี่",
            "Paket Anda ditahan di bea cukai. Bayar biaya bea cukai untuk melepaskan paket. Klik di sini.",
            "Nai-hold ang package sa customs. Magbayad ng fee para ma-release. Click here.",
        ][..]),

        IndicatorId::PrizeLure => (0.88, 0.92, &[
            "Congratulations! You've won $50,000 in our international lottery. Pay the processing fee to claim your prize. Respond within 24 hours.",
            "You've accumulated enough points to redeem a cashback reward. Claim your reward now at our portal. Limited time offer, expires today.",
            "You have been selected as our lucky winner for this month's draw. Click here to claim your free gift and cashback reward.",
            // Short-message variants
            "You won! Claim your prize here. Pay $5 processing fee. Expires today.",
            "Congratulations winner! Click to claim your reward.",
            // Multilingual variants
            "Chúc mừng! Bạn đã trúng thưởng 50 triệu. Trả phí xử lý để nhận thưởng. Trong 24h.",
            "ยินดีด้วย! คุณถูกรางวัล ชำระค่าธรรมเนียมเพื่อรับรางวัล ภายใน 24 ชม.",
            "Selamat! Anda menang hadiah. Bayar biaya proses untuk klaim. Dalam 24 jam.",
        ][..]),

        IndicatorId::Sextortion => (0.88, 0.93, &[
            "We have recorded you through your device camera. We have sensitive video footage of you. Pay $2000 in Bitcoin to prevent us from sharing these videos with your contacts.",
            "I hacked your camera and have explicit photos of you. I will send these to your family and friends unless you pay. Send money to this Bitcoin wallet within 48 hours.",
            "We installed spyware on your device and captured your screen while you were watching adult content. Pay to delete the footage, otherwise we will publish it online.",
            "We have your private photos and browsing history. Send $1000 in Bitcoin or we will share these with your contacts and family. You have 24 hours to comply.",
            // Short-message variants
            "I have your webcam footage. Pay $500 BTC or I send to your contacts.",
            "We recorded you. Send Bitcoin to this address or we publish everything.",
            // Multilingual variants
            "Chúng tôi có video nhạy cảm của bạn. Chuyển 2000 USD Bitcoin hoặc chúng tôi gửi cho người thân.",
            "เรามีวิดีโอละเอียดอ่อนของคุณ โอน Bitcoin มิฉะนั้นจะส่งให้ครอบครัว",
            "Kami punya video pribadi Anda. Transfer Bitcoin atau kami sebar ke kontak Anda.",
        ][..]),

        IndicatorId::RecoveryScam => (0.88, 0.92, &[
            "We are a funds recovery service. We can help you get back the money you lost to a scam. Our recovery team has already traced your stolen funds. Pay a small fee to initiate the recovery process.",
            "Have you been scammed? Our asset recovery team can help you reclaim your lost funds. We have successfully recovered millions for scam victims. Contact us to start the recovery process.",
            "We are from the cybercrime recovery division. Your case has been reviewed and we can help you get your money back. Pay the tracing fee and we will recover your stolen funds within 7 days.",
            // Short-message variants
            "Lost money to a scam? We can recover it. Pay tracing fee. 7 days guaranteed.",
            "Scammed? Our team recovers funds. Small fee to start. Contact now.",
            // Multilingual variants
            "Bạn bị lừa? Chúng tôi giúp bạn thu hồi tiền. Trả phí dịch vụ, 7 ngày nhận lại.",
            "ถูกหลอก? ทีมเราช่วยคืนเงินได้ จ่ายค่าบริการ 7 วันคืนให้",
            "Tertipu? Tim kami bisa pulihkan dana. Bayar biaya, 7 hari dikembalikan.",
        ][..]),

        IndicatorId::GovernmentBenefitLure => (0.88, 0.92, &[
            "You qualify for the ComCare assistance scheme. You are eligible for a government payout of $3000. Click here to claim your financial aid before the deadline.",
            "Good news! You are pre-approved for the Enhanced Housing Grant. Claim your government subsidy now. Reply with your details to receive the payout.",
            "You have been selected to receive a government relief fund payment. Claim your cash payout now. This is a cost of living support payment from the government.",
            // Short-message variants
            "You qualify for $3000 government payout. Click to claim before deadline.",
            "Pre-approved for government grant. Reply with details to receive payout.",
            // Multilingual variants
            "Bạn đủ điều kiện nhận trợ cấp chính phủ 3000 USD. Bấm nhận trước hạn chót.",
            "คุณมีสิทธิ์รับเงินช่วยเหลือจากรัฐ 3000 ดอลลาร์ คลิกรับก่อนหมดเขต",
            "Anda memenuhi syarat untuk bantuan pemerintah. Klaim sebelum batas waktu.",
        ][..]),

        IndicatorId::FakeMarketplace => (0.88, 0.92, &[
            "iPhone 15 Pro Max, brand new sealed in box. Retail price $1899, selling for only $500. Limited stock available. Authentic guaranteed. Contact me to buy now.",
            "Brand new Samsung Galaxy S24 Ultra, factory sealed. Below retail price at $400 only. Unopened, original brand. Wholesale price. First come first served, limited stock.",
            // Short-message variants
            "iPhone 15 Pro Max brand new sealed. $500 only. DM to buy. Limited stock.",
            "Samsung S24 Ultra factory sealed. $400. Wholesale price. First come first served.",
            // Multilingual variants
            "iPhone 15 Pro Max mới nguyên hộp. Giá chỉ 12 triệu. Liên hệ mua ngay. Còn ít hàng.",
            "iPhone 15 Pro Max ใหม่ในกล่อง ราคา 15000 บาท ติดต่อซื้อด่วน สต็อกจำกัด",
            "iPhone 15 Pro Max baru segel. Harga cuma 8 juta. Hubungi sekarang. Stok terbatas.",
        ][..]),

        IndicatorId::ThreatLegal => (0.88, 0.92, &[
            "This is a final legal notice. You will be arrested and face criminal charges if you do not respond immediately. A warrant has been issued for your arrest. Contact us now to resolve this matter.",
            // Short-message variants
            "Final notice. Arrest warrant issued. Call now to resolve.",
            "You will be arrested if you don't respond. Contact us immediately.",
            // Multilingual variants
            "Thông báo cuối cùng. Lệnh bắt đã được ban hành. Liên hệ ngay để giải quyết.",
            "หมายจับออกแล้ว ติดต่อมาทันทีเพื่อแก้ไขคดี",
            "Surat terakhir. Surat perintah penangkapan dikeluarkan. Hubungi segera.",
        ][..]),

        IndicatorId::ThreatAccount => (0.88, 0.92, &[
            "Your account has been suspended due to suspicious activity. Your account will be permanently closed in 24 hours unless you verify your identity immediately. Click here to reactivate.",
            // Short-message variants
            "Account suspended. Verify now or permanently closed in 24h.",
            "Your account will be deleted. Click to reactivate.",
            // Multilingual variants
            "Tài khoản bị tạm khóa do hoạt động bất thường. Xác minh ngay trong 24h hoặc khóa vĩnh viễn.",
            "บัญชีถูกระงับ ยืนยันตัวตนภายใน 24 ชม. มิฉะนั้นปิดถาวร",
            "Akun ditangguhkan. Verifikasi dalam 24 jam atau ditutup permanen.",
        ][..]),

        IndicatorId::VerificationRequest => (0.88, 0.92, &[
            "Verify your identity to secure your account. Your account has been flagged for unusual activity. Confirm your details at our secure portal to prevent permanent suspension.",
            "Your account has been deactivated for security reasons. Reactivate now to avoid permanent loss of access. Click here to verify your identity and restore your account.",
            "We detected unauthorized access to your account. Your account is temporarily locked. Please verify your identity to unlock and restore access to your account.",
            // Short-message variants
            "Verify your account now. Click link to confirm identity.",
            "Account locked. Verify identity to restore access.",
            // Multilingual variants
            "Xác minh danh tính để bảo mật tài khoản. Tài khoản bị khóa tạm. Bấm xác minh ngay.",
            "ยืนยันตัวตนเพื่อปลดล็อกบัญชี คลิกที่นี่",
            "Verifikasi identitas untuk membuka akun. Klik di sini.",
        ][..]),

        IndicatorId::TaxPenalty => (0.88, 0.92, &[
            "You have an unpaid toll fine on the expressway. Settle the outstanding amount immediately to avoid additional penalties or legal action. Click here to pay now.",
            "You have an outstanding traffic summons. Pay the compound fine before the deadline to avoid court action. Settle your violation penalty now through our online portal.",
            "Your ERP charges are overdue. Pay the outstanding road toll amount immediately to avoid enforcement action. Click the link to settle your toll fees online.",
            // Short-message variants
            "Unpaid toll fine. Pay now or face legal action. Click link.",
            "Traffic summons outstanding. Pay compound before deadline.",
            // Multilingual variants
            "Bạn có phí cầu đường chưa trả. Thanh toán ngay để tránh phạt thêm. Bấm vào link.",
            "ค่าทางด่วนค้างชำระ จ่ายเดี๋ยวนี้เพื่อหลีกเลี่ยงการดำเนินการ",
            "Denda tol belum dibayar. Bayar sekarang atau ditindak. Klik link.",
        ][..]),

        IndicatorId::FinancialRequest => (0.88, 0.92, &[
            "Your loan has been approved! Get $5,000 instantly with no collateral needed. Just pay the processing fee upfront to release the funds. Low interest, flexible repayment.",
            "Easy loan approval with no credit check. Get cash fast with minimal documentation. Pay the administrative fee to release your loan amount today.",
            // Short-message variants
            "Loan approved! $5000 instant. Pay processing fee to release. No collateral.",
            "Easy loan, no credit check. Pay admin fee to get cash today.",
            // Multilingual variants
            "Khoản vay đã duyệt! 50 triệu ngay. Trả phí xử lý để nhận tiền. Không cần thế chấp.",
            "สินเชื่ออนุมัติแล้ว! รับเงินทันที จ่ายค่าธรรมเนียมเพื่อปล่อยเงิน ไม่ต้องมีหลักทรัพย์",
            "Pinjaman disetujui! Bayar biaya administrasi untuk cair. Tanpa agunan.",
        ][..]),

        IndicatorId::Urgency => (0.90, 0.94, &[
            "Act now or your account will be permanently deleted. You have 2 hours to respond.",
            "Immediate action required. Failure to comply will result in legal consequences.",
            // Multilingual
            "Phải hành động ngay trong 2 giờ hoặc tài khoản sẽ bị xóa vĩnh viễn.",
            "ต้องดำเนินการทันทีภายใน 2 ชั่วโมง มิฉะนั้นบัญชีจะถูกลบ",
            "Harus bertindak segera dalam 2 jam atau akun akan dihapus permanen.",
        ][..]),

        IndicatorId::CredentialRequest => (0.90, 0.94, &[
            "Please share your OTP code sent to your phone. We need it to verify your account.",
            "Enter your password and OTP to confirm your identity. Don't share this code with anyone.",
            // Multilingual
            "Vui lòng chia sẻ mã OTP gửi đến điện thoại của bạn. Chúng tôi cần để xác minh.",
            "กรุณาแชร์รหัส OTP ที่ส่งไปยังโทรศัพท์ของคุณ เราต้องการเพื่อยืนยัน",
            "Bagikan kode OTP yang dikirim ke ponsel Anda. Kami butuh untuk verifikasi.",
        ][..]),

        IndicatorId::RemoteAccess => (0.90, 0.94, &[
            "Download AnyDesk and allow remote access so our technician can fix your computer.",
            "Install TeamViewer so we can access your device and resolve the security issue.",
            // Multilingual
            "Tải AnyDesk và cho phép truy cập từ xa để kỹ thuật viên sửa máy của bạn.",
            "ดาวน์โหลด AnyDesk และอนุญาตการเข้าถึงระยะไกล เพื่อให้ช่างเทคนิคแก้ปัญหา",
            "Unduh AnyDesk dan izinkan akses jarak jauh agar teknisi bisa memperbaiki.",
        ][..]),

        IndicatorId::CryptoScheme => (0.89, 0.93, &[
            "Join our crypto staking platform. Earn 50% APY on your Bitcoin. Zero risk, guaranteed returns. Connect your wallet to start earning.",
            "New token presale! Get 10x returns on launch. Connect your wallet and buy now before the price goes up.",
            // Multilingual
            "Tham gia nền tảng staking tiền ảo. Lãi 50%/năm, không rủi ro. Kết nối ví để bắt đầu.",
            "เข้าร่วมแพลตฟอร์มสตาร์คิงคริปโต รับ 50% APY เชื่อมวอลเล็ตเริ่มต้น",
            "Gabung platform staking kripto. Dapat 50% APY. Hubungkan wallet untuk mulai.",
        ][..]),

        IndicatorId::GiftCard => (0.90, 0.94, &[
            "Pay the fee using Steam gift cards or Google Play cards. Buy them from the store and send us the codes.",
            "We only accept payment via iTunes gift cards. Purchase them and send the redemption codes.",
            // Multilingual
            "Thanh toán bằng thẻ Steam hoặc Google Play. Mua và gửi mã thẻ cho chúng tôi.",
            "ชำระด้วยบัตรของขวัญ Steam ซื้อแล้วส่งรหัสให้เรา",
            "Bayar pakai kartu hadiah Steam. Beli dan kirim kodenya ke kami.",
        ][..]),

        IndicatorId::PersonalInfoRequest => (0.90, 0.94, &[
            "Please provide your full name, date of birth, ID number, and address to complete your profile.",
            "We need your passport number and national ID for verification. Reply with your details.",
            // Multilingual
            "Vui lòng cung cấp họ tên, ngày sinh, số CMND và địa chỉ để hoàn tất hồ sơ.",
            "กรุณาให้ชื่อเต็ม วันเกิด เลขบัตรประชาชน และที่อยู่",
            "Mohon berikan nama lengkap, tanggal lahir, nomor KTP, dan alamat.",
        ][..]),

        IndicatorId::BankTransfer => (0.90, 0.94, &[
            "Transfer the payment to this bank account: 1234567890, Vietcombank, Nguyen Van A.",
            "Send the money to this account number: 9876543210, BCA Bank, PT Sejahtera.",
            // Multilingual
            "Chuyển khoản vào số tài khoản: 1234567890, Vietcombank, Nguyễn Văn A.",
            "โอนเงินเข้าบัญชี: 1234567890 ธนาคารกสิกรไทย คุณสมชาย",
            "Transfer ke rekening: 1234567890 BCA Bank PT Sejahtera.",
        ][..]),

        IndicatorId::QRCodeScan => (0.89, 0.93, &[
            "Scan this QR code to pay for your parking. Quick and convenient contactless payment.",
            "Scan the QR code below to complete your payment and receive your order.",
            "To claim your refund, simply scan this QR code with your banking app.",
            // Multilingual
            "Quét mã QR để thanh toán phí giữ xe. Nhanh chóng và tiện lợi.",
            "สแกน QR code เพื่อชำระค่าจอดรถ สะดวกรวดเร็ว",
            "Pindai kode QR untuk membayar biaya parkir. Cepat dan mudah.",
        ][..]),

        IndicatorId::WrongNumberPivot => (0.88, 0.92, &[
            "Hi, I got your number by mistake but you seem like a nice person. Let's be friends!",
            "Sorry, wrong number! But you sound interesting. What do you do for work?",
            "I think I added the wrong number. Are you free to chat? You seem kind.",
            // Multilingual
            "Xin lỗi, nhầm số rồi! Nhưng bạn có vẻ vui tính. Làm quen nhé!",
            "ขอโทษครับ โทรผิดเบอร์! แต่คุณดูน่าคุยดี มาคุยกันไหมครับ",
            "Maaf, salah nomor! Tapi kamu sepertinya orang yang menarik. Kenalan yuk!",
        ][..]),

        IndicatorId::SubscriptionTrap => (0.89, 0.93, &[
            "Your free trial has ended. You will be charged $49.99/month starting today. To cancel, call our premium rate number.",
            "Your subscription has been activated. Monthly charges of $29.99 will apply automatically. Cancel anytime by calling our hotline.",
            // Multilingual
            "Gói dùng thử miễn phí đã hết. Bạn sẽ bị tính phí $49.99/tháng từ hôm nay.",
            "การทดลองใช้ฟรีสิ้นสุดแล้ว จะมีการเรียกเก็บ $49.99/เดือน ตั้งแต่วันนี้",
            "Uji coba gratis Anda telah berakhir. Anda akan dikenakan biaya $49.99/bulan mulai hari ini.",
        ][..]),

        IndicatorId::DeepfakeImpersonation => (0.90, 0.94, &[
            "This is a live video call from your boss. Please verify your identity by looking at the camera.",
            "I am calling you with AI voice cloning technology to verify this is really you on the phone.",
            // Multilingual
            "Đây là cuộc gọi video từ sếp của bạn. Vui lòng xác thực danh tính.",
            "นี่คือการโทรวิดีโอจากเจ้านายของคุณ กรุณายืนยันตัวตน",
            "Ini adalah panggilan video dari atasan Anda. Silakan verifikasi identitas Anda.",
        ][..]),

        _ => return None,
    };

    Some(EmbeddingConfig { threshold, high_threshold, prototypes })
}

/// All indicators that have embedding prototypes configured.
const EMBEDDING_INDICATORS: &[IndicatorId] = &[
    IndicatorId::RomanceGrooming,
    IndicatorId::AuthorityClaim,
    IndicatorId::PromiseHighReturn,
    IndicatorId::CharityAppeal,
    IndicatorId::FamilyEmergency,
    IndicatorId::JobOffer,
    IndicatorId::DeliveryLure,
    IndicatorId::PrizeLure,
    IndicatorId::Sextortion,
    IndicatorId::RecoveryScam,
    IndicatorId::GovernmentBenefitLure,
    IndicatorId::FakeMarketplace,
    IndicatorId::ThreatLegal,
    IndicatorId::ThreatAccount,
    IndicatorId::VerificationRequest,
    IndicatorId::TaxPenalty,
    IndicatorId::FinancialRequest,
    // New: expanded embedding coverage
    IndicatorId::Urgency,
    IndicatorId::CredentialRequest,
    IndicatorId::RemoteAccess,
    IndicatorId::CryptoScheme,
    IndicatorId::GiftCard,
    IndicatorId::PersonalInfoRequest,
    IndicatorId::BankTransfer,
    // New: emerging scam pattern indicators
    IndicatorId::QRCodeScan,
    IndicatorId::WrongNumberPivot,
    IndicatorId::SubscriptionTrap,
    IndicatorId::DeepfakeImpersonation,
];

/// Pre-compute embedding vectors for all prototype texts across all indicators.
///
/// Should be called once when the embedding model is first loaded.
/// Returns a map from indicator ID to a list of embedding vectors (one per prototype).
pub async fn precompute_prototype_cache(
    engine: &mut AiEngine,
) -> Result<HashMap<IndicatorId, Vec<Vec<f32>>>, zk_ai_core::ZkAiError> {
    let mut cache = HashMap::new();

    for &indicator_id in EMBEDDING_INDICATORS {
        let config = match embedding_config(indicator_id) {
            Some(c) => c,
            None => continue,
        };

        let mut proto_embeddings = Vec::with_capacity(config.prototypes.len());
        for &prototype in config.prototypes {
            let prefixed = format!("query: {}", prototype);
            let emb = engine.run_embedding(&prefixed).await?;
            proto_embeddings.push(emb);
        }
        cache.insert(indicator_id, proto_embeddings);
    }

    Ok(cache)
}

/// Detect indicators using embedding-based semantic similarity.
///
/// Uses multi-prototype matching: takes the max similarity across all
/// pre-computed prototype embeddings for an indicator. Per-indicator
/// thresholds allow broader patterns (AuthorityClaim) to fire at lower
/// thresholds while specific patterns (FamilyEmergency) require higher
/// similarity.
///
/// Only one embedding inference call is made per message (for the input text).
/// Prototype embeddings are pre-computed by `precompute_prototype_cache`.
pub async fn detect_embeddings(
    engine: &mut AiEngine,
    prototype_cache: &HashMap<IndicatorId, Vec<Vec<f32>>>,
    text: &str,
    _channel: Channel,
    _language: &str,
) -> Result<Vec<IndicatorHit>, zk_ai_core::ZkAiError> {
    let prefixed_text = format!("query: {}", text);
    let text_embedding = engine.run_embedding(&prefixed_text).await?;
    let mut hits = Vec::new();

    for &indicator_id in EMBEDDING_INDICATORS {
        let config = match embedding_config(indicator_id) {
            Some(c) => c,
            None => continue,
        };

        let proto_embeddings = match prototype_cache.get(&indicator_id) {
            Some(embs) => embs,
            None => continue,
        };

        let mut best_score = 0.0f32;

        for proto_emb in proto_embeddings {
            let score = cosine_similarity(&text_embedding, proto_emb);
            if score > best_score {
                best_score = score;
            }
        }

        if best_score >= config.threshold {
            let strength = if best_score >= config.high_threshold {
                IndicatorStrength::High
            } else {
                IndicatorStrength::Medium
            };
            hits.push(IndicatorHit {
                id: indicator_id,
                strength,
                match_count: 1,
            });
        }
    }

    hits.sort_by(|a, b| {
        b.strength.weight().partial_cmp(&a.strength.weight()).unwrap_or(std::cmp::Ordering::Equal)
    });

    Ok(hits)
}
