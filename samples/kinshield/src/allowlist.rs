//! Sender and domain allowlists for false positive reduction.
//!
//! Legitimate institutions (banks, telcos, e-commerce, government) send
//! notifications that use scam-adjacent vocabulary (urgency, credentials,
//! financial requests). This module provides:
//!
//! - **Sender brand tags**: `[DBS]`, `[Shopee]`, etc. — used to identify
//!   legitimate senders and reduce risk.
//! - **Domain allowlist**: legitimate domains that should never trigger
//!   `LinkSuspicious` on their own.
//! - **Legitimate notification patterns**: security alerts, transaction
//!   confirmations, refund notices — patterns that strongly indicate
//!   a genuine notification rather than a scam.

/// Known legitimate sender brand tags found in SMS/message headers.
///
/// When a message contains one of these tags (e.g., `[DBS]`), it's
/// likely from the legitimate institution. This is used to strengthen
/// legitimacy reduction in scoring.
pub const SENDER_BRAND_TAGS: &[&str] = &[
    // Singapore banks
    "[dbs]", "[posb]", "[ocbc]", "[uob]", "[hsbc]", "[citibank]", "[citi]",
    "[standard chartered]", "[scb]", "[bofa]",
    // Singapore government
    "[cpf]", "[gov.sg]", "[spf]", "[moh]", "[mom]", "[ica]", "[hdb]",
    "[mas]", "[ir]", "[iras]", "[ministry", "[acra]", "[hota]", "[mfa]",
    // Singapore telcos
    "[singtel]", "[starhub]", "[m1]", "[circles]", "[gomo]", "[giga]",
    // Singapore services
    "[singpost]", "[grab]", "[shopee]", "[lazada]", "[carousell]", "[qoo10]",
    "[ninja van]", "[ninjavan]", "[qexpress]", "[ezbuy]", "[foodpanda]",
    "[deliveroo]", "[dbs]", "[posb]",
    // Singapore misc
    "[microsoft]", "[google]", "[apple]", "[netflix]", "[spotify]",
    "[youtube]", "[telegram]", "[whatsapp]", "[facebook]", "[instagram]",
    "[tiktok]", "[garena]", "[steam]", "[riot]",
    // Vietnam banks
    "[vietcombank]", "[vcb]", "[tpbank]", "[techcombank]", "[tcb]",
    "[vietinbank]", "[bidv]", "[hdbank]", "[vpbank]", "[agribank]",
    "[acb]", "[mb bank]", "[mbbank]", "[sacombank]", "[eximbank]",
    "[vib]", "[nam a]", "[bac a]", "[ocb]", "[tpb]", "[lienvietpostbank]",
    "[vrb]", "[pvcombank]", "[gp bank]", "[capital]", "[pvi]",
    // Vietnam fintech
    "[momo]", "[vnpay]", "[zalopay]", "[vietnam post]", "[vnpost]",
    "[viettel]", "[viettel money]", "[viettel pay]",
    "[vnpt]", "[mobifone]", "[vinaphone]", "[fpt]",
    "[ghn]", "[ghtk]", "[tiki]", "[sendo]", "[winmart]", "[thegioididong]",
    "[dien may xanh]", "[chotot]", "[shopee]", "[lazada]", "[grab]",
    // Vietnam government
    "[vneid]", "[dvc]", "[dichvucong]", "[gov.vn]", "[bo tai chinh]",
    "[mof]", "[sbv]", "[ngan hang nha nuoc]", "[tax]", "[thue]",
    "[gdt]", "[cucthue]", "[bhxh]", "[bao hiem xa hoi]",
    // Thailand banks
    "[bangkok bank]", "[bbl]", "[kasikorn]", "[kbank]", "[krungthai]",
    "[krungsri]", "[scb]", "[k plus]", "[kplus]", "[ttb]", "[bay]",
    "[tisco]", "[lh bank]", "[uob]", "[hsbc]",
    "[tmb]", "[tbank]", "[bankthai]", "[tcrb]", "[baac]",
    "[gsb]", "[government savings bank]", "[cimb thai]",
    // Thailand telco/services
    "[ais]", "[truemoney]", "[lalamove]", "[thai post]", "[thailand post]",
    "[grab]", "[shopee]", "[lazada]", "[line]", "[line man]",
    "[dtac]", "[true]", "[true move]", "[truemove]", "[3bb]",
    "[promptpay]", "[rabbit line pay]", "[shopeepay]",
    // Indonesia banks
    "[bca]", "[mandiri]", "[bni]", "[bri]", "[cimb niaga]", "[cimb]",
    "[permata]", "[danamon]", "[btn]", "[bsi]", "[mega]", "[bukopin]",
    "[panin]", "[btpn]", "[btpn jenius]", "[jenius]", "[neo]",
    "[bank jago]", "[jago]", "[alfamart]", "[indomaret]",
    // Indonesia e-commerce/telco/fintech
    "[tokopedia]", "[bukalapak]", "[telkomsel]", "[indosat]", "[xl]",
    "[gojek]", "[gopay]", "[ovo]", "[dana]", "[linkaja]", "[jne]",
    "[j&t]", "[pos indonesia]", "[shopee]", "[lazada]", "[grab]",
    "[blibli]", "[bukalapak]", "[sicepat]", "[jnt]",
    "[shopeepay]", "[akulaku]", "[kredivo]", "[atome]",
    "[tri]", "[3]", "[by.u]", "[mytelkomsel]",
    // Malaysia banks
    "[maybank]", "[cimb]", "[public bank]", "[rhb]", "[ambank]",
    "[bank rakyat]", "[hong leong]", "[hong leong bank]", "[affin]",
    "[bsn]", "[muamalat]", "[agrobank]",
    "[kuwait finance]", "[kfh]", "[bank islam]", "[amislam]",
    "[alliance bank]", "[abmb]",
    // Malaysia telco/services
    "[maxis]", "[celcom]", "[digi]", "[u mobile]", "[yes]",
    "[pos malaysia]", "[grab]", "[shopee]", "[lazada]", "[touch n go]",
    "[tng]", "[boost]", "[rm10]", "[rm50]",
    "[unifi]", "[tm]", "[telekom]", "[aeon]", "[aeon credit]",
    "[shopeepay]", "[setel]", "[riz]",
    // Philippines banks/services
    "[bdo]", "[bpi]", "[metrobank]", "[gcash]", "[globe]", "[smart]",
    "[lbc]", "[paymaya]", "[maya]", "[shopee]", "[lazada]", "[grab]",
    "[palawan]", "[cebuana]", "[mlhuillier]", "[western union]",
    "[unionbank]", "[security bank]", "[chinabank]", "[pnb]",
    "[rcbc]", "[psbank]", "[aub]", "[eastwest]",
    "[sun cellular]", "[tnt]", "[globe]", "[pldt]",
    "[foodpanda]", "[grabfood]", "[angkas]", "[joyride]",
    // Cambodia banks/services
    "[aba]", "[aba bank]", "[acleda]", "[acleda bank]", "[canadia]",
    "[sathapana]", "[wing]", "[wing money]", "[true money]",
    "[pi pay]", "[pipay]", "[smart]", "[cellcard]", "[metfone]",
    "[seatech]", "[ly hour]", "[prasac]", "[amret]", "[hattha]",
    // Cambodia e-commerce/delivery
    "[nham24]", "[foodpanda]", "[grab]", "[lalamove]", "[deliveree]",
    // International delivery
    "[dhl]", "[fedex]", "[ups]", "[yodel]", "[royal mail]",
    "[jnt]", "[j&t]",
    // International banks
    "[hsbc]", "[standard chartered]", "[citibank]", "[jpmorgan]",
    // Careers
    "[uob careers]", "[dbs careers]", "[ocbc careers]", "[grab careers]",
    // Thailand government
    "[rd]", "[revenue department]", "[dopa]", "[moj]", "[moe]",
    "[moph]", "[dsi]", "[nacc]", "[oic]",
    // Indonesia government
    "[kemenkeu]", "[djp]", "[direktorat jenderal pajak]",
    "[bkn]", "[kemenkes]", "[kemendikbud]", "[kemenhub]",
    "[bnpt]", "[kominfo]", "[oss]", "[dinsos]",
    // Malaysia government
    "[lhdn]", "[jpn]", "[jpj]", "[kkm]", "[moe]",
    "[jkm]", "[moha]", "[mod]", "[kpkt]",
    // Philippines government
    "[bir]", "[sss]", "[philhealth]", "[pag-ibig]", "[gsis]",
    "[dswd]", "[doj]", "[comelec]", "[nbi]", "[pnp]",
    // Cambodia government
    "[gdt]", "[general department of taxation]", "[mef]",
    "[moj]", "[moeys]", "[moh]", "[ncct]", "[cib]",
];

/// Check if text contains a recognized sender brand tag.
pub fn has_sender_brand_tag(lower_text: &str) -> bool {
    SENDER_BRAND_TAGS.iter().any(|tag| lower_text.contains(tag))
}

/// Known brand names that appear in legitimate messages without bracket format.
/// Used to detect legitimate sender identity (e.g., "ACB: Quý khách...", "BIDV: Thông báo...").
/// Short names (≤4 chars) require word-boundary or colon/space suffix to avoid false matches.
pub const KNOWN_BRAND_NAMES: &[&str] = &[
    // Vietnam banks
    "vietcombank", "techcombank", "bidv", "mbbank", "mb bank",
    "agribank", "vietinbank", "acb", "tpbank", "vpbank",
    "sacombank", "eximbank", "hdbank", "ocb", "vib",
    "nam a bank", "bac a bank", "lienvietpostbank", "pvcombank",
    // Vietnam fintech/telco
    "momo", "vnpay", "zalopay", "viettel money", "viettel pay",
    "viettel", "vnpt", "mobifone", "vinaphone", "fpt",
    "ghn", "ghtk", "tiki", "sendo", "winmart", "thegioididong",
    "chotot", "shopee", "lazada", "grab",
    // Vietnam government
    "vneid", "dichvucong", "dvc", "gdt", "cucthue", "bhxh",
    "bao hiem xa hoi", "bo tai chinh", "sbv",
    // Thailand banks
    "bangkok bank", "kasikorn", "kbank", "krungthai", "krungsri",
    "scb", "k plus", "kplus", "ttb", "tisco", "lh bank",
    "gsb", "baac", "tcrb",
    // Thailand telco/services
    "ais", "dtac", "truemove", "true move", "promptpay",
    // Indonesia banks
    "bca", "mandiri", "bni", "bri", "cimb niaga", "cimb",
    "permata", "danamon", "btn", "bsi", "panin", "btpn",
    "jenius", "bank jago", "jago",
    // Indonesia e-commerce/telco
    "tokopedia", "bukalapak", "telkomsel", "indosat", "xl",
    "gojek", "gopay", "ovo", "dana", "linkaja",
    "blibli", "sicepat", "shopeepay", "akulaku", "kredivo",
    // Malaysia banks
    "maybank", "cimb", "public bank", "rhb", "ambank",
    "bank rakyat", "hong leong", "affin", "bsn", "agrobank",
    "bank islam", "alliance bank",
    // Malaysia telco/services
    "maxis", "celcom", "digi", "u mobile", "unifi",
    "touch n go", "tng", "boost", "aeon",
    // Philippines banks/services
    "bdo", "bpi", "metrobank", "gcash", "paymaya", "maya",
    "unionbank", "security bank", "chinabank", "pnb", "rcbc",
    "psbank",
    // Philippines telco
    "globe", "smart", "pldt",
    // Cambodia banks/services
    "aba bank", "aba", "acleda", "acleda bank", "canadia",
    "wing", "wing money", "sathapana",
    // International
    "hsbc", "standard chartered", "citibank",
    "dhl", "fedex", "ups",
    "microsoft", "google", "apple", "netflix", "spotify",
    "telegram", "whatsapp", "facebook", "instagram", "tiktok",
];

/// Check if text contains a known brand name (non-bracket format).
/// For short brand names (≤4 chars), requires word-boundary or colon/space suffix
/// to avoid false positive matches (e.g., "acb" won't match "transaction").
pub fn has_known_brand_name(lower_text: &str) -> bool {
    for brand in KNOWN_BRAND_NAMES {
        if brand.len() <= 4 && brand.is_ascii() {
            // Short ASCII brands need word-boundary matching
            if word_boundary_brand_match(lower_text, brand) {
                return true;
            }
        } else {
            if lower_text.contains(brand) {
                return true;
            }
        }
    }
    false
}

/// Check if a short brand name appears as a word (followed by colon, space, or word boundary).
fn word_boundary_brand_match(lower_text: &str, brand: &str) -> bool {
    let text = lower_text;
    let mut search_start = 0;
    while let Some(pos) = text[search_start..].find(brand) {
        let abs_pos = search_start + pos;
        let end_pos = abs_pos + brand.len();
        // Check char before is not alphanumeric
        let ok_before = abs_pos == 0
            || !text[..abs_pos].chars().next_back().is_some_and(|c| c.is_alphanumeric());
        // Check char after is colon, space, newline, or non-alphanumeric
        let after_byte = end_pos;
        let ok_after = after_byte >= text.len()
            || !text[after_byte..].chars().next().is_some_and(|c| c.is_alphanumeric());
        if ok_before && ok_after {
            return true;
        }
        search_start = abs_pos + 1;
    }
    false
}

/// Legitimate domains that should not trigger `LinkSuspicious` on their own.
///
/// Extracted from the `KNOWN_BRANDS` list in `url.rs` plus additional
/// legitimate government and service domains.
pub const ALLOWED_DOMAINS: &[&str] = &[
    // Singapore
    "dbs.com", "dbs.com.sg", "dbs.sg", "posb.com.sg", "posb.sg",
    "ocbc.com", "ocbc.com.sg", "uob.com", "uob.com.sg", "uob.sg",
    "hsbc.com", "hsbc.com.sg", "sc.com", "standardchartered.com",
    "cpf.gov.sg", "gov.sg", "iras.gov.sg", "moh.gov.sg", "mom.gov.sg",
    "ica.gov.sg", "hdb.gov.sg", "mas.gov.sg", "acra.gov.sg",
    "singtel.com", "starhub.com", "m1.com.sg",
    "singpost.com", "grab.com", "grab.sg",
    "shopee.sg", "shopee.com", "shopee.vn", "shopee.co.id", "shopee.com.my", "shopee.ph", "shopee.co.th",
    "lazada.sg", "lazada.com", "lazada.vn", "lazada.co.id", "lazada.com.my", "lazada.com.ph",
    "carousell.sg", "carousell.com", "qoo10.sg", "qoo10.com",
    "ninjavan.co", "ninjavan.com", "foodpanda.sg", "deliveroo.sg",
    // Vietnam
    "vietcombank.com.vn", "vcb.vn", "tpb.vn", "tpbank.vn", "tpbank.com.vn",
    "techcombank.com.vn", "tcb.vn", "vietinbank.com.vn", "bidv.com.vn",
    "hdbank.com.vn", "vpbank.com.vn", "agribank.com.vn", "acb.com.vn",
    "mbbank.com.vn", "sacombank.com.vn", "eximbank.com.vn",
    "vib.com.vn", "namabank.com.vn", "baca.com.vn", "ocb.com.vn",
    "momo.vn", "vnpay.vn", "zalopay.vn", "vnpost.vn",
    "viettel.com.vn", "mobifone.vn", "vinaphone.vn", "fpt.com",
    "ghn.vn", "ghtk.vn", "tiki.vn", "sendo.vn", "winmart.vn",
    "thegioididong.com", "dienmayxanh.com", "chotot.com",
    "gov.vn", "dichvucong.gov.vn", "mof.gov.vn", "sbv.gov.vn",
    "tax.gov.vn", "gdt.gov.vn", "bhxh.gov.vn",
    // Thailand
    "bbl.co.th", "kasikornbank.com", "kbank.com", "krungthai.com",
    "krungsri.com", "scb.co.th", "kplus.com", "ttb.co.th",
    "ais.co.th", "truemoney.com", "lalamove.com",
    "thailandpost.co.th",
    "dtac.co.th", "truemove.co.th", "truemoveh.co.th",
    "promptpay.co.th", "rabbitlinepay.com",
    "tisco.co.th", "lhbank.co.th", "bay.co.th",
    "gsb.or.th", "baac.or.th", "tcrb.co.th",
    "rd.go.th", "dopa.go.th", "moph.go.th", "moj.go.th",
    "nacc.go.th", "dsi.go.th",
    // Indonesia
    "bca.co.id", "bankmandiri.co.id", "bni.co.id", "bri.co.id",
    "cimbniaga.co.id", "permatabank.com", "bankdanamon.co.id",
    "tokopedia.com", "bukalapak.com", "telkomsel.com", "indosat.com",
    "gojek.com", "go-jek.com", "ovo.id", "dana.id", "linkaja.com",
    "jne.co.id", "jet.co.id", "posindonesia.co.id",
    "blibli.com", "sicepat.com",
    "panin.co.id", "btpn.co.id", "jenius.com", "bankjago.co.id",
    "bsi.co.id", "btn.co.id", "mega.co.id",
    "shopeepay.co.id", "kredivo.com", "akulaku.com",
    "kemenkeu.go.id", "pajak.go.id", "djp.go.id",
    "bkn.go.id", "kemenkes.go.id", "kominfo.go.id",
    // Malaysia
    "maybank2u.com", "maybank.com", "cimbclicks.com", "cimb.com",
    "pbebank.com", "rhbgroup.com", "ambankgroup.com", "bankrakyat.com.my",
    "hongleong.com", "hongleongbank.com", "affinbank.com.my",
    "bsn.com.my", "muamalat.com.my", "agrobank.com.my",
    "maxis.com.my", "celcom.com.my", "digi.com.my",
    "pos.com.my", "tngdigital.com.my", "myboost.com.my",
    "bankislam.com", "kfh.com.my", "alliancebank.com.my",
    "aeoncredit.com.my", "unifi.com.my", "tm.com.my",
    "lhdn.gov.my", "jpj.gov.my", "kkm.gov.my", "jkm.gov.my",
    // Philippines
    "bdo.com.ph", "bpi.com.ph", "metrobank.com.ph",
    "gcash.com", "globe.com.ph", "smart.com.ph",
    "lbcexpress.com", "paymaya.com", "mayabank.ph",
    "unionbankph.com", "securitybank.com", "chinabank.ph",
    "pnb.com.ph", "rcbc.com", "psbank.com.ph",
    "bir.gov.ph", "sss.gov.ph", "philhealth.gov.ph",
    "pagibigfund.gov.ph", "gsis.gov.ph", "dswd.gov.ph",
    // Cambodia
    "ababank.com", "aba.com.kh", "acledabank.com",
    "canadiabank.com", "sathapana.com", "wingmoney.com",
    "truemoney.com.kh", "pipay.com.kh", "smart.com.kh",
    "cellcard.com", "metfone.com.kh",
    "nham24.com", "lyhour.com", "prasac.com", "amret.com.kh",
    "gdt.gov.kh", "mef.gov.kh", "moeys.gov.kh",
    // International
    "apple.com", "icloud.com", "microsoft.com", "live.com", "outlook.com",
    "google.com", "netflix.com", "spotify.com", "youtube.com", "youtu.be",
    "telegram.org", "whatsapp.com", "facebook.com", "instagram.com",
    "tiktok.com", "garena.sg", "garena.com",
    "steampowered.com", "steamcommunity.com", "valvesoftware.com",
    "riotgames.com", "dhl.com", "fedex.com", "ups.com",
    "binance.com", "binance.vn",
    // Additional legitimate domains
    "fpt.vn", "fpt.com", "fpt.com.vn",
    "baohiemxahoi.gov.vn", "bhxh.gov.vn",
    "notarise.gov.sg", "skillsfuture.gov.sg", "skillsfuture.sg",
    "best-inc.com", "best-inc.vn",
    "tigerbrokers.com",
    "vnpt.com.vn", "vietnamobile.com.vn",
    "paypal.com", "stripe.com", "wise.com",
    "tcbs.com.vn", "vndirect.com.vn", "ssi.com.vn",
    "hsc.com.vn", "vps.com.vn", "dnse.com.vn",
    "kbnn.gov.vn", "vnid.vn", "dichvucong.gov.vn",
    "mi.com", "xiaomi.com",
    "dell.com", "asus.com", "acer.com", "lenovo.com", "hp.com",
    "people.com.sg", "pa.gov.sg",
    "tigerbrokers.com", "tigerbrokers.com.sg",
    "spx.co", "spx.vn",
    "ninjavan.co", "ninjavan.com",
];

/// Check if a domain is in the allowlist.
///
/// Returns true if `domain` exactly matches or is a subdomain of
/// an allowed domain.
pub fn is_allowed_domain(domain: &str) -> bool {
    let lower = domain.to_lowercase();
    // Strip common prefixes like "www."
    let stripped = lower.strip_prefix("www.").unwrap_or(&lower);
    for &allowed in ALLOWED_DOMAINS {
        if stripped == allowed || stripped.ends_with(&format!(".{}", allowed)) {
            return true;
        }
    }
    false
}

/// Patterns that strongly indicate a legitimate security notification.
///
/// These are messages from institutions about account security events
/// (password changes, login alerts, OTP delivery) that use scam-adjacent
/// vocabulary but are genuine.
pub fn is_security_notification(lower: &str) -> bool {
    // "Password was changed" / "password has been changed"
    let password_changed = lower.contains("password was changed")
        || lower.contains("password has been changed")
        || lower.contains("password changed")
        || lower.contains("mật khẩu") && (lower.contains("thay đổi") || lower.contains("được thay"))
        || lower.contains("mat khau") && (lower.contains("thay doi") || lower.contains("duoc thay"))
        || lower.contains("รหัสผ่าน") && lower.contains("เปลี่ยน")
        || lower.contains("kata laluan") && lower.contains("ditukar")
        || lower.contains("kata sandi") && (lower.contains("diubah") || lower.contains("berubah"));

    // "If this wasn't you" / "if not you" — classic security alert pattern
    let if_not_you = lower.contains("if this wasn't you")
        || lower.contains("if this was not you")
        || lower.contains("if not you")
        || lower.contains("if you did not")
        || lower.contains("nếu không phải bạn")
        || lower.contains("neu khong phai ban")
        || lower.contains("nếu không phải anh")
        || lower.contains("nếu không phải chị")
        || lower.contains("jika bukan anda")
        || lower.contains("jika bukan awak")
        || lower.contains("jika anda tidak")
        || lower.contains("ถ้าไม่ใช่คุณ")
        || lower.contains("kung hindi ikaw")
        || lower.contains("kung hindi mo");

    // "Login from new device" / "new login detected"
    let new_login = lower.contains("new login")
        || lower.contains("login from new")
        || lower.contains("login detected")
        || lower.contains("sign-in from")
        || lower.contains("đăng nhập từ")
        || lower.contains("dang nhap tu")
        || lower.contains("masuk dari")
        || lower.contains("เข้าสู่ระบบจาก");

    // OTP delivery message (contains OTP/code + "do not share" variants)
    let has_otp = lower.contains("otp") || lower.contains("verification code")
        || lower.contains("one-time password") || lower.contains("one time password")
        || lower.contains("mã xác nhận") || lower.contains("ma xac nhan")
        || lower.contains("mã otp") || lower.contains("ma otp")
        || lower.contains("kode otp") || lower.contains("kode verifikasi")
        || lower.contains("รหัส otp") || lower.contains("รหัสยืนยัน")
        || lower.contains("code")
        || lower.contains("pin");

    let has_dont_share = lower.contains("do not share")
        || lower.contains("don't share")
        || lower.contains("never ask")
        || lower.contains("never share")
        || lower.contains("không chia sẻ") || lower.contains("khong chia se")
        || lower.contains("không tiết lộ") || lower.contains("khong tiet lo")
        || lower.contains("jangan berikan")
        || lower.contains("jangan bagikan")
        || lower.contains("jangan sebarkan")
        || lower.contains("jangan beri")
        || lower.contains("jangan kongsi")
        || lower.contains("tidak akan pernah meminta")
        || lower.contains("tidak pernah minta")
        || lower.contains("ไม่แชร์") || lower.contains("ห้ามแชร์")
        || lower.contains("hindi ibigay") || lower.contains("wag ibigay")
        || lower.contains("hindi i-share") || lower.contains("wag i-share")
        || lower.contains("កានតែមិនដែលសុំ");

    // "Contact us at" an email or phone number is a phishing pattern,
    // not a legitimate OTP delivery. Legitimate OTP messages just deliver
    // the code without asking the user to contact anyone.
    let has_contact_request = lower.contains("contact us at")
        || lower.contains("contact us immediately")
        || lower.contains("call us at")
        || lower.contains("call immediately")
        || lower.contains("reply to this number");

    // OTP delivery with "do not share" is almost always legitimate,
    // UNLESS it asks the user to contact someone (phishing pattern)
    if has_otp && has_dont_share && !has_contact_request {
        return true;
    }

    // Password changed notification with "if not you" is a security alert
    if password_changed && if_not_you {
        return true;
    }

    // New login alert with "if not you"
    if new_login && if_not_you {
        return true;
    }

    // Password changed + brand tag (even without "if not you")
    if password_changed && has_sender_brand_tag(lower) {
        return true;
    }

    false
}

/// Patterns that indicate a legitimate transaction notification.
///
/// These are messages confirming a completed transaction, not requesting one.
pub fn is_transaction_notification(lower: &str) -> bool {
    // Transaction completed/processed/credited
    let transaction_completed =
        lower.contains("has been completed")
        || lower.contains("has been processed")
        || lower.contains("has been credited")
        || lower.contains("has been sent")
        || lower.contains("has been debited")
        || lower.contains("has been posted")
        || lower.contains("successfully completed")
        || lower.contains("successfully changed")
        || lower.contains("transaction successful")
        || lower.contains("payment successful")
        || lower.contains("transfer successful")
        // Vietnamese
        || lower.contains("giao dịch thành công")
        || lower.contains("thanh toán thành công")
        || lower.contains("chuyển khoản thành công")
        // Vietnamese — "đã được" alone is too broad (means "has been"),
        // so require it to be followed by a transaction-related word
        || lower.contains("đã được xử lý")
        || lower.contains("đã được ghi nhận")
        || lower.contains("đã được duyệt")
        || lower.contains("đã được hoàn thành")
        || lower.contains("đã được chuyển")
        || lower.contains("đã được kích hoạt")
        || lower.contains("đã chuyển")
        || lower.contains("đã thanh toán")
        || lower.contains("đã chuyển khoản")
        // "thành công" alone is too broad — require transaction context
        || (lower.contains("thành công") && (lower.contains("giao dịch")
            || lower.contains("thanh toán") || lower.contains("chuyển khoản")))
        // Indonesian
        || lower.contains("transaksi berhasil")
        || lower.contains("pembayaran berhasil")
        || lower.contains("transfer berhasil")
        || lower.contains("pembayaran telah")
        || lower.contains("pembayaran selesai")
        || lower.contains("telah diterima")
        || lower.contains("telah berhasil")
        // Thai
        || lower.contains("ชำระสำเร็จ")
        || lower.contains("โอนสำเร็จ")
        || lower.contains("ทำรายการสำเร็จ")
        // Filipino
        || lower.contains("transaksyon ay tagumpay")
        || lower.contains("matagumpay")
        || lower.contains("natanggap na");

    // "Received a transaction" / "debit on your account"
    let received_notification =
        lower.contains("received a transaction")
        || lower.contains("received a payment")
        || lower.contains("ghi nhận một giao dịch")
        || lower.contains("ghi nhận giao dịch")
        || lower.contains("đã nhận được một giao dịch")
        || lower.contains("đã nhận được giao dịch")
        || lower.contains("tercatat transaksi")
        || lower.contains("transaksi tercatat")
        || lower.contains("มีธุรกรรม");

    // "Small transaction" alert (bank fraud monitoring)
    let small_txn_alert =
        (lower.contains("giao dịch nhỏ") || lower.contains("giao dich nho")
            || lower.contains("small transaction") || lower.contains("transaksi kecil"))
        && (lower.contains("if you did not") || lower.contains("nếu bạn không")
            || lower.contains("neu ban khong") || lower.contains("jika anda tidak"));

    transaction_completed || received_notification || small_txn_alert
}

/// Check if a transaction notification is actually a scam.
/// Messages that ask the user to return money, call a number, or visit a link
/// after mentioning a "credited" transaction are scams, not notifications.
fn is_transaction_scam_pattern(lower: &str) -> bool {
    // "Credited by mistake" + ask to return/call = scam
    (lower.contains("by mistake") || lower.contains("credited with"))
        && (lower.contains("please call") || lower.contains("arrange the return")
            || lower.contains("transfer back") || lower.contains("return the")
            || lower.contains("send back"))
    // Vietnamese: "chuyển nhầm" + ask to return = scam
    || (lower.contains("chuyển nhầm") || lower.contains("chuyen nham"))
        && (lower.contains("chuyển lại") || lower.contains("chuyen lai")
            || lower.contains("trả lại") || lower.contains("tra lai"))
}

/// Legitimate charity organizations that send donation appeals.
const LEGITIMATE_CHARITY_SENDERS: &[&str] = &[
    "[mttq", "mttq", "mặt trận tổ quốc", "mat tran to quoc",
    "[hội chữ thập đỏ", "hội chữ thập đỏ", "hoi chu thap do",
    "red cross", "changi", "community chest", "[nvpc",
    "[cứu trợ", "cuu tro", "quỹ cứu trợ",
    "unger foundation", "unicef", "who", "[who]",
    "từ thiện", "tu thien",
];

/// Check if text is from a legitimate charity organization.
pub fn is_legitimate_charity(lower: &str) -> bool {
    LEGITIMATE_CHARITY_SENDERS.iter().any(|&s| lower.contains(s))
}

/// Patterns that indicate a legitimate government notification.
pub fn is_government_notification(lower: &str) -> bool {
    // Identity card / CCCD notification (Vietnam)
    let id_card = lower.contains("cccd") || lower.contains("thẻ cccd")
        || lower.contains("the cccd") || lower.contains("identity card")
        || lower.contains("cmnd") || lower.contains("định danh")
        || lower.contains("dinh danh");

    // Government sender tags
    let has_gov_sender = lower.contains("[cục cảnh sát") || lower.contains("[cuc canh sat")
        || lower.contains("[ngân hàng nhà nước") || lower.contains("[ngan hang nha nuoc")
        || lower.contains("[cục thuế") || lower.contains("[cuc thue")
        || lower.contains("[bộ tài chính") || lower.contains("[bo tai chinh")
        || lower.contains("[cổng dvc") || lower.contains("[dvc")
        || lower.contains("[vneid") || lower.contains("[bhxh")
        || lower.contains("[mof") || lower.contains("[sbv")
        || lower.contains("[boj") || lower.contains("[bis")
        || lower.contains("[iras") || lower.contains("[cpf")
        || lower.contains("[gov.sg") || lower.contains("[gov.vn")
        || lower.contains("[ ministry") || lower.contains("[ministry");

    // Interest rate / policy announcement (not requesting action)
    let is_policy_announcement = lower.contains("lãi suất")
        || lower.contains("lai suat")
        || lower.contains("interest rate")
        || lower.contains("thông báo")
        || lower.contains("thong bao")
        || lower.contains("nhắc nhở")
        || lower.contains("nhac nho")
        || lower.contains("reminder");

    // Tax filing reminder
    let is_tax_reminder = lower.contains("khai thuế") || lower.contains("khai thue")
        || lower.contains("tax filing") || lower.contains("file your tax")
        || lower.contains("nộp thuế") || lower.contains("nop thue");

    // ID card ready for pickup
    let id_card_pickup = id_card && (lower.contains("sẵn sàng") || lower.contains("san sang")
        || lower.contains("ready") || lower.contains("đến") || lower.contains("den")
        || lower.contains("nhận") || lower.contains("nhan"));

    // Government policy announcement with no action link
    (has_gov_sender && is_policy_announcement)
    || (has_gov_sender && id_card_pickup)
    || (has_gov_sender && is_tax_reminder)
    || (has_gov_sender && !lower.contains("http") && !lower.contains("link"))
}

/// Patterns that indicate a legitimate bank security alert.
pub fn is_bank_security_alert(lower: &str) -> bool {
    // Unusual/suspicious activity detected
    let has_activity_alert = lower.contains("unusual activity")
        || lower.contains("suspicious activity")
        || lower.contains("hoạt động lạ")
        || lower.contains("hoat dong la")
        || lower.contains("giao dịch bất thường")
        || lower.contains("giao dich bat thuong")
        || lower.contains("aktivitas mencurigakan")
        || lower.contains("aktivitas tidak wajar")
        || lower.contains("กิจกรรมผิดปกติ")
        || lower.contains("ธุรกรรมผิดปกติ")
        || lower.contains("aktiviti mencurigakan")
        || lower.contains("aktiviti tidak biasa")
        || lower.contains("kakaibang aktibidad")
        || lower.contains("pinaghihinalaang aktibidad")
        || lower.contains("សកម្មភាពខុសប្រក្រតី");

    // Account verification from known bank
    let has_bank_brand = lower.contains("vpbank") || lower.contains("vietcombank")
        || lower.contains("vcb") || lower.contains("tpbank") || lower.contains("tpb")
        || lower.contains("techcombank") || lower.contains("tcb")
        || lower.contains("vietinbank") || lower.contains("bidv")
        || lower.contains("hdbank") || lower.contains("agribank")
        || lower.contains("acb") || lower.contains("mbbank") || lower.contains("mb bank")
        || lower.contains("sacombank") || lower.contains("eximbank")
        || lower.contains("vib") || lower.contains("ocb")
        || lower.contains("dbs") || lower.contains("posb") || lower.contains("ocbc")
        || lower.contains("uob") || lower.contains("hsbc")
        || lower.contains("maybank") || lower.contains("cimb")
        || lower.contains("bca") || lower.contains("mandiri") || lower.contains("bni")
        || lower.contains("bri") || lower.contains("bdo") || lower.contains("bpi")
        || lower.contains("metrobank") || lower.contains("bangkok bank")
        || lower.contains("kasikorn") || lower.contains("kbank")
        || lower.contains("krungthai") || lower.contains("krungsri")
        || lower.contains("scb") || lower.contains("ttb")
        || lower.contains("public bank") || lower.contains("rhb")
        || lower.contains("ambank") || lower.contains("hong leong")
        || lower.contains("bsn") || lower.contains("bank rakyat")
        || lower.contains("unionbank") || lower.contains("security bank")
        || lower.contains("chinabank") || lower.contains("pnb")
        || lower.contains("rcbc") || lower.contains("psbank")
        || lower.contains("danamon") || lower.contains("permata")
        || lower.contains("bsi") || lower.contains("btn")
        || lower.contains("panin") || lower.contains("btpn")
        || lower.contains("aba bank") || lower.contains("aba]")
        || lower.contains("acleda") || lower.contains("canadia")
        || lower.contains("sathapana") || lower.contains("wing money")
        || lower.contains("gcash") || lower.contains("paymaya") || lower.contains("maya");

    // Security alert patterns
    let has_security_pattern = lower.contains("an toàn") || lower.contains("an toan")
        || lower.contains("secure") || lower.contains("security")
        || lower.contains("bảo mật") || lower.contains("bao mat")
        || lower.contains("xác thực") || lower.contains("xac thuc")
        || lower.contains("verify") || lower.contains("verification")
        || lower.contains("ความปลอดภัย") || lower.contains("ปลอดภัย")
        || lower.contains("keamanan") || lower.contains("verifikasi")
        || lower.contains("keselamatan") || lower.contains("seguridad")
        || lower.contains("seguridad") || lower.contains("verify ang")
        || lower.contains("សុវត្ថិភាព") || lower.contains("ផ្ទៀងផ្ទាត់");

    // Transaction review notification
    let is_transaction_review = lower.contains("đang được xem xét")
        || lower.contains("dang duoc xem xet")
        || lower.contains("being reviewed")
        || lower.contains("under review")
        || lower.contains("đang xem xét")
        || lower.contains("dang xem xet");

    (has_activity_alert && has_bank_brand)
    || (is_transaction_review && has_bank_brand)
    || (has_activity_alert && has_security_pattern)
}

/// Patterns that indicate a legitimate delivery/customs notification from known delivery services.
pub fn is_delivery_notification(lower: &str) -> bool {
    let has_delivery_brand = lower.contains("lalamove") || lower.contains("grab")
        || lower.contains("ghn") || lower.contains("ghtk")
        || lower.contains("ninja van") || lower.contains("ninjavan")
        || lower.contains("jne") || lower.contains("j&t") || lower.contains("jnt")
        || lower.contains("sicepat") || lower.contains("dhl") || lower.contains("fedex")
        || lower.contains("ups") || lower.contains("singpost") || lower.contains("vnpost")
        || lower.contains("thailand post") || lower.contains("pos malaysia")
        || lower.contains("lbc") || lower.contains("winmart")
        || lower.contains("best express") || lower.contains("best-inc")
        || lower.contains("spx express") || lower.contains("spx");

    let has_customs = lower.contains("customs") || lower.contains("hải quan")
        || lower.contains("hai quan");

    let has_delivery = lower.contains("parcel") || lower.contains("package")
        || lower.contains("kiện hàng") || lower.contains("kien hang")
        || lower.contains("đơn hàng") || lower.contains("don hang")
        || lower.contains("paket") || lower.contains("พัสดุ");

    let has_delivery_failure = lower.contains("could not be delivered")
        || lower.contains("giao không thành công")
        || lower.contains("không thành công")
        || lower.contains("delivery failed")
        || lower.contains("giao hàng không thành công")
        || lower.contains("đặt lại lịch")
        || lower.contains("reschedule");

    // Customs fee from known delivery brand
    (has_delivery_brand && has_customs && has_delivery)
    // Package damage notification from known delivery brand
    || (has_delivery_brand && has_delivery && (lower.contains("móp") || lower.contains("mop")
        || lower.contains("damaged") || lower.contains("hư hỏng") || lower.contains("hu hong")))
    // Shipping fee notification from known delivery brand
    || (has_delivery_brand && (lower.contains("vận chuyển") || lower.contains("van chuyen")
        || lower.contains("shipping") || lower.contains("delivery fee")))
    // Delivery failure / reschedule notification from known delivery brand
    || (has_delivery_brand && has_delivery && has_delivery_failure)
}

/// Patterns that indicate a legitimate refund/cashback notification.
pub fn is_refund_notification(lower: &str) -> bool {
    // Refund pending/processed from known brand
    let has_refund = lower.contains("refund") || lower.contains("hoàn tiền")
        || lower.contains("hoan tien") || lower.contains("pengembalian")
        || lower.contains("คืนเงิน") || lower.contains("refund processed")
        || lower.contains("refund pending") || lower.contains("hoàn đang chờ")
        || lower.contains("khoản hoàn tiền");

    let has_brand = has_sender_brand_tag(lower)
        || lower.contains("shopee") || lower.contains("lazada")
        || lower.contains("grab") || lower.contains("tiki")
        || lower.contains("tokopedia") || lower.contains("carousell")
        || lower.contains("qoo10") || lower.contains("sendo");

    // "Refund waiting in your account" / "refund is pending"
    let refund_in_account = lower.contains("refund is waiting")
        || lower.contains("waiting in your account")
        || lower.contains("hoàn tiền đang chờ")
        || lower.contains("khoản hoàn tiền đang chờ")
        || lower.contains("pengembalian dana menunggu")
        || lower.contains("refund is pending")
        || lower.contains("refund has been processed");

    // Cashback reward notification
    let cashback_notification = lower.contains("cashback")
        && (lower.contains("credited") || lower.contains("received")
            || lower.contains("đã nhận") || lower.contains("đã được"));

    (has_refund && has_brand) || refund_in_account || (cashback_notification && has_brand)
}

/// Patterns that indicate a legitimate service expiry/renewal notification.
pub fn is_service_notification(lower: &str) -> bool {
    let has_expiry = lower.contains("expir") || lower.contains("hết hạn")
        || lower.contains("het han") || lower.contains("berakhir")
        || lower.contains("หมดอายุ") || lower.contains("mag-eexpire")
        || lower.contains("will expire") || lower.contains("sắp hết hạn")
        || lower.contains("sap het han");

    let has_renewal = lower.contains("renew") || lower.contains("gia hạn")
        || lower.contains("gia han") || lower.contains("perpanjang")
        || lower.contains("ต่ออายุ") || lower.contains("ipagpatuloy");

    let has_service = lower.contains("subscription") || lower.contains("membership")
        || lower.contains("plan") || lower.contains("package")
        || lower.contains("gói dịch vụ") || lower.contains("goi dich vu")
        || lower.contains("paket") || lower.contains("pakej")
        || lower.contains("แพ็คเกจ");

    let has_brand = has_sender_brand_tag(lower);

    // Service expiry from known brand
    let is_service = (has_expiry || has_renewal) && (has_service || has_brand);

    // Exclude scam patterns: urgent payment demand via link
    let has_urgent_payment = lower.contains("nạp tiền ngay")
        || lower.contains("nap tien ngay")
        || lower.contains("pay now")
        || lower.contains("pay immediately")
        || lower.contains("trả trước trong vòng")
        || lower.contains("tra truoc trong vong");
    let has_link_ref = lower.contains("link sau") || lower.contains("link_ngắn")
        || lower.contains("link ngan") || lower.contains("đường link")
        || lower.contains("duong link") || lower.contains("link below");
    let has_time_pressure = lower.contains("30 phút") || lower.contains("30 phut")
        || lower.contains("within 30") || lower.contains("within 1 hour")
        || lower.contains("trong vòng") || lower.contains("trong vong");

    is_service && !(has_urgent_payment && (has_link_ref || has_time_pressure))
}

/// Patterns that indicate a legitimate job posting from a known company.
pub fn is_legitimate_job_posting(lower: &str) -> bool {
    let has_careers = lower.contains("careers") || lower.contains("hiring")
        || lower.contains("we are hiring") || lower.contains("job details")
        || lower.contains("apply") || lower.contains("application");

    let has_known_employer = lower.contains("uob careers")
        || lower.contains("dbs careers") || lower.contains("ocbc careers")
        || lower.contains("grab careers") || lower.contains("shopee careers")
        || lower.contains("google careers") || lower.contains("microsoft careers")
        || lower.contains("singtel careers") || lower.contains("viettel careers");

    has_careers && has_known_employer
}

/// Check if a message exhibits strong legitimacy signals that should
/// suppress certain indicators or aggressively reduce risk bucket.
///
/// Returns a `LegitimacyContext` with flags for each detected pattern.
#[derive(Debug, Clone, Default)]
pub struct LegitimacyContext {
    /// Message is a security notification (password change, login alert, OTP).
    pub is_security_notification: bool,
    /// Message is a transaction confirmation.
    pub is_transaction_notification: bool,
    /// Message is a refund/cashback notification from a known brand.
    pub is_refund_notification: bool,
    /// Message is a service expiry/renewal notification.
    pub is_service_notification: bool,
    /// Message is a legitimate job posting from a known employer.
    pub is_legitimate_job_posting: bool,
    /// Message is from a legitimate charity organization.
    pub is_legitimate_charity: bool,
    /// Message is a government notification (ID card, policy, tax reminder).
    pub is_government_notification: bool,
    /// Message is a bank security alert (unusual activity, transaction review).
    pub is_bank_security_alert: bool,
    /// Message is a delivery/customs notification from a known delivery brand.
    pub is_delivery_notification: bool,
    /// Message contains a recognized sender brand tag.
    pub has_sender_brand_tag: bool,
    /// Message contains a known brand name (non-bracket format, e.g. "ACB:", "BIDV:").
    pub has_known_brand_name: bool,
    /// All URLs in the message are from allowlisted domains.
    pub all_urls_allowed: bool,
    /// Number of legitimacy signals detected (for scoring).
    pub signal_count: usize,
}

/// Analyze a message for legitimacy signals.
///
/// `has_urls` indicates whether the message contains any URLs.
/// `all_urls_allowed` indicates whether all URLs are from allowlisted domains.
pub fn analyze_legitimacy(
    lower_text: &str,
    has_urls: bool,
    all_urls_allowed: bool,
) -> LegitimacyContext {
    let has_sender_brand_tag = has_sender_brand_tag(lower_text);
    let has_known_brand_name = has_known_brand_name(lower_text);
    let is_security_notification = is_security_notification(lower_text);
    let is_transaction_notification = is_transaction_notification(lower_text)
        && !is_transaction_scam_pattern(lower_text);
    let is_refund_notification = is_refund_notification(lower_text);
    let is_service_notification = is_service_notification(lower_text);
    let is_legitimate_job_posting = is_legitimate_job_posting(lower_text);
    let is_legitimate_charity = is_legitimate_charity(lower_text);
    let is_government_notification = is_government_notification(lower_text);
    let is_bank_security_alert = is_bank_security_alert(lower_text);
    let is_delivery_notification = is_delivery_notification(lower_text);

    let mut signal_count = 0;
    if is_security_notification { signal_count += 1; }
    if is_transaction_notification { signal_count += 1; }
    if is_refund_notification { signal_count += 1; }
    if is_service_notification { signal_count += 1; }
    if is_legitimate_job_posting { signal_count += 1; }
    if is_legitimate_charity { signal_count += 1; }
    if is_government_notification { signal_count += 1; }
    if is_bank_security_alert { signal_count += 1; }
    if is_delivery_notification { signal_count += 1; }
    if has_sender_brand_tag { signal_count += 1; }
    // Note: has_known_brand_name is NOT counted in signal_count because scammers
    // frequently mention brand names (Telegram, Facebook, Instagram) in their
    // messages. It's only used in the targeted brand reduction in compute_risk_bucket.
    if has_urls && all_urls_allowed { signal_count += 1; }

    LegitimacyContext {
        is_security_notification,
        is_transaction_notification,
        is_refund_notification,
        is_service_notification,
        is_legitimate_job_posting,
        is_legitimate_charity,
        is_government_notification,
        is_bank_security_alert,
        is_delivery_notification,
        has_sender_brand_tag,
        has_known_brand_name,
        all_urls_allowed,
        signal_count,
    }
}
