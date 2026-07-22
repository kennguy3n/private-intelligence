//! Detection channel abstraction.
//!
//! Represents the input source of a message being scanned for scam risk.
//! No platform integration code — the channel is an input enum. Platform
//! adapters (Android SMS listener, browser extension, call transcription)
//! are documented interfaces, not implemented here.

use serde::{Deserialize, Serialize};

/// The channel through which a potentially scam message was received.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Channel {
    /// SMS text message.
    Sms,
    /// Email message.
    Email,
    /// Web browser — URL or page text snippet.
    Browser,
    /// OTA messenger (Zalo, WhatsApp, Telegram, LINE, etc.).
    Messaging,
    /// Voice call — transcribed text if available.
    Call,
}

impl Channel {
    /// Coarse channel bucket string for decision trace (no raw metadata).
    pub fn as_str(&self) -> &'static str {
        match self {
            Channel::Sms => "sms",
            Channel::Email => "email",
            Channel::Browser => "browser",
            Channel::Messaging => "messaging",
            Channel::Call => "call",
        }
    }

    /// All channels as a slice.
    pub fn all() -> &'static [Channel] {
        &[
            Channel::Sms,
            Channel::Email,
            Channel::Browser,
            Channel::Messaging,
            Channel::Call,
        ]
    }
}

impl std::fmt::Display for Channel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}
