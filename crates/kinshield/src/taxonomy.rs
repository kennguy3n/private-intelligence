//! Scam type taxonomy — 15 families with Southeast Asia focus.
//!
//! Fixed, versioned enum. SEA-specific scam families are first-class.
//! Used for classification output and confusion matrix construction.

use serde::{Deserialize, Serialize};

/// Scam type families in the KinShield taxonomy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ScamType {
    /// Fake bank SMS/calls asking to verify or transfer.
    BankImpersonation,
    /// Fake police, tax, immigration officials.
    GovernmentImpersonation,
    /// Crypto, forex, "guaranteed return" schemes.
    InvestmentFraud,
    /// Fake package delivery SMS with malicious links.
    DeliveryScam,
    /// Online dating grooming leading to financial requests.
    RomanceScam,
    /// Fake job offers, "easy money" task scams.
    JobScam,
    /// "You've won" notifications asking for fees.
    LotteryPrize,
    /// Fake tech support calls, remote access requests.
    TechSupport,
    /// Fake disaster/charity appeals.
    CharityScam,
    /// "Grandchild in trouble" — send money urgently.
    FamilyEmergency,
    /// Fake seller, non-delivery, phished marketplace accounts.
    ECommerceFraud,
    /// Fake telco (Viettel, AIS, Telkomsel) offers/threats.
    TelcoImpersonation,
    /// Phished social accounts used to scam contacts.
    SocialMediaTakeover,
    /// Illegal lending, "easy approval" loan offers.
    LoanScam,
    /// Fake customs fee for international package.
    ParcelCustoms,
    /// Scam detected but does not match any known family.
    OtherUnknown,
}

impl ScamType {
    /// Stable string identifier (for decision trace serialization).
    pub fn as_str(&self) -> &'static str {
        match self {
            ScamType::BankImpersonation => "bank_impersonation",
            ScamType::GovernmentImpersonation => "government_impersonation",
            ScamType::InvestmentFraud => "investment_fraud",
            ScamType::DeliveryScam => "delivery_scam",
            ScamType::RomanceScam => "romance_scam",
            ScamType::JobScam => "job_scam",
            ScamType::LotteryPrize => "lottery_prize",
            ScamType::TechSupport => "tech_support",
            ScamType::CharityScam => "charity_scam",
            ScamType::FamilyEmergency => "family_emergency",
            ScamType::ECommerceFraud => "e_commerce_fraud",
            ScamType::TelcoImpersonation => "telco_impersonation",
            ScamType::SocialMediaTakeover => "social_media_takeover",
            ScamType::LoanScam => "loan_scam",
            ScamType::ParcelCustoms => "parcel_customs",
            ScamType::OtherUnknown => "other_unknown",
        }
    }

    /// Human-readable label.
    pub fn label(&self) -> &'static str {
        match self {
            ScamType::BankImpersonation => "Bank Impersonation",
            ScamType::GovernmentImpersonation => "Government Impersonation",
            ScamType::InvestmentFraud => "Investment Fraud",
            ScamType::DeliveryScam => "Delivery Scam",
            ScamType::RomanceScam => "Romance Scam",
            ScamType::JobScam => "Job Scam",
            ScamType::LotteryPrize => "Lottery/Prize Scam",
            ScamType::TechSupport => "Tech Support Scam",
            ScamType::CharityScam => "Charity Scam",
            ScamType::FamilyEmergency => "Family Emergency Scam",
            ScamType::ECommerceFraud => "E-Commerce Fraud",
            ScamType::TelcoImpersonation => "Telco Impersonation",
            ScamType::SocialMediaTakeover => "Social Media Takeover",
            ScamType::LoanScam => "Loan Scam",
            ScamType::ParcelCustoms => "Parcel/Customs Scam",
            ScamType::OtherUnknown => "Other / Unknown Scam",
        }
    }

    /// All scam types as a slice.
    pub fn all() -> &'static [ScamType] {
        &[
            ScamType::BankImpersonation,
            ScamType::GovernmentImpersonation,
            ScamType::InvestmentFraud,
            ScamType::DeliveryScam,
            ScamType::RomanceScam,
            ScamType::JobScam,
            ScamType::LotteryPrize,
            ScamType::TechSupport,
            ScamType::CharityScam,
            ScamType::FamilyEmergency,
            ScamType::ECommerceFraud,
            ScamType::TelcoImpersonation,
            ScamType::SocialMediaTakeover,
            ScamType::LoanScam,
            ScamType::ParcelCustoms,
            ScamType::OtherUnknown,
        ]
    }

    /// Parse from string identifier.
    pub fn from_str(s: &str) -> Option<Self> {
        Self::all().iter().find(|t| t.as_str() == s).copied()
    }

    /// Prototype text for embedding-based k-NN classification.
    /// Each prototype is a representative example message for that scam type.
    pub fn prototype(&self) -> &'static str {
        match self {
            ScamType::BankImpersonation => "Dear customer, your bank account has been suspended. Please verify your identity immediately by clicking this link or calling this number to restore access.",
            ScamType::GovernmentImpersonation => "This is the police/tax authority. You have an outstanding warrant or unpaid tax penalty. Pay now to avoid arrest or legal action.",
            ScamType::InvestmentFraud => "Guaranteed high returns with zero risk! Join our crypto/forex investment group. Professional traders will manage your funds. Minimum investment only $100, withdraw anytime.",
            ScamType::DeliveryScam => "Your package could not be delivered. Click here to reschedule delivery or update your address. Small redelivery fee may apply.",
            ScamType::RomanceScam => "I've fallen in love with you after just a few days of chatting. I want to visit you but I need money for flights/visa. Can you send money via transfer?",
            ScamType::JobScam => "Easy work from home job! Earn $500/day by completing simple tasks. No experience needed. Pay processing fee to start. Limited positions available.",
            ScamType::LotteryPrize => "Congratulations! You've won $50,000 in our international lottery. Pay the processing/transfer fee to claim your prize. Respond within 24 hours.",
            ScamType::TechSupport => "This is Microsoft/Apple support. We detected a virus on your computer. Install this remote access tool so we can fix it. Do not turn off your computer.",
            ScamType::CharityScam => "Urgent appeal: victims of the recent disaster need your help. Donate now to provide food and shelter. 100% goes to the victims.",
            ScamType::FamilyEmergency => "Mom/Dad, I'm in the hospital/jail. I need money urgently for medical bills/bail. Please send money to this account. Don't tell anyone.",
            ScamType::ECommerceFraud => "Great deal on this item! Click to buy now. Pay via bank transfer or gift cards for faster shipping. Seller has limited stock.",
            ScamType::TelcoImpersonation => "Dear customer, your phone number will be deactivated in 2 hours. Click this link to update your information or call this number to prevent disconnection.",
            ScamType::SocialMediaTakeover => "Hey, is this you in this photo? Click to see. Also I'm selling gift cards at a discount, want to buy some?",
            ScamType::LoanScam => "Easy loan approval! No credit check needed. Get $5,000 instantly. Just pay the processing fee upfront. Low interest, flexible repayment.",
            ScamType::ParcelCustoms => "Your international package is held at customs. Pay the customs duty fee to release your package. Click here to pay and arrange delivery.",
            ScamType::OtherUnknown => "This message contains suspicious indicators but does not match any known scam pattern. Please review carefully and report if you believe it is a scam.",
        }
    }
}

impl std::fmt::Display for ScamType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Taxonomy schema version identifier.
pub const SCAM_TAXONOMY_VERSION: &str = "1.0.0";
