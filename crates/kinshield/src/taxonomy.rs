//! Scam type taxonomy — 30 families with Southeast Asia focus.
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
    /// Sextortion — threats to release sensitive photos/videos.
    Sextortion,
    /// Recovery scam — targets previous scam victims with false recovery offers.
    RecoveryScam,
    /// Account takeover phishing — reactivation/security update for non-bank accounts.
    AccountTakeover,
    /// Toll/traffic fine scam — unpaid toll, ERP, traffic summons phishing.
    TollFine,
    /// Pig butchering — romance grooming + investment fraud hybrid (杀猪盘).
    PigButchering,
    /// Money mule recruitment — "earn money by receiving and forwarding payments."
    MoneyMule,
    /// Fake customer service / refund scam — impersonating e-commerce CS.
    CustomerServiceScam,
    /// Property rental scam — fake property listings asking for deposits.
    PropertyRental,
    /// Utility impersonation — fake electricity/water company threatening disconnection.
    UtilityImpersonation,
    /// Business email compromise — fake boss/colleague asking to transfer funds.
    BusinessEmailCompromise,
    /// Inheritance scam — fake estate/inheritance from a distant relative.
    InheritanceScam,
    /// SIM swap / port-out fraud — hijacking phone numbers to intercept OTPs.
    SimSwapFraud,
    /// Fake QR code / quishing — malicious QR codes for parking, payments.
    FakeQRCode,
    /// Subscription trap — hidden recurring charges from "free trials."
    SubscriptionTrap,
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
            ScamType::Sextortion => "sextortion",
            ScamType::RecoveryScam => "recovery_scam",
            ScamType::AccountTakeover => "account_takeover",
            ScamType::TollFine => "toll_fine",
            ScamType::PigButchering => "pig_butchering",
            ScamType::MoneyMule => "money_mule",
            ScamType::CustomerServiceScam => "customer_service_scam",
            ScamType::PropertyRental => "property_rental",
            ScamType::UtilityImpersonation => "utility_impersonation",
            ScamType::BusinessEmailCompromise => "business_email_compromise",
            ScamType::InheritanceScam => "inheritance_scam",
            ScamType::SimSwapFraud => "sim_swap_fraud",
            ScamType::FakeQRCode => "fake_qr_code",
            ScamType::SubscriptionTrap => "subscription_trap",
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
            ScamType::Sextortion => "Sextortion",
            ScamType::RecoveryScam => "Recovery Scam",
            ScamType::AccountTakeover => "Account Takeover / Phishing",
            ScamType::TollFine => "Toll / Traffic Fine Scam",
            ScamType::PigButchering => "Pig Butchering Scam",
            ScamType::MoneyMule => "Money Mule Recruitment",
            ScamType::CustomerServiceScam => "Customer Service / Refund Scam",
            ScamType::PropertyRental => "Property Rental Scam",
            ScamType::UtilityImpersonation => "Utility Impersonation",
            ScamType::BusinessEmailCompromise => "Business Email Compromise",
            ScamType::InheritanceScam => "Inheritance Scam",
            ScamType::SimSwapFraud => "SIM Swap Fraud",
            ScamType::FakeQRCode => "Fake QR Code / Quishing",
            ScamType::SubscriptionTrap => "Subscription Trap",
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
            ScamType::Sextortion,
            ScamType::RecoveryScam,
            ScamType::AccountTakeover,
            ScamType::TollFine,
            ScamType::PigButchering,
            ScamType::MoneyMule,
            ScamType::CustomerServiceScam,
            ScamType::PropertyRental,
            ScamType::UtilityImpersonation,
            ScamType::BusinessEmailCompromise,
            ScamType::InheritanceScam,
            ScamType::SimSwapFraud,
            ScamType::FakeQRCode,
            ScamType::SubscriptionTrap,
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
            ScamType::Sextortion => "We have recorded you through your device camera. We have sensitive video footage of you. Pay to prevent us from sharing these videos with your contacts.",
            ScamType::RecoveryScam => "We are a funds recovery service. We can help you get back the money you lost to a scam. Our recovery team has already traced your stolen funds. Pay a small fee to initiate the recovery process.",
            ScamType::AccountTakeover => "Your account has been deactivated for security reasons. Reactivate now to avoid loss of access. Click here to verify your identity and restore your account.",
            ScamType::TollFine => "You have an unpaid toll fine on the expressway. Settle the outstanding amount immediately to avoid additional penalties or legal action. Click here to pay now.",
            ScamType::PigButchering => "Hi, I got your number by mistake but you seem nice. I'm a crypto trader making 20% monthly returns. Let me show you how to invest — my platform is very safe and profitable. We can make money together while we get to know each other.",
            ScamType::MoneyMule => "Work from home opportunity! We need agents to receive payments into their bank accounts and forward them to our partners. Earn 10% commission on each transfer. No experience needed, just a bank account.",
            ScamType::CustomerServiceScam => "Hello, this is Shopee customer service. There is an issue with your recent order and we need to process a refund. Please provide your bank details or click this link to verify your account and receive your refund.",
            ScamType::PropertyRental => "Beautiful 2-bedroom condo for rent in prime location at below market price. Move in immediately. Pay one month deposit to secure the unit. Limited availability, first come first served. Transfer deposit to reserve.",
            ScamType::UtilityImpersonation => "This is the electricity company. Your power will be disconnected in 2 hours due to unpaid bills. Pay immediately to avoid disconnection. Click here to settle your outstanding balance now.",
            ScamType::BusinessEmailCompromise => "Hi, I'm in a meeting and can't talk. I need you to urgently process a payment of $15,000 to this supplier account. This is confidential and time-sensitive. Please confirm once the transfer is done. Thanks, CEO.",
            ScamType::InheritanceScam => "I am a lawyer representing the estate of your late relative who passed away leaving $5 million. As the next of kin, you are entitled to this inheritance. Pay the legal fees and transfer charges to claim your funds.",
            ScamType::SimSwapFraud => "Your SIM card will be deactivated tonight due to a system upgrade. To maintain service, reply with your IC number and a one-time PIN to verify your identity. Your number will be transferred to a new SIM if not verified.",
            ScamType::FakeQRCode => "Scan this QR code to pay for parking. Official parking payment system. Scan and enter your card details to complete payment. Quick and convenient contactless payment.",
            ScamType::SubscriptionTrap => "You've activated your free 7-day trial of our premium service. After the trial, you'll be charged $49.99/month automatically. To cancel, call our cancellation hotline (premium rate number).",
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
pub const SCAM_TAXONOMY_VERSION: &str = "1.1.0";
