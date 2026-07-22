//! Threat intelligence feed — external scam campaign data ingestion.
//!
//! Allows the detection engine to ingest external threat intelligence
//! about active scam campaigns and use that information to boost
//! indicator detection for matching messages.

use serde::{Deserialize, Serialize};
use crate::ontology::{IndicatorId, IndicatorStrength, IndicatorHit};
use crate::taxonomy::ScamType;
use crate::channel::Channel;

/// Status of a scam campaign.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CampaignStatus {
    /// Campaign is actively targeting users.
    Active,
    /// Campaign is declining in activity.
    Declining,
    /// Campaign has been resolved/disrupted.
    Resolved,
}

impl CampaignStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            CampaignStatus::Active => "active",
            CampaignStatus::Declining => "declining",
            CampaignStatus::Resolved => "resolved",
        }
    }

    pub fn from_str(s: &str) -> Self {
        match s {
            "active" => CampaignStatus::Active,
            "declining" => CampaignStatus::Declining,
            _ => CampaignStatus::Resolved,
        }
    }
}

/// A scam campaign from external threat intelligence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScamCampaign {
    /// Unique campaign identifier.
    pub campaign_id: String,
    /// Scam type associated with this campaign.
    pub scam_type: ScamType,
    /// Indicators typically present in this campaign's messages.
    pub indicators: Vec<IndicatorId>,
    /// Geographic regions targeted (e.g., "SEA", "EU", "LATAM").
    pub regions: Vec<String>,
    /// Channels used by this campaign.
    pub channels: Vec<Channel>,
    /// First seen date (ISO format).
    pub first_seen: String,
    /// Last seen date (ISO format).
    pub last_seen: String,
    /// Severity level (1-5, 5 = most severe).
    pub severity: u8,
    /// Campaign-specific keywords to watch for.
    pub keywords: Vec<String>,
    /// Known malicious URL patterns.
    pub url_patterns: Vec<String>,
    /// Campaign status.
    pub status: CampaignStatus,
    /// Human-readable description.
    pub description: String,
}

/// Threat intelligence feed containing multiple campaigns.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIntelFeed {
    /// Active and historical campaigns.
    pub campaigns: Vec<ScamCampaign>,
    /// Feed source identifier.
    pub source: String,
    /// Last updated timestamp.
    pub last_updated: String,
    /// Feed schema version.
    pub schema_version: String,
}

impl Default for ThreatIntelFeed {
    fn default() -> Self {
        Self::new()
    }
}

impl ThreatIntelFeed {
    /// Create an empty feed.
    pub fn new() -> Self {
        Self {
            campaigns: Vec::new(),
            source: "local".to_string(),
            last_updated: chrono::Utc::now().to_rfc3339(),
            schema_version: "1.0.0".to_string(),
        }
    }

    /// Ingest a JSON feed from an external source.
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    /// Serialize to JSON for storage.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Merge another feed's campaigns into this one.
    /// Deduplicates by campaign_id, keeping the most recent version.
    pub fn merge(&mut self, other: &ThreatIntelFeed) {
        for campaign in &other.campaigns {
            if let Some(existing) = self.campaigns.iter_mut().find(|c| c.campaign_id == campaign.campaign_id) {
                // Replace if the other feed has a more recent last_seen
                if campaign.last_seen > existing.last_seen {
                    *existing = campaign.clone();
                }
            } else {
                self.campaigns.push(campaign.clone());
            }
        }
        if other.last_updated > self.last_updated {
            self.last_updated = other.last_updated.clone();
        }
    }

    /// Get only active campaigns.
    pub fn active_campaigns(&self) -> Vec<&ScamCampaign> {
        self.campaigns
            .iter()
            .filter(|c| c.status == CampaignStatus::Active)
            .collect()
    }

    /// Match a message against known campaign patterns.
    ///
    /// Returns matching campaigns that are active and whose keywords or
    /// URL patterns appear in the text.
    pub fn match_campaigns(&self, text: &str, channel: Channel) -> Vec<&ScamCampaign> {
        let text_lower = text.to_lowercase();
        self.active_campaigns()
            .into_iter()
            .filter(|c| {
                // Channel match (if campaign specifies channels)
                let channel_match = c.channels.is_empty()
                    || c.channels.iter().any(|ch| ch.as_str() == channel.as_str());
                if !channel_match {
                    return false;
                }

                // Keyword match
                let keyword_match = c.keywords.iter().any(|k| {
                    text_lower.contains(&k.to_lowercase())
                });

                // URL pattern match
                let url_match = c.url_patterns.iter().any(|p| {
                    text_lower.contains(&p.to_lowercase())
                });

                keyword_match || url_match
            })
            .collect()
    }

    /// Boost indicator hits based on matching campaigns.
    ///
    /// For each indicator that is part of a matching campaign, boost its
    /// strength to at least Medium. If the indicator is not already present,
    /// add it with Medium strength.
    pub fn boost_indicators(
        &self,
        indicators: &mut Vec<IndicatorHit>,
        matching_campaigns: &[&ScamCampaign],
    ) {
        for campaign in matching_campaigns {
            for &ind_id in &campaign.indicators {
                if let Some(existing) = indicators.iter_mut().find(|h| h.id == ind_id) {
                    // Boost to at least Medium
                    if existing.strength.weight() < IndicatorStrength::Medium.weight() {
                        existing.strength = IndicatorStrength::Medium;
                    }
                    existing.match_count += 1;
                } else {
                    // Add new indicator with Medium strength
                    indicators.push(IndicatorHit {
                        id: ind_id,
                        strength: IndicatorStrength::Medium,
                        match_count: 1,
                    });
                }
            }
        }
    }

    /// Add a campaign to the feed.
    pub fn add_campaign(&mut self, campaign: ScamCampaign) {
        self.campaigns.push(campaign);
        self.last_updated = chrono::Utc::now().to_rfc3339();
    }

    /// Number of campaigns in the feed.
    pub fn len(&self) -> usize {
        self.campaigns.len()
    }

    /// Whether the feed is empty.
    pub fn is_empty(&self) -> bool {
        self.campaigns.is_empty()
    }
}

/// Result of a threat intelligence check on a message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIntelReport {
    /// Matching campaign IDs.
    pub matching_campaign_ids: Vec<String>,
    /// Matching campaign descriptions.
    pub matching_descriptions: Vec<String>,
    /// Scam types from matching campaigns.
    pub suggested_scam_types: Vec<ScamType>,
    /// Number of indicators boosted by threat intel.
    pub indicators_boosted: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_campaign() -> ScamCampaign {
        ScamCampaign {
            campaign_id: "vn_bank_2024_01".to_string(),
            scam_type: ScamType::BankImpersonation,
            indicators: vec![IndicatorId::Urgency, IndicatorId::CredentialRequest],
            regions: vec!["SEA".to_string()],
            channels: vec![Channel::Sms],
            first_seen: "2024-01-01".to_string(),
            last_seen: "2024-06-01".to_string(),
            severity: 4,
            keywords: vec!["Vietcombank".to_string(), "tai khoan".to_string()],
            url_patterns: vec!["vcb-verify.com".to_string()],
            status: CampaignStatus::Active,
            description: "Vietcombank impersonation campaign targeting Vietnamese users".to_string(),
        }
    }

    #[test]
    fn test_feed_merge() {
        let mut feed1 = ThreatIntelFeed::new();
        feed1.add_campaign(make_campaign());

        let mut feed2 = ThreatIntelFeed::new();
        feed2.source = "external".to_string();
        feed2.add_campaign(ScamCampaign {
            campaign_id: "th_delivery_2024_02".to_string(),
            scam_type: ScamType::DeliveryScam,
            indicators: vec![IndicatorId::DeliveryLure, IndicatorId::LinkSuspicious],
            regions: vec!["SEA".to_string()],
            channels: vec![Channel::Sms],
            first_seen: "2024-03-01".to_string(),
            last_seen: "2024-06-15".to_string(),
            severity: 3,
            keywords: vec!["package".to_string(), "delivery".to_string()],
            url_patterns: vec!["th-post.co".to_string()],
            status: CampaignStatus::Active,
            description: "Thailand delivery scam campaign".to_string(),
        });

        feed1.merge(&feed2);
        assert_eq!(feed1.len(), 2);
    }

    #[test]
    fn test_match_campaign() {
        let mut feed = ThreatIntelFeed::new();
        feed.add_campaign(make_campaign());

        let matches = feed.match_campaigns(
            "Tai khoan Vietcombank cua ban bi khoa. Kiem tra tai vcb-verify.com",
            Channel::Sms,
        );
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].campaign_id, "vn_bank_2024_01");
    }

    #[test]
    fn test_no_match() {
        let mut feed = ThreatIntelFeed::new();
        feed.add_campaign(make_campaign());

        let matches = feed.match_campaigns("Hello, how are you today?", Channel::Sms);
        assert!(matches.is_empty());
    }

    #[test]
    fn test_boost_indicators() {
        let mut feed = ThreatIntelFeed::new();
        feed.add_campaign(make_campaign());

        let matches = feed.match_campaigns(
            "Tai khoan Vietcombank cua ban bi khoa",
            Channel::Sms,
        );

        let mut indicators = vec![IndicatorHit {
            id: IndicatorId::Urgency,
            strength: IndicatorStrength::Low,
            match_count: 1,
        }];

        feed.boost_indicators(&mut indicators, &matches);

        // Urgency should be boosted to Medium
        assert_eq!(indicators[0].strength, IndicatorStrength::Medium);
        // CredentialRequest should be added
        assert!(indicators.iter().any(|h| h.id == IndicatorId::CredentialRequest));
    }

    #[test]
    fn test_serialization() {
        let mut feed = ThreatIntelFeed::new();
        feed.add_campaign(make_campaign());

        let json = feed.to_json().unwrap();
        let parsed = ThreatIntelFeed::from_json(&json).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed.campaigns[0].campaign_id, "vn_bank_2024_01");
    }

    #[test]
    fn test_active_campaigns_filter() {
        let mut feed = ThreatIntelFeed::new();
        feed.add_campaign(make_campaign());
        feed.add_campaign(ScamCampaign {
            campaign_id: "old_campaign".to_string(),
            scam_type: ScamType::LotteryPrize,
            indicators: vec![IndicatorId::PrizeLure],
            regions: vec!["EU".to_string()],
            channels: vec![Channel::Email],
            first_seen: "2023-01-01".to_string(),
            last_seen: "2023-06-01".to_string(),
            severity: 2,
            keywords: vec!["lottery".to_string()],
            url_patterns: vec![],
            status: CampaignStatus::Resolved,
            description: "Old lottery scam".to_string(),
        });

        assert_eq!(feed.len(), 2);
        assert_eq!(feed.active_campaigns().len(), 1);
    }
}
