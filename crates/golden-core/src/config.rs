//! Protocol configuration validation.

use crate::ParticipantId;
use alloc::collections::BTreeSet;

extern crate alloc;

/// Golden DKG participant and threshold configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtocolConfig {
    threshold: usize,
    participants: Vec<ParticipantId>,
}

impl ProtocolConfig {
    /// Validate and construct a protocol configuration.
    pub fn new(threshold: usize, participants: Vec<ParticipantId>) -> Result<Self, ConfigError> {
        if participants.is_empty() {
            return Err(ConfigError::EmptyParticipants);
        }

        if threshold == 0 || threshold > participants.len() {
            return Err(ConfigError::InvalidThreshold);
        }

        let mut seen = BTreeSet::new();
        for participant in &participants {
            if !seen.insert(*participant) {
                return Err(ConfigError::DuplicateParticipant);
            }
        }

        Ok(Self {
            threshold,
            participants,
        })
    }

    /// Threshold required to reconstruct or sign.
    #[must_use]
    pub const fn threshold(&self) -> usize {
        self.threshold
    }

    /// Ordered participant identifiers.
    #[must_use]
    pub fn participants(&self) -> &[ParticipantId] {
        &self.participants
    }

    /// Return true if the participant belongs to this DKG.
    #[must_use]
    pub fn contains_participant(&self, participant: ParticipantId) -> bool {
        self.participants.contains(&participant)
    }
}

/// Protocol configuration failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigError {
    /// No participants were configured.
    EmptyParticipants,
    /// Threshold must satisfy `1 <= threshold <= participants.len()`.
    InvalidThreshold,
    /// A participant identifier appears more than once.
    DuplicateParticipant,
}

#[cfg(test)]
mod tests {
    use super::{ConfigError, ProtocolConfig};
    use crate::ParticipantId;

    fn id(value: u64) -> ParticipantId {
        ParticipantId::new(value).expect("non-zero id")
    }

    #[test]
    fn validates_threshold_bounds() {
        assert_eq!(
            ProtocolConfig::new(0, vec![id(1), id(2)]),
            Err(ConfigError::InvalidThreshold)
        );
        assert_eq!(
            ProtocolConfig::new(3, vec![id(1), id(2)]),
            Err(ConfigError::InvalidThreshold)
        );
    }

    #[test]
    fn rejects_duplicate_participants() {
        assert_eq!(
            ProtocolConfig::new(1, vec![id(1), id(1)]),
            Err(ConfigError::DuplicateParticipant)
        );
    }

    #[test]
    fn accepts_valid_config() {
        let config = ProtocolConfig::new(2, vec![id(1), id(2), id(3)]).expect("valid");

        assert_eq!(config.threshold(), 2);
        assert!(config.contains_participant(id(2)));
        assert!(!config.contains_participant(id(9)));
    }
}
