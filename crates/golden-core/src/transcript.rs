//! Dealer transcript types and validation.

use crate::FieldElement;
use core::num::NonZeroU16;

/// Highest participant index accepted by the FROST APIs used by `RedPallas`.
pub const MAX_FROST_PARTICIPANT_ID: u64 = 65_535;

/// A non-zero participant identifier compatible with FROST identifier indexes.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ParticipantId(NonZeroU16);

impl ParticipantId {
    /// Construct a participant identifier.
    #[must_use]
    pub fn new(value: u64) -> Option<Self> {
        Self::try_from(value).ok()
    }

    /// Return the integer representation used for Shamir evaluation points.
    #[must_use]
    pub fn get(self) -> u64 {
        u64::from(self.0.get())
    }

    /// Return the FROST-compatible identifier index.
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        self.0.get()
    }
}

impl TryFrom<u16> for ParticipantId {
    type Error = ParticipantIdError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        NonZeroU16::new(value)
            .map(Self)
            .ok_or(ParticipantIdError::Zero)
    }
}

impl TryFrom<u64> for ParticipantId {
    type Error = ParticipantIdError;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        if value == 0 {
            return Err(ParticipantIdError::Zero);
        }

        let value = u16::try_from(value).map_err(|_| ParticipantIdError::OutOfRange)?;
        Self::try_from(value)
    }
}

impl From<ParticipantId> for u16 {
    fn from(value: ParticipantId) -> Self {
        value.as_u16()
    }
}

/// Participant identifier construction failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParticipantIdError {
    /// FROST identifiers are non-zero.
    Zero,
    /// FROST identifier indexes are represented as `u16` values.
    OutOfRange,
}

#[cfg(test)]
mod participant_id_tests {
    use super::{ParticipantId, ParticipantIdError};

    #[test]
    fn rejects_zero_and_values_outside_frost_identifier_range() {
        assert_eq!(ParticipantId::new(0), None);
        assert_eq!(ParticipantId::new(u64::from(u16::MAX) + 1), None);
    }

    #[test]
    fn exposes_frost_identifier_index_without_ambiguity() {
        let participant = ParticipantId::new(u64::from(u16::MAX)).expect("max FROST id");

        assert_eq!(participant.get(), u64::from(u16::MAX));
        assert_eq!(participant.as_u16(), u16::MAX);
        assert_eq!(u16::from(participant), u16::MAX);
        assert_eq!(ParticipantId::try_from(u16::MAX), Ok(participant));
        assert_eq!(
            ParticipantId::try_from(0_u16),
            Err(ParticipantIdError::Zero)
        );
        assert_eq!(
            ParticipantId::try_from(u64::from(u16::MAX) + 1),
            Err(ParticipantIdError::OutOfRange)
        );
    }
}

/// Public commitments to a dealer polynomial.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicPolynomial<C> {
    /// Commitments to coefficients of the dealer polynomial.
    pub coefficient_commitments: Vec<C>,
}

/// A masked share for one participant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MaskedShare<F, C> {
    /// Participant receiving this masked share.
    pub participant: ParticipantId,
    /// Published value `s_ji + m_ij`.
    pub value: F,
    /// Commitment to the mask.
    pub mask_commitment: C,
}

/// Proof verification state for a dealer transcript.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProofStatus {
    /// The proof has not been checked.
    Unverified,
    /// The proof was verified by an external proof system.
    Verified,
    /// The proof was checked and rejected.
    Rejected,
}

/// One dealer's Golden contribution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Transcript<F, C> {
    /// Dealer identifier.
    pub dealer: ParticipantId,
    /// Public polynomial commitments.
    pub public_polynomial: PublicPolynomial<C>,
    /// Masked shares indexed by participant.
    pub masked_shares: Vec<MaskedShare<F, C>>,
    /// External proof status.
    pub proof_status: ProofStatus,
}

/// A transcript that passed proof and commitment-equation checks.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedTranscript<F, C>(Transcript<F, C>);

impl<F, C> VerifiedTranscript<F, C> {
    /// Borrow the underlying transcript.
    #[must_use]
    pub const fn as_ref(&self) -> &Transcript<F, C> {
        &self.0
    }

    /// Consume the wrapper and return the underlying transcript.
    #[must_use]
    pub fn into_inner(self) -> Transcript<F, C> {
        self.0
    }
}

/// Transcript verification failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerificationError {
    /// The zero-knowledge proof has not been accepted.
    ProofNotVerified,
    /// A transcript contains duplicate masked shares for a participant.
    DuplicateParticipant,
    /// The target participant was not included in the transcript.
    MissingParticipant,
    /// The public commitment equation failed.
    CommitmentEquationFailed,
}

/// Validate transcript metadata and a caller-provided commitment equation.
pub fn validate_transcript<F, C>(
    transcript: &Transcript<F, C>,
    target: ParticipantId,
    commitment_equation: impl Fn(&MaskedShare<F, C>, &PublicPolynomial<C>) -> bool,
) -> Result<(), VerificationError>
where
    F: FieldElement,
{
    if transcript.proof_status != ProofStatus::Verified {
        return Err(VerificationError::ProofNotVerified);
    }

    let mut found_target = false;
    for (index, share) in transcript.masked_shares.iter().enumerate() {
        if transcript.masked_shares[index + 1..]
            .iter()
            .any(|other| other.participant == share.participant)
        {
            return Err(VerificationError::DuplicateParticipant);
        }

        if share.participant == target {
            found_target = true;
            if !commitment_equation(share, &transcript.public_polynomial) {
                return Err(VerificationError::CommitmentEquationFailed);
            }
        }
    }

    if !found_target {
        return Err(VerificationError::MissingParticipant);
    }

    Ok(())
}

/// Verify a transcript and return a type that can be safely aggregated.
pub fn verify_transcript<F, C>(
    transcript: Transcript<F, C>,
    target: ParticipantId,
    commitment_equation: impl Fn(&MaskedShare<F, C>, &PublicPolynomial<C>) -> bool,
) -> Result<VerifiedTranscript<F, C>, VerificationError>
where
    F: FieldElement,
{
    validate_transcript(&transcript, target, commitment_equation)?;
    Ok(VerifiedTranscript(transcript))
}
