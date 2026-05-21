//! Dealer transcript types and validation.

use crate::FieldElement;

/// A non-zero participant identifier.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ParticipantId(u64);

impl ParticipantId {
    /// Construct a participant identifier.
    #[must_use]
    pub fn new(value: u64) -> Option<Self> {
        (value != 0).then_some(Self(value))
    }

    /// Return the integer representation.
    #[must_use]
    pub fn get(self) -> u64 {
        self.0
    }
}

/// A public polynomial commitment placeholder.
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

/// Verify transcript metadata and a caller-provided commitment equation.
pub fn verify_transcript<F, C>(
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
