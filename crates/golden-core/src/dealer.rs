//! Dealer-side transcript construction and participant share recovery.

use crate::{
    FieldElement, MaskedShare, ParticipantId, Polynomial, ProofStatus, PublicPolynomial, Transcript,
};

/// Dealer configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DealerConfig<C> {
    /// Dealer identifier.
    pub dealer: ParticipantId,
    /// Participants receiving masked shares.
    pub participants: Vec<ParticipantId>,
    /// Public polynomial commitments for the dealer polynomial.
    pub public_polynomial: PublicPolynomial<C>,
}

/// Dealer secret polynomial.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DealerSecret<F> {
    /// Shamir polynomial.
    pub polynomial: Polynomial<F>,
}

/// Dealer transcript construction failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DealerError {
    /// No participants were configured.
    EmptyParticipants,
}

/// Build a dealer transcript from a polynomial and externally supplied masks.
pub fn build_transcript<F, C>(
    config: DealerConfig<C>,
    secret: &DealerSecret<F>,
    mask_for: impl Fn(ParticipantId) -> (F, C),
) -> Result<Transcript<F, C>, DealerError>
where
    F: FieldElement,
{
    if config.participants.is_empty() {
        return Err(DealerError::EmptyParticipants);
    }

    let masked_shares = config
        .participants
        .iter()
        .copied()
        .map(|participant| {
            let x = F::from_u64(participant.get());
            let share = secret.polynomial.evaluate(x);
            let (mask, mask_commitment) = mask_for(participant);
            MaskedShare {
                participant,
                value: share + mask,
                mask_commitment,
            }
        })
        .collect();

    Ok(Transcript {
        dealer: config.dealer,
        public_polynomial: config.public_polynomial,
        masked_shares,
        proof_status: ProofStatus::Unverified,
    })
}

/// Recover an unmasked share from a masked transcript value and local eVRF mask.
pub fn recover_share<F: FieldElement>(masked_share: F, mask: F) -> F {
    masked_share - mask
}

#[cfg(test)]
mod tests {
    use super::{DealerConfig, DealerSecret, build_transcript, recover_share};
    use crate::{
        FieldElement, ProofStatus, PublicPolynomial, VerificationError,
        field::test_field::Fp,
        polynomial::{Polynomial, interpolate_at_zero},
        transcript::ParticipantId,
        validate_transcript,
    };

    #[test]
    fn creates_and_recovers_masked_shares() {
        let participants = [1, 2, 3]
            .into_iter()
            .map(|id| ParticipantId::new(id).expect("non-zero id"))
            .collect::<Vec<_>>();
        let dealer = ParticipantId::new(9).expect("non-zero id");
        let secret = DealerSecret {
            polynomial: Polynomial::new(vec![Fp(42), Fp(8), Fp(11)]),
        };
        let config = DealerConfig {
            dealer,
            participants: participants.clone(),
            public_polynomial: PublicPolynomial {
                coefficient_commitments: vec![1_u8, 2, 3],
            },
        };

        let mut transcript = build_transcript(config, &secret, |participant| {
            (Fp(participant.get() + 10), 7_u8)
        })
        .expect("transcript");
        transcript.proof_status = ProofStatus::Verified;

        assert_eq!(
            validate_transcript(&transcript, participants[0], |_share, _public| true),
            Ok(())
        );

        let samples = transcript
            .masked_shares
            .iter()
            .map(|masked| {
                let mask = Fp(masked.participant.get() + 10);
                (
                    Fp::from_u64(masked.participant.get()),
                    recover_share(masked.value, mask),
                )
            })
            .collect::<Vec<_>>();

        assert_eq!(interpolate_at_zero(&samples), Ok(Fp(42)));
    }

    #[test]
    fn rejects_unverified_proof() {
        let participant = ParticipantId::new(1).expect("non-zero id");
        let dealer = ParticipantId::new(2).expect("non-zero id");
        let secret = DealerSecret {
            polynomial: Polynomial::new(vec![Fp(1), Fp(2)]),
        };
        let config = DealerConfig {
            dealer,
            participants: vec![participant],
            public_polynomial: PublicPolynomial {
                coefficient_commitments: vec![1_u8],
            },
        };
        let transcript = build_transcript(config, &secret, |_| (Fp(3), 4_u8)).expect("transcript");

        assert_eq!(
            validate_transcript(&transcript, participant, |_share, _public| true),
            Err(VerificationError::ProofNotVerified)
        );
    }
}
