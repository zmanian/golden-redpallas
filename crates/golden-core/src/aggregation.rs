//! Share and public-key aggregation for verified dealer transcripts.

use crate::{
    FieldElement, ParticipantId, ProtocolConfig, PublicPolynomial, VerifiedTranscript,
    recover_share,
};
use alloc::collections::BTreeSet;

extern crate alloc;

/// Aggregated share output for one participant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AggregatedShare<F> {
    /// Participant that recovered the share.
    pub participant: ParticipantId,
    /// Sum of recovered dealer shares.
    pub value: F,
    /// Number of valid dealer contributions included.
    pub dealer_count: usize,
}

/// Aggregation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AggregationError {
    /// The target participant is not part of the configured DKG.
    UnknownParticipant,
    /// Fewer than the threshold number of dealer transcripts were provided.
    InsufficientDealers,
    /// A dealer appears more than once.
    DuplicateDealer,
    /// A verified transcript did not include the target participant.
    MissingShare,
    /// A public polynomial has no constant commitment.
    MissingConstantCommitment,
}

/// Aggregate verified dealer contributions into one participant's final share.
pub fn aggregate_share<F, C>(
    config: &ProtocolConfig,
    transcripts: &[VerifiedTranscript<F, C>],
    target: ParticipantId,
    mask_for: impl Fn(ParticipantId) -> F,
) -> Result<AggregatedShare<F>, AggregationError>
where
    F: FieldElement,
{
    if !config.contains_participant(target) {
        return Err(AggregationError::UnknownParticipant);
    }

    validate_dealers(config, transcripts)?;

    let mut value = F::ZERO;
    for transcript in transcripts {
        let masked = transcript
            .as_ref()
            .masked_shares
            .iter()
            .find(|share| share.participant == target)
            .ok_or(AggregationError::MissingShare)?;
        value += recover_share(masked.value, mask_for(transcript.as_ref().dealer));
    }

    Ok(AggregatedShare {
        participant: target,
        value,
        dealer_count: transcripts.len(),
    })
}

/// Aggregate constant-term public polynomial commitments into a public key.
pub fn aggregate_public_key<F, C, G>(
    config: &ProtocolConfig,
    transcripts: &[VerifiedTranscript<F, C>],
    identity: G,
    add_constant: impl Fn(G, &C) -> G,
) -> Result<G, AggregationError>
where
    F: FieldElement,
{
    validate_dealers(config, transcripts)?;

    let mut acc = identity;
    for transcript in transcripts {
        let constant = constant_commitment(&transcript.as_ref().public_polynomial)?;
        acc = add_constant(acc, constant);
    }

    Ok(acc)
}

fn validate_dealers<F, C>(
    config: &ProtocolConfig,
    transcripts: &[VerifiedTranscript<F, C>],
) -> Result<(), AggregationError>
where
    F: FieldElement,
{
    if transcripts.len() < config.threshold() {
        return Err(AggregationError::InsufficientDealers);
    }

    let mut seen = BTreeSet::new();
    for transcript in transcripts {
        if !seen.insert(transcript.as_ref().dealer) {
            return Err(AggregationError::DuplicateDealer);
        }
    }

    Ok(())
}

fn constant_commitment<C>(public_polynomial: &PublicPolynomial<C>) -> Result<&C, AggregationError> {
    public_polynomial
        .coefficient_commitments
        .first()
        .ok_or(AggregationError::MissingConstantCommitment)
}

#[cfg(test)]
mod tests {
    use super::{AggregationError, aggregate_public_key, aggregate_share};
    use crate::{
        DealerConfig, DealerSecret, FieldElement, ParticipantId, ProofStatus, ProtocolConfig,
        PublicPolynomial, VerifiedTranscript, build_transcript,
        field::test_field::Fp,
        polynomial::{Polynomial, interpolate_at_zero},
        verify_transcript,
    };

    fn id(value: u64) -> ParticipantId {
        ParticipantId::new(value).expect("non-zero id")
    }

    fn transcript_for_dealer(
        dealer: ParticipantId,
        constant: Fp,
        participants: Vec<ParticipantId>,
    ) -> VerifiedTranscript<Fp, u64> {
        let config = DealerConfig {
            dealer,
            participants,
            public_polynomial: PublicPolynomial {
                coefficient_commitments: vec![constant.0],
            },
        };
        let secret = DealerSecret {
            polynomial: Polynomial::new(vec![constant, Fp(3)]),
        };
        let mut transcript = build_transcript(config, &secret, |participant| {
            (Fp(dealer.get() + participant.get()), 0_u64)
        })
        .expect("transcript");
        transcript.proof_status = ProofStatus::Verified;
        verify_transcript(transcript, id(1), |_share, _public| true).expect("verified")
    }

    #[test]
    fn aggregates_participant_share_from_verified_transcripts() {
        let participants = vec![id(1), id(2), id(3)];
        let config = ProtocolConfig::new(2, participants.clone()).expect("valid");
        let transcripts = vec![
            transcript_for_dealer(id(10), Fp(5), participants.clone()),
            transcript_for_dealer(id(11), Fp(7), participants.clone()),
        ];

        let share = aggregate_share(&config, &transcripts, id(1), |dealer| Fp(dealer.get() + 1))
            .expect("aggregated");

        assert_eq!(share.value, Fp(18));
        assert_eq!(share.dealer_count, 2);
    }

    #[test]
    fn aggregated_shares_reconstruct_sum_of_dealer_secrets() {
        let participants = vec![id(1), id(2), id(3)];
        let config = ProtocolConfig::new(2, participants.clone()).expect("valid");
        let transcripts = vec![
            transcript_for_dealer(id(10), Fp(5), participants.clone()),
            transcript_for_dealer(id(11), Fp(7), participants.clone()),
        ];

        let samples = participants
            .iter()
            .copied()
            .map(|participant| {
                let share = aggregate_share(&config, &transcripts, participant, |dealer| {
                    Fp(dealer.get() + participant.get())
                })
                .expect("aggregated");
                (Fp::from_u64(participant.get()), share.value)
            })
            .collect::<Vec<_>>();

        assert_eq!(interpolate_at_zero(&samples[..2]), Ok(Fp(12)));
        assert_eq!(interpolate_at_zero(&samples), Ok(Fp(12)));
    }

    #[test]
    fn rejects_insufficient_dealers() {
        let participants = vec![id(1), id(2)];
        let config = ProtocolConfig::new(2, participants.clone()).expect("valid");
        let transcripts = vec![transcript_for_dealer(id(10), Fp(5), participants)];

        assert_eq!(
            aggregate_share(&config, &transcripts, id(1), |_| Fp(0)),
            Err(AggregationError::InsufficientDealers)
        );
    }

    #[test]
    fn rejects_duplicate_dealers() {
        let participants = vec![id(1), id(2)];
        let config = ProtocolConfig::new(2, participants.clone()).expect("valid");
        let transcripts = vec![
            transcript_for_dealer(id(10), Fp(5), participants.clone()),
            transcript_for_dealer(id(10), Fp(7), participants),
        ];

        assert_eq!(
            aggregate_share(&config, &transcripts, id(1), |_| Fp(0)),
            Err(AggregationError::DuplicateDealer)
        );
    }

    #[test]
    fn aggregates_public_key_commitments() {
        let participants = vec![id(1), id(2)];
        let config = ProtocolConfig::new(2, participants.clone()).expect("valid");
        let transcripts = vec![
            transcript_for_dealer(id(10), Fp(5), participants.clone()),
            transcript_for_dealer(id(11), Fp(7), participants),
        ];

        assert_eq!(
            aggregate_public_key(&config, &transcripts, 0_u64, |acc, constant| acc + constant),
            Ok(12)
        );
    }
}
