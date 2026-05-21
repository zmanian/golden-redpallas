//! Proof-aware DKG simulation harness.

use core::marker::PhantomData;

use golden_core::{
    AggregatedShare, AggregationError, FieldElement, ParticipantId, ProofStatus, Transcript,
    VerificationError, recover_share, verify_transcript,
};
use golden_pallas::{
    DkgFixture, DkgSimulation, PallasPoint, PallasScalar, SharedSecret, SimulationDealer,
    SimulationError, SimulationParticipant, derive_mask, verify_masked_share_commitment,
};

use crate::{MaskProof, ProofBatchItem, ProofError, ProofPublicInputs, ProofSystem, ProofWitness};

/// Dealer transcript plus one mask proof per participant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProofedTranscript {
    /// Public dealer transcript.
    pub transcript: Transcript<PallasScalar, PallasPoint>,
    /// Per-recipient mask proofs.
    pub proofs: Vec<MaskProofEntry>,
}

/// One mask proof and its public inputs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MaskProofEntry {
    /// Participant receiving the corresponding masked share.
    pub participant: ParticipantId,
    /// Public proof inputs.
    pub public_inputs: ProofPublicInputs,
    /// Proof bytes.
    pub proof: MaskProof,
}

/// Proof-aware DKG simulation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProofedDkgSimulation<P> {
    /// Underlying DKG simulation.
    pub simulation: DkgSimulation,
    /// Proof-bearing transcripts.
    pub proofed_transcripts: Vec<ProofedTranscript>,
    proof_system: PhantomData<P>,
}

impl<P: ProofSystem> ProofedDkgSimulation<P> {
    /// Build a proof-aware simulation from a deterministic fixture.
    pub fn from_fixture(fixture: &DkgFixture) -> Result<Self, ProofedDkgError> {
        let simulation = fixture.run()?;
        let proofed_transcripts = simulation
            .transcripts
            .iter()
            .map(|transcript| proof_transcript::<P>(&simulation, transcript))
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self {
            simulation,
            proofed_transcripts,
            proof_system: PhantomData,
        })
    }

    /// Recover one participant's aggregate share after verifying proofs.
    pub fn recover_participant(
        &self,
        participant_id: ParticipantId,
    ) -> Result<AggregatedShare<PallasScalar>, ProofedDkgError> {
        recover_with_proofs::<P>(&self.simulation, participant_id, &self.proofed_transcripts)
    }

    /// Aggregate the public key after verifying proofs for the first participant.
    pub fn aggregate_public_key(&self) -> Result<PallasPoint, ProofedDkgError> {
        let first = self
            .simulation
            .participants
            .first()
            .ok_or(ProofedDkgError::UnknownParticipant)?;
        verify_proofed_transcripts::<P>(&self.simulation, first.id, &self.proofed_transcripts)?;
        self.simulation
            .aggregate_public_key()
            .map_err(ProofedDkgError::Simulation)
    }
}

/// Recover one participant's aggregate share after verifying proof-bearing
/// transcripts.
pub fn recover_with_proofs<P: ProofSystem>(
    simulation: &DkgSimulation,
    participant_id: ParticipantId,
    proofed_transcripts: &[ProofedTranscript],
) -> Result<AggregatedShare<PallasScalar>, ProofedDkgError> {
    let verified_transcripts =
        verify_proofed_transcripts::<P>(simulation, participant_id, proofed_transcripts)?;
    let participant = find_participant(simulation, participant_id)?;

    if verified_transcripts.len() < simulation.config.threshold() {
        return Err(AggregationError::InsufficientDealers.into());
    }

    let mut seen_dealers = Vec::with_capacity(verified_transcripts.len());
    let mut value = PallasScalar::ZERO;
    for verified_transcript in &verified_transcripts {
        let transcript = verified_transcript.as_ref();
        if seen_dealers.contains(&transcript.dealer) {
            return Err(AggregationError::DuplicateDealer.into());
        }
        seen_dealers.push(transcript.dealer);

        let dealer = find_dealer(simulation, transcript.dealer)?;
        let masked_share = transcript
            .masked_shares
            .iter()
            .find(|share| share.participant == participant_id)
            .ok_or(AggregationError::MissingShare)?;
        let public_inputs = proof_public_inputs(
            simulation,
            transcript,
            dealer,
            participant,
            masked_share.mask_commitment,
        );
        value += recover_share(masked_share.value, public_inputs.mask);
    }

    Ok(AggregatedShare {
        participant: participant_id,
        value,
        dealer_count: verified_transcripts.len(),
    })
}

fn proof_transcript<P: ProofSystem>(
    simulation: &DkgSimulation,
    transcript: &Transcript<PallasScalar, PallasPoint>,
) -> Result<ProofedTranscript, ProofedDkgError> {
    let dealer = find_dealer(simulation, transcript.dealer)?;
    let proofs = transcript
        .masked_shares
        .iter()
        .map(|masked_share| {
            let participant = find_participant(simulation, masked_share.participant)?;
            let public_inputs = proof_public_inputs(
                simulation,
                transcript,
                dealer,
                participant,
                masked_share.mask_commitment,
            );
            let witness = ProofWitness {
                dealer_secret: dealer.helper_secret.scalar(),
                shared_point: public_inputs.shared_point.point(),
                mask: public_inputs.mask,
            };
            let proof =
                P::prove(&public_inputs, &witness).map_err(|source| ProofedDkgError::Proof {
                    dealer: transcript.dealer,
                    participant: participant.id,
                    source,
                })?;
            Ok(MaskProofEntry {
                participant: participant.id,
                public_inputs,
                proof,
            })
        })
        .collect::<Result<Vec<_>, ProofedDkgError>>()?;

    Ok(ProofedTranscript {
        transcript: transcript.clone(),
        proofs,
    })
}

fn verify_proofed_transcripts<P: ProofSystem>(
    simulation: &DkgSimulation,
    participant_id: ParticipantId,
    proofed_transcripts: &[ProofedTranscript],
) -> Result<Vec<golden_core::VerifiedTranscript<PallasScalar, PallasPoint>>, ProofedDkgError> {
    let mut batch = Vec::with_capacity(proofed_transcripts.len());
    let mut transcripts = Vec::with_capacity(proofed_transcripts.len());

    for proofed in proofed_transcripts {
        let transcript = &proofed.transcript;
        let dealer = find_dealer(simulation, transcript.dealer)?;
        let participant = find_participant(simulation, participant_id)?;
        let masked_share = transcript
            .masked_shares
            .iter()
            .find(|share| share.participant == participant_id)
            .ok_or(AggregationError::MissingShare)?;
        let proof_entry = proofed
            .proofs
            .iter()
            .find(|entry| entry.participant == participant_id)
            .ok_or(ProofedDkgError::MissingProof)?;
        let expected_inputs = proof_public_inputs(
            simulation,
            transcript,
            dealer,
            participant,
            masked_share.mask_commitment,
        );

        if proof_entry.public_inputs != expected_inputs {
            return Err(ProofedDkgError::PublicInputsMismatch {
                dealer: transcript.dealer,
                participant: participant_id,
            });
        }

        batch.push(ProofBatchItem {
            public_inputs: &proof_entry.public_inputs,
            proof: &proof_entry.proof,
        });
        transcripts.push(transcript);
    }

    P::verify_batch(&batch).map_err(|source| ProofedDkgError::BatchProof {
        participant: participant_id,
        source,
    })?;

    transcripts
        .into_iter()
        .map(|transcript| {
            let mut verified_candidate = transcript.clone();
            verified_candidate.proof_status = ProofStatus::Verified;
            verify_transcript(
                verified_candidate,
                participant_id,
                verify_masked_share_commitment,
            )
            .map_err(|source| ProofedDkgError::Transcript {
                dealer: transcript.dealer,
                participant: participant_id,
                source,
            })
        })
        .collect()
}

fn proof_public_inputs(
    simulation: &DkgSimulation,
    transcript: &Transcript<PallasScalar, PallasPoint>,
    dealer: &SimulationDealer,
    participant: SimulationParticipant,
    mask_commitment: PallasPoint,
) -> ProofPublicInputs {
    let dealer_public = dealer.helper_public();
    let participant_public = participant.helper_public();
    let shared_point = SharedSecret::from_point(
        participant_public
            .point()
            .mul_scalar(dealer.helper_secret.scalar()),
    );
    let mut public_inputs = ProofPublicInputs {
        session_id: simulation.session_id.clone(),
        dealer_id: transcript.dealer,
        participant_id: participant.id,
        dealer_public,
        participant_public,
        shared_point,
        mask: PallasScalar::ZERO,
        mask_commitment,
        public_polynomial: transcript.public_polynomial.clone(),
    };
    public_inputs.mask = derive_mask(shared_point, &public_inputs.mask_transcript());
    public_inputs
}

fn find_participant(
    simulation: &DkgSimulation,
    participant_id: ParticipantId,
) -> Result<SimulationParticipant, ProofedDkgError> {
    simulation
        .participants
        .iter()
        .copied()
        .find(|participant| participant.id == participant_id)
        .ok_or(ProofedDkgError::UnknownParticipant)
}

fn find_dealer(
    simulation: &DkgSimulation,
    dealer_id: ParticipantId,
) -> Result<&SimulationDealer, ProofedDkgError> {
    simulation
        .dealers
        .iter()
        .find(|dealer| dealer.id == dealer_id)
        .ok_or(ProofedDkgError::UnknownDealer)
}

/// Proof-aware DKG failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProofedDkgError {
    /// Underlying simulation failed.
    Simulation(SimulationError),
    /// Share aggregation failed.
    Aggregation(AggregationError),
    /// Dealer fixture is missing.
    UnknownDealer,
    /// Participant fixture is missing.
    UnknownParticipant,
    /// No proof exists for a participant's masked share.
    MissingProof,
    /// Stored public inputs do not match the transcript being verified.
    PublicInputsMismatch {
        /// Dealer whose proof inputs mismatched.
        dealer: ParticipantId,
        /// Participant whose proof inputs mismatched.
        participant: ParticipantId,
    },
    /// Proof verification failed.
    Proof {
        /// Dealer whose proof failed.
        dealer: ParticipantId,
        /// Participant whose proof failed.
        participant: ParticipantId,
        /// Backend proof failure.
        source: ProofError,
    },
    /// Batch proof verification failed.
    BatchProof {
        /// Participant whose proof batch failed.
        participant: ParticipantId,
        /// Backend proof failure.
        source: ProofError,
    },
    /// Transcript verification failed.
    Transcript {
        /// Dealer whose transcript failed.
        dealer: ParticipantId,
        /// Participant whose transcript failed.
        participant: ParticipantId,
        /// Transcript verification failure.
        source: VerificationError,
    },
}

impl From<SimulationError> for ProofedDkgError {
    fn from(value: SimulationError) -> Self {
        Self::Simulation(value)
    }
}

impl From<AggregationError> for ProofedDkgError {
    fn from(value: AggregationError) -> Self {
        Self::Aggregation(value)
    }
}

#[cfg(test)]
mod tests {
    use golden_core::{AggregationError, FieldElement, interpolate_at_zero};
    use golden_pallas::{DkgFixture, PallasPoint, PallasScalar};

    use crate::{FixtureProofSystem, ProofError};

    use super::{ProofedDkgError, ProofedDkgSimulation, recover_with_proofs};

    const DKG_VECTOR_V0: &str = include_str!("../../../test-vectors/golden-pallas/dkg-v0.txt");

    #[test]
    fn proofed_fixture_recovers_all_participant_shares() {
        let fixture = DkgFixture::parse(DKG_VECTOR_V0).expect("fixture");
        let proofed =
            ProofedDkgSimulation::<FixtureProofSystem>::from_fixture(&fixture).expect("proofed");
        let aggregate_secret = proofed.simulation.aggregate_secret().expect("secret");
        let aggregate_public_key = proofed.aggregate_public_key().expect("public key");

        assert_eq!(
            aggregate_public_key,
            PallasPoint::generator_mul(aggregate_secret)
        );

        let samples = proofed
            .simulation
            .participants
            .iter()
            .map(|participant| {
                let share = proofed
                    .recover_participant(participant.id)
                    .expect("participant share");
                (PallasScalar::from_u64(participant.id.get()), share.value)
            })
            .collect::<Vec<_>>();

        assert_eq!(interpolate_at_zero(&samples[..2]), Ok(aggregate_secret));
        assert_eq!(interpolate_at_zero(&samples), Ok(aggregate_secret));
    }

    #[test]
    fn proof_verification_rejects_tampered_proof_even_if_commitment_equation_still_holds() {
        let fixture = DkgFixture::parse(DKG_VECTOR_V0).expect("fixture");
        let proofed =
            ProofedDkgSimulation::<FixtureProofSystem>::from_fixture(&fixture).expect("proofed");
        let participant = proofed.simulation.participants[0].id;
        let mut proofed_transcripts = proofed.proofed_transcripts.clone();
        proofed_transcripts[0].proofs[0].proof.bytes[0] ^= 1;

        assert!(matches!(
            recover_with_proofs::<FixtureProofSystem>(
                &proofed.simulation,
                participant,
                &proofed_transcripts,
            ),
            Err(ProofedDkgError::BatchProof {
                source: ProofError::InvalidProof,
                ..
            })
        ));
    }

    #[test]
    fn proof_verification_rejects_tampered_public_inputs() {
        let fixture = DkgFixture::parse(DKG_VECTOR_V0).expect("fixture");
        let proofed =
            ProofedDkgSimulation::<FixtureProofSystem>::from_fixture(&fixture).expect("proofed");
        let participant = proofed.simulation.participants[0].id;
        let mut proofed_transcripts = proofed.proofed_transcripts.clone();
        proofed_transcripts[0].proofs[0].public_inputs.session_id = b"wrong-session".to_vec();

        assert!(matches!(
            recover_with_proofs::<FixtureProofSystem>(
                &proofed.simulation,
                participant,
                &proofed_transcripts,
            ),
            Err(ProofedDkgError::PublicInputsMismatch { .. })
        ));
    }

    #[test]
    fn proofed_recovery_rejects_missing_proof() {
        let fixture = DkgFixture::parse(DKG_VECTOR_V0).expect("fixture");
        let proofed =
            ProofedDkgSimulation::<FixtureProofSystem>::from_fixture(&fixture).expect("proofed");
        let participant = proofed.simulation.participants[0].id;
        let mut proofed_transcripts = proofed.proofed_transcripts.clone();
        proofed_transcripts[0].proofs.remove(0);

        assert_eq!(
            recover_with_proofs::<FixtureProofSystem>(
                &proofed.simulation,
                participant,
                &proofed_transcripts,
            ),
            Err(ProofedDkgError::MissingProof)
        );
    }

    #[test]
    fn proofed_recovery_rejects_insufficient_dealers() {
        let fixture = DkgFixture::parse(DKG_VECTOR_V0).expect("fixture");
        let proofed =
            ProofedDkgSimulation::<FixtureProofSystem>::from_fixture(&fixture).expect("proofed");
        let participant = proofed.simulation.participants[0].id;

        assert_eq!(
            recover_with_proofs::<FixtureProofSystem>(
                &proofed.simulation,
                participant,
                &proofed.proofed_transcripts[..1],
            ),
            Err(ProofedDkgError::Aggregation(
                AggregationError::InsufficientDealers
            ))
        );
    }
}
