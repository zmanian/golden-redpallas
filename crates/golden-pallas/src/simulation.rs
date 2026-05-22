//! Deterministic end-to-end Golden DKG simulation over Pallas/Vesta.
//!
//! This module intentionally treats the zero-knowledge proof as already
//! externally accepted. It exercises the rest of the Golden data flow with real
//! Pallas commitments and Vesta-derived masks.

use golden_core::{
    AggregatedShare, AggregationError, ConfigError, DealerConfig, DealerError, DealerSecret,
    FieldElement, ParticipantId, Polynomial, ProofStatus, ProtocolConfig, Transcript,
    VerifiedTranscript, aggregate_public_key, build_transcript, recover_share, verify_transcript,
};

use crate::{
    HelperPublicKey, HelperSecretKey, PallasPoint, PallasScalar, VestaScalar, commit_polynomial,
    derive_mask, dkg_mask_transcript, verify_masked_share_commitment,
};

/// Participant fixture input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SimulationParticipant {
    /// Participant identifier used as the Shamir evaluation point.
    pub id: ParticipantId,
    /// Participant helper-curve secret key.
    pub helper_secret: HelperSecretKey,
}

impl SimulationParticipant {
    /// Construct a simulation participant from small deterministic values.
    #[must_use]
    pub fn from_u64(id: u64, helper_secret: u64) -> Option<Self> {
        Some(Self {
            id: ParticipantId::new(id)?,
            helper_secret: HelperSecretKey::from_scalar(VestaScalar::from_u64(helper_secret)),
        })
    }

    /// Return the helper public key.
    #[must_use]
    pub fn helper_public(self) -> HelperPublicKey {
        self.helper_secret.public_key()
    }
}

/// Dealer fixture input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SimulationDealer {
    /// Dealer identifier.
    pub id: ParticipantId,
    /// Dealer helper-curve secret key.
    pub helper_secret: HelperSecretKey,
    /// Dealer Shamir polynomial.
    pub polynomial: Polynomial<PallasScalar>,
}

impl SimulationDealer {
    /// Construct a simulation dealer from small deterministic values.
    #[must_use]
    pub fn from_u64(id: u64, helper_secret: u64, coefficients: &[u64]) -> Option<Self> {
        Some(Self {
            id: ParticipantId::new(id)?,
            helper_secret: HelperSecretKey::from_scalar(VestaScalar::from_u64(helper_secret)),
            polynomial: Polynomial::new(
                coefficients
                    .iter()
                    .copied()
                    .map(PallasScalar::from_u64)
                    .collect(),
            ),
        })
    }

    /// Return the helper public key.
    #[must_use]
    pub fn helper_public(&self) -> HelperPublicKey {
        self.helper_secret.public_key()
    }
}

/// Deterministic DKG fixture.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DkgFixture {
    /// Threshold for the generated Shamir shares.
    pub threshold: usize,
    /// Session identifier bound into every mask.
    pub session_id: Vec<u8>,
    /// Participants receiving shares.
    pub participants: Vec<SimulationParticipant>,
    /// Dealers contributing polynomials.
    pub dealers: Vec<SimulationDealer>,
}

impl DkgFixture {
    /// Parse the simple line-oriented fixture format used in `test-vectors/`.
    pub fn parse(input: &str) -> Result<Self, SimulationError> {
        let mut version = None;
        let mut threshold = None;
        let mut session_id = None;
        let mut participants = None;
        let mut dealers = None;

        for raw_line in input.lines() {
            let line = raw_line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            let Some((key, value)) = line.split_once('=') else {
                return Err(SimulationError::InvalidFixtureLine);
            };

            match key {
                "version" => version = Some(value),
                "threshold" => threshold = Some(parse_usize(value)?),
                "session" => session_id = Some(value.as_bytes().to_vec()),
                "participants" => participants = Some(parse_participants(value)?),
                "dealers" => dealers = Some(parse_dealers(value)?),
                _ => return Err(SimulationError::UnknownFixtureKey),
            }
        }

        if version != Some("0") {
            return Err(SimulationError::UnsupportedFixtureVersion);
        }

        Ok(Self {
            threshold: threshold.ok_or(SimulationError::MissingFixtureKey)?,
            session_id: session_id.ok_or(SimulationError::MissingFixtureKey)?,
            participants: participants.ok_or(SimulationError::MissingFixtureKey)?,
            dealers: dealers.ok_or(SimulationError::MissingFixtureKey)?,
        })
    }

    /// Validate and run the DKG simulation.
    pub fn run(&self) -> Result<DkgSimulation, SimulationError> {
        let participant_ids = self
            .participants
            .iter()
            .map(|participant| participant.id)
            .collect::<Vec<_>>();
        let config = ProtocolConfig::new(self.threshold, participant_ids)?;
        let mut transcripts = Vec::with_capacity(self.dealers.len());

        for dealer in &self.dealers {
            transcripts.push(self.build_dealer_transcript(dealer)?);
        }

        Ok(DkgSimulation {
            config,
            session_id: self.session_id.clone(),
            participants: self.participants.clone(),
            dealers: self.dealers.clone(),
            transcripts,
        })
    }

    fn build_dealer_transcript(
        &self,
        dealer: &SimulationDealer,
    ) -> Result<Transcript<PallasScalar, PallasPoint>, SimulationError> {
        let public_polynomial = commit_polynomial(&dealer.polynomial);
        let config = DealerConfig {
            dealer: dealer.id,
            participants: self
                .participants
                .iter()
                .map(|participant| participant.id)
                .collect(),
            public_polynomial: public_polynomial.clone(),
        };
        let secret = DealerSecret {
            polynomial: dealer.polynomial.clone(),
        };
        let mut transcript = build_transcript(config, &secret, |participant_id| {
            let participant = self
                .participant(participant_id)
                .expect("dealer transcript only uses configured participants");
            let mask = dealer_mask(&self.session_id, dealer, participant, &public_polynomial);
            (mask, PallasPoint::generator_mul(mask))
        })?;
        transcript.proof_status = ProofStatus::Verified;
        Ok(transcript)
    }

    fn participant(&self, id: ParticipantId) -> Option<SimulationParticipant> {
        self.participants
            .iter()
            .copied()
            .find(|participant| participant.id == id)
    }
}

/// Completed DKG simulation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DkgSimulation {
    /// Validated protocol configuration.
    pub config: ProtocolConfig,
    /// Session identifier bound into every mask.
    pub session_id: Vec<u8>,
    /// Participants receiving shares.
    pub participants: Vec<SimulationParticipant>,
    /// Dealer fixture inputs.
    pub dealers: Vec<SimulationDealer>,
    /// Public dealer transcripts.
    pub transcripts: Vec<Transcript<PallasScalar, PallasPoint>>,
}

impl DkgSimulation {
    /// Recover one participant's aggregate share from this simulation.
    pub fn recover_participant(
        &self,
        participant_id: ParticipantId,
    ) -> Result<AggregatedShare<PallasScalar>, SimulationError> {
        self.recover_participant_from_transcripts(participant_id, &self.transcripts)
    }

    /// Recover one participant's aggregate share from a caller-provided
    /// transcript ordering.
    pub fn recover_participant_from_transcripts(
        &self,
        participant_id: ParticipantId,
        transcripts: &[Transcript<PallasScalar, PallasPoint>],
    ) -> Result<AggregatedShare<PallasScalar>, SimulationError> {
        let participant = self
            .participant(participant_id)
            .ok_or(SimulationError::UnknownParticipant)?;
        let verified = Self::verify_transcripts_for_participant(participant_id, transcripts)?;
        let masks = verified
            .iter()
            .map(|verified_transcript| {
                let transcript = verified_transcript.as_ref();
                let dealer = self
                    .dealer(transcript.dealer)
                    .ok_or(SimulationError::UnknownDealer)?;
                Ok((
                    transcript.dealer,
                    participant_mask(
                        &self.session_id,
                        transcript.dealer,
                        dealer.helper_public(),
                        participant,
                        &transcript.public_polynomial,
                    ),
                ))
            })
            .collect::<Result<Vec<_>, SimulationError>>()?;

        if verified.len() < self.config.threshold() {
            return Err(AggregationError::InsufficientDealers.into());
        }

        let mut seen_dealers = Vec::with_capacity(verified.len());
        let mut value = PallasScalar::ZERO;
        for verified_transcript in &verified {
            let transcript = verified_transcript.as_ref();
            if seen_dealers.contains(&transcript.dealer) {
                return Err(AggregationError::DuplicateDealer.into());
            }
            seen_dealers.push(transcript.dealer);

            let masked_share = transcript
                .masked_shares
                .iter()
                .find(|share| share.participant == participant_id)
                .ok_or(AggregationError::MissingShare)?;
            let mask = masks
                .iter()
                .find_map(|(candidate, mask)| (*candidate == transcript.dealer).then_some(*mask))
                .ok_or(SimulationError::UnknownDealer)?;
            value += recover_share(masked_share.value, mask);
        }

        Ok(AggregatedShare {
            participant: participant_id,
            value,
            dealer_count: verified.len(),
        })
    }

    /// Aggregate the public key from all dealer public polynomials.
    pub fn aggregate_public_key(&self) -> Result<PallasPoint, SimulationError> {
        let first_participant = self
            .participants
            .first()
            .ok_or(SimulationError::UnknownParticipant)?;
        let verified =
            Self::verify_transcripts_for_participant(first_participant.id, &self.transcripts)?;
        aggregate_public_key(
            &self.config,
            &verified,
            PallasPoint::identity(),
            |acc, point| acc + *point,
        )
        .map_err(Into::into)
    }

    /// Return the sum of dealer secret polynomial constants.
    #[must_use]
    pub fn aggregate_secret(&self) -> Option<PallasScalar> {
        let mut secret = PallasScalar::ZERO;
        for dealer in &self.dealers {
            secret += dealer.polynomial.constant()?;
        }
        Some(secret)
    }

    fn verify_transcripts_for_participant(
        participant_id: ParticipantId,
        transcripts: &[Transcript<PallasScalar, PallasPoint>],
    ) -> Result<Vec<VerifiedTranscript<PallasScalar, PallasPoint>>, SimulationError> {
        transcripts
            .iter()
            .cloned()
            .map(|transcript| {
                let dealer = transcript.dealer;
                verify_transcript(transcript, participant_id, verify_masked_share_commitment)
                    .map_err(|source| SimulationError::Verification { dealer, source })
            })
            .collect()
    }

    fn participant(&self, id: ParticipantId) -> Option<SimulationParticipant> {
        self.participants
            .iter()
            .copied()
            .find(|participant| participant.id == id)
    }

    fn dealer(&self, id: ParticipantId) -> Option<&SimulationDealer> {
        self.dealers.iter().find(|dealer| dealer.id == id)
    }
}

/// Simulation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SimulationError {
    /// Invalid protocol configuration.
    Config(ConfigError),
    /// Dealer transcript construction failed.
    Dealer(DealerError),
    /// Share or public-key aggregation failed.
    Aggregation(AggregationError),
    /// Transcript verification failed.
    Verification {
        /// Dealer whose transcript failed.
        dealer: ParticipantId,
        /// Verification failure.
        source: golden_core::VerificationError,
    },
    /// Participant was not found in the fixture.
    UnknownParticipant,
    /// Dealer was not found in the fixture.
    UnknownDealer,
    /// A fixture line was not `key=value`.
    InvalidFixtureLine,
    /// A fixture key is not recognized.
    UnknownFixtureKey,
    /// Required fixture key is missing.
    MissingFixtureKey,
    /// Fixture version is not supported.
    UnsupportedFixtureVersion,
    /// Numeric fixture value failed to parse.
    InvalidNumber,
    /// Participant fixture item is malformed.
    InvalidParticipant,
    /// Dealer fixture item is malformed.
    InvalidDealer,
    /// Dealer polynomial has no coefficients.
    EmptyDealerPolynomial,
}

impl From<ConfigError> for SimulationError {
    fn from(value: ConfigError) -> Self {
        Self::Config(value)
    }
}

impl From<DealerError> for SimulationError {
    fn from(value: DealerError) -> Self {
        Self::Dealer(value)
    }
}

impl From<AggregationError> for SimulationError {
    fn from(value: AggregationError) -> Self {
        Self::Aggregation(value)
    }
}

fn dealer_mask(
    session_id: &[u8],
    dealer: &SimulationDealer,
    participant: SimulationParticipant,
    public_polynomial: &golden_core::PublicPolynomial<PallasPoint>,
) -> PallasScalar {
    let shared = dealer
        .helper_secret
        .diffie_hellman(participant.helper_public());
    derive_mask(
        shared,
        &dkg_mask_transcript(
            session_id,
            dealer.id,
            participant.id,
            dealer.helper_public(),
            participant.helper_public(),
            public_polynomial,
        ),
    )
}

fn participant_mask(
    session_id: &[u8],
    dealer_id: ParticipantId,
    dealer_public: HelperPublicKey,
    participant: SimulationParticipant,
    public_polynomial: &golden_core::PublicPolynomial<PallasPoint>,
) -> PallasScalar {
    let shared = participant.helper_secret.diffie_hellman(dealer_public);
    derive_mask(
        shared,
        &dkg_mask_transcript(
            session_id,
            dealer_id,
            participant.id,
            dealer_public,
            participant.helper_public(),
            public_polynomial,
        ),
    )
}

fn parse_participants(input: &str) -> Result<Vec<SimulationParticipant>, SimulationError> {
    split_items(input)
        .map(|item| {
            let (id, helper_secret) = item
                .split_once(':')
                .ok_or(SimulationError::InvalidParticipant)?;
            SimulationParticipant::from_u64(parse_u64(id)?, parse_u64(helper_secret)?)
                .ok_or(SimulationError::InvalidParticipant)
        })
        .collect()
}

fn parse_dealers(input: &str) -> Result<Vec<SimulationDealer>, SimulationError> {
    split_items(input)
        .map(|item| {
            let (dealer, coefficient_text) =
                item.split_once(':').ok_or(SimulationError::InvalidDealer)?;
            let (id, helper_secret) = dealer
                .split_once('/')
                .ok_or(SimulationError::InvalidDealer)?;
            let coefficients = coefficient_text
                .split(',')
                .map(parse_u64)
                .collect::<Result<Vec<_>, _>>()?;

            if coefficients.is_empty() {
                return Err(SimulationError::EmptyDealerPolynomial);
            }

            SimulationDealer::from_u64(parse_u64(id)?, parse_u64(helper_secret)?, &coefficients)
                .ok_or(SimulationError::InvalidDealer)
        })
        .collect()
}

fn split_items(input: &str) -> impl Iterator<Item = &str> {
    input
        .split(';')
        .map(str::trim)
        .filter(|item| !item.is_empty())
}

fn parse_usize(input: &str) -> Result<usize, SimulationError> {
    input
        .parse::<usize>()
        .map_err(|_error| SimulationError::InvalidNumber)
}

fn parse_u64(input: &str) -> Result<u64, SimulationError> {
    input
        .parse::<u64>()
        .map_err(|_error| SimulationError::InvalidNumber)
}

#[cfg(test)]
mod tests {
    use golden_core::{AggregationError, FieldElement, interpolate_at_zero};

    use super::{DkgFixture, SimulationError};
    use crate::{PallasPoint, PallasScalar};

    const DKG_VECTOR_V0: &str = include_str!("../../../test-vectors/golden-pallas/dkg-v0.txt");

    #[test]
    fn deterministic_fixture_recovers_all_participant_shares() {
        let fixture = DkgFixture::parse(DKG_VECTOR_V0).expect("fixture");
        let simulation = fixture.run().expect("simulation");
        let aggregate_secret = simulation.aggregate_secret().expect("secret");
        let aggregate_public_key = simulation.aggregate_public_key().expect("public key");

        assert_eq!(
            aggregate_public_key,
            PallasPoint::generator_mul(aggregate_secret)
        );

        let samples = simulation
            .participants
            .iter()
            .map(|participant| {
                let share = simulation
                    .recover_participant(participant.id)
                    .expect("participant share");
                (PallasScalar::from_u64(participant.id.get()), share.value)
            })
            .collect::<Vec<_>>();

        assert_eq!(interpolate_at_zero(&samples[..2]), Ok(aggregate_secret));
        assert_eq!(interpolate_at_zero(&samples), Ok(aggregate_secret));
    }

    #[test]
    fn transcript_ordering_does_not_change_recovered_share() {
        let fixture = DkgFixture::parse(DKG_VECTOR_V0).expect("fixture");
        let simulation = fixture.run().expect("simulation");
        let participant = simulation.participants[0].id;
        let baseline = simulation
            .recover_participant(participant)
            .expect("baseline share");
        let mut reversed = simulation.transcripts.clone();
        reversed.reverse();
        let reordered = simulation
            .recover_participant_from_transcripts(participant, &reversed)
            .expect("reordered share");

        assert_eq!(baseline.value, reordered.value);
    }

    #[test]
    fn invalid_mask_commitment_is_rejected() {
        let fixture = DkgFixture::parse(DKG_VECTOR_V0).expect("fixture");
        let simulation = fixture.run().expect("simulation");
        let participant = simulation.participants[0].id;
        let mut corrupted = simulation.transcripts.clone();
        corrupted[0].masked_shares[0].mask_commitment += PallasPoint::generator();

        assert!(matches!(
            simulation.recover_participant_from_transcripts(participant, &corrupted),
            Err(SimulationError::Verification { .. })
        ));
    }

    #[test]
    fn fewer_than_threshold_valid_dealers_fails() {
        let fixture = DkgFixture::parse(DKG_VECTOR_V0).expect("fixture");
        let simulation = fixture.run().expect("simulation");
        let participant = simulation.participants[0].id;

        assert_eq!(
            simulation
                .recover_participant_from_transcripts(participant, &simulation.transcripts[..1],),
            Err(SimulationError::Aggregation(
                AggregationError::InsufficientDealers
            ))
        );
    }

    #[test]
    fn transcript_parser_fuzz_corpus_does_not_panic() {
        let corpus = [
            "",
            "version=0\nthreshold=2\n",
            "version=1\nthreshold=2\nsession=x\nparticipants=1:2\ndealers=3/4:5\n",
            "version=0\nthreshold=x\nsession=x\nparticipants=1:2\ndealers=3/4:5\n",
            "version=0\nthreshold=2\nsession=x\nparticipants=0:2\ndealers=3/4:5\n",
            "version=0\nthreshold=2\nsession=x\nparticipants=1:2;1:3\ndealers=3/4:5,6\n",
            "version=0\nthreshold=2\nsession=x\nparticipants=1:2;2:3\ndealers=3/4:\n",
            "version=0\nthreshold=2\nsession=x\nparticipants=1:2;2:3\ndealers=3/4:5,6;3/4:7,8\n",
            DKG_VECTOR_V0,
        ];

        for input in corpus {
            let _ = DkgFixture::parse(input).and_then(|fixture| fixture.run());
        }
    }
}
