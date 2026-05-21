//! Deterministic fixture backend for proof-boundary tests.

use blake2b_simd::Params;
use golden_pallas::{PallasPoint, derive_mask};

use crate::{MaskProof, ProofError, ProofPublicInputs, ProofSystem, ProofWitness};

const BACKEND: &str = "golden-fixture-proof/v0";
const DIGEST_DOMAIN: &[u8] = b"GoldenRedPallas/FixtureProof/v0";

/// Non-zero-knowledge fixture proof backend.
///
/// This backend proves nothing cryptographically. It checks the same public input
/// bindings that the real Bulletproofs backend must preserve, then emits a
/// deterministic digest so integration tests can exercise proof plumbing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FixtureProofSystem;

impl ProofSystem for FixtureProofSystem {
    fn prove(
        public_inputs: &ProofPublicInputs,
        witness: &ProofWitness,
    ) -> Result<MaskProof, ProofError> {
        validate_witness(public_inputs, witness)?;
        Ok(MaskProof {
            backend: BACKEND,
            bytes: digest_public_inputs(public_inputs),
        })
    }

    fn verify(public_inputs: &ProofPublicInputs, proof: &MaskProof) -> Result<(), ProofError> {
        if proof.backend != BACKEND {
            return Err(ProofError::BackendMismatch);
        }

        if proof.bytes == digest_public_inputs(public_inputs) {
            Ok(())
        } else {
            Err(ProofError::InvalidProof)
        }
    }
}

fn validate_witness(
    public_inputs: &ProofPublicInputs,
    witness: &ProofWitness,
) -> Result<(), ProofError> {
    let dealer_public = public_inputs.dealer_public.point();
    let expected_dealer_public = golden_pallas::VestaPoint::generator_mul(witness.dealer_secret);
    if dealer_public != expected_dealer_public {
        return Err(ProofError::InvalidWitness);
    }

    let expected_shared = public_inputs
        .participant_public
        .point()
        .mul_scalar(witness.dealer_secret);
    if witness.shared_point != expected_shared {
        return Err(ProofError::InvalidWitness);
    }

    if public_inputs.shared_point.point() != witness.shared_point {
        return Err(ProofError::InvalidWitness);
    }

    let mask = derive_mask(public_inputs.shared_point, &public_inputs.mask_transcript());
    if public_inputs.mask != mask || witness.mask != mask {
        return Err(ProofError::InvalidWitness);
    }

    if public_inputs.mask_commitment != PallasPoint::generator_mul(mask) {
        return Err(ProofError::InvalidWitness);
    }

    Ok(())
}

fn digest_public_inputs(public_inputs: &ProofPublicInputs) -> Vec<u8> {
    let hash = Params::new()
        .hash_length(32)
        .to_state()
        .update(DIGEST_DOMAIN)
        .update(&public_inputs.mask_transcript())
        .update(&public_inputs.shared_point.point().to_bytes())
        .update(&public_inputs.mask.to_bytes())
        .update(&public_inputs.mask_commitment.to_bytes())
        .finalize();
    hash.as_bytes().to_vec()
}

#[cfg(test)]
mod tests {
    use golden_core::{FieldElement, ParticipantId, Polynomial};
    use golden_pallas::{
        HelperPublicKey, HelperSecretKey, PallasPoint, PallasScalar, VestaScalar,
        commit_polynomial, derive_mask,
    };

    use super::FixtureProofSystem;
    use crate::{ProofError, ProofPublicInputs, ProofSystem, ProofWitness};

    fn id(value: u64) -> ParticipantId {
        ParticipantId::new(value).expect("non-zero id")
    }

    fn valid_case() -> (ProofPublicInputs, ProofWitness) {
        let dealer_secret = HelperSecretKey::from_scalar(VestaScalar::from_u64(13));
        let participant_secret = HelperSecretKey::from_scalar(VestaScalar::from_u64(29));
        let public_polynomial = commit_polynomial(&Polynomial::new(vec![
            PallasScalar::from_u64(5),
            PallasScalar::from_u64(7),
        ]));
        let mut public_inputs = ProofPublicInputs {
            session_id: b"proof-fixture-session".to_vec(),
            dealer_id: id(10),
            participant_id: id(1),
            dealer_public: dealer_secret.public_key(),
            participant_public: participant_secret.public_key(),
            shared_point: dealer_secret.diffie_hellman(participant_secret.public_key()),
            mask: PallasScalar::ZERO,
            mask_commitment: PallasPoint::identity(),
            public_polynomial,
        };
        let mask = derive_mask(public_inputs.shared_point, &public_inputs.mask_transcript());
        public_inputs.mask = mask;
        public_inputs.mask_commitment = PallasPoint::generator_mul(mask);
        let witness = ProofWitness {
            dealer_secret: dealer_secret.scalar(),
            shared_point: public_inputs.shared_point.point(),
            mask,
        };
        (public_inputs, witness)
    }

    #[test]
    fn fixture_backend_proves_and_verifies_valid_inputs() {
        let (public_inputs, witness) = valid_case();
        let proof = FixtureProofSystem::prove(&public_inputs, &witness).expect("proof");

        assert_eq!(FixtureProofSystem::verify(&public_inputs, &proof), Ok(()));
    }

    #[test]
    fn rejects_wrong_session_id() {
        let (public_inputs, witness) = valid_case();
        let proof = FixtureProofSystem::prove(&public_inputs, &witness).expect("proof");
        let mut tampered = public_inputs;
        tampered.session_id = b"other-session".to_vec();

        assert_eq!(
            FixtureProofSystem::verify(&tampered, &proof),
            Err(ProofError::InvalidProof)
        );
    }

    #[test]
    fn rejects_wrong_dealer_key() {
        let (public_inputs, witness) = valid_case();
        let mut tampered = public_inputs;
        tampered.dealer_public = HelperPublicKey::from_point(
            HelperSecretKey::from_scalar(VestaScalar::from_u64(99))
                .public_key()
                .point(),
        );

        assert_eq!(
            FixtureProofSystem::prove(&tampered, &witness),
            Err(ProofError::InvalidWitness)
        );
    }

    #[test]
    fn rejects_wrong_participant_key() {
        let (public_inputs, witness) = valid_case();
        let mut tampered = public_inputs;
        tampered.participant_public = HelperPublicKey::from_point(
            HelperSecretKey::from_scalar(VestaScalar::from_u64(99))
                .public_key()
                .point(),
        );

        assert_eq!(
            FixtureProofSystem::prove(&tampered, &witness),
            Err(ProofError::InvalidWitness)
        );
    }

    #[test]
    fn rejects_wrong_mask_commitment() {
        let (public_inputs, witness) = valid_case();
        let mut tampered = public_inputs;
        tampered.mask_commitment += PallasPoint::generator();

        assert_eq!(
            FixtureProofSystem::prove(&tampered, &witness),
            Err(ProofError::InvalidWitness)
        );
    }

    #[test]
    fn rejects_wrong_public_polynomial() {
        let (public_inputs, witness) = valid_case();
        let proof = FixtureProofSystem::prove(&public_inputs, &witness).expect("proof");
        let mut tampered = public_inputs;
        tampered.public_polynomial = commit_polynomial(&Polynomial::new(vec![
            PallasScalar::from_u64(8),
            PallasScalar::from_u64(7),
        ]));

        assert_eq!(
            FixtureProofSystem::verify(&tampered, &proof),
            Err(ProofError::InvalidProof)
        );
    }

    #[test]
    fn rejects_wrong_backend() {
        let (public_inputs, witness) = valid_case();
        let mut proof = FixtureProofSystem::prove(&public_inputs, &witness).expect("proof");
        proof.backend = "other";

        assert_eq!(
            FixtureProofSystem::verify(&public_inputs, &proof),
            Err(ProofError::BackendMismatch)
        );
    }

    #[test]
    fn rejects_wrong_proof_bytes() {
        let (public_inputs, witness) = valid_case();
        let mut proof = FixtureProofSystem::prove(&public_inputs, &witness).expect("proof");
        proof.bytes[0] ^= 1;

        assert_eq!(
            FixtureProofSystem::verify(&public_inputs, &proof),
            Err(ProofError::InvalidProof)
        );
    }
}
