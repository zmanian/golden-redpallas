//! Feature-gated Pallas proof backend skeleton.
//!
//! This module is not a production Bulletproofs implementation. It pins the
//! Pallas transcript domains, proof framing, generator derivation boundary, and
//! the first executable mask-relation constraint layer that the real backend
//! will replace with a zero-knowledge proof over the Pallas scalar field.

use blake2b_simd::{Params, State};
use golden_pallas::{PallasPoint, PallasScalar, domains};

use crate::{
    MaskProof, ProofBatchItem, ProofError, ProofPublicInputs, ProofSystem, ProofWitness,
    witness::validate_witness,
};

const BACKEND: &str = "golden-pallas-proof-skeleton/v3";
const CHALLENGE_DOMAIN: &[u8] = b"GoldenRedPallas/PallasProofChallenge/v0";
const CONSTRAINT_DOMAIN: &[u8] = b"GoldenRedPallas/PallasMaskConstraints/v0";
const GENERATOR_DOMAIN: &[u8] = b"GoldenRedPallas/PallasProofGenerator/v0";
const MASK_TRACE_DOMAIN: &[u8] = b"GoldenRedPallas/PallasMaskHashTrace/v0";
const MASK_BLINDING_DOMAIN: &[u8] = b"GoldenRedPallas/PallasMaskBlinding/v0";
const MASK_OPENING_NONCE_DOMAIN: &[u8] = b"GoldenRedPallas/PallasMaskOpeningNonce/v0";
const PROOF_CHALLENGE_LABEL: &[u8] = b"mask-proof";
const MASK_VARIABLE_GENERATOR_LABEL: &[u8] = b"mask-variable";
const MASK_BLINDING_GENERATOR_LABEL: &[u8] = b"mask-blinding";
const PROOF_MAGIC: &[u8; 4] = b"GPBP";
const PROOF_VERSION: u8 = 3;
const CHALLENGE_OFFSET: usize = 5;
const MASK_COMMITMENT_OFFSET: usize = CHALLENGE_OFFSET + 32;
const OPENING_NONCE_COMMITMENT_OFFSET: usize = MASK_COMMITMENT_OFFSET + 32;
const OPENING_RESPONSE_OFFSET: usize = OPENING_NONCE_COMMITMENT_OFFSET + 32;
const TRACE_SHARED_POINT_OFFSET: usize = OPENING_RESPONSE_OFFSET + 32;
const TRACE_TRANSCRIPT_DIGEST_OFFSET: usize = TRACE_SHARED_POINT_OFFSET + 32;
const TRACE_MASK_DIGEST_OFFSET: usize = TRACE_TRANSCRIPT_DIGEST_OFFSET + 32;
const TRACE_MASK_OFFSET: usize = TRACE_MASK_DIGEST_OFFSET + 64;
const CONSTRAINT_DIGEST_OFFSET: usize = TRACE_MASK_OFFSET + 32;
const PROOF_LEN: usize = CONSTRAINT_DIGEST_OFFSET + 32;

/// Pallas-field proof transcript helper.
///
/// The production backend should keep these domain separators stable unless a
/// proof-format version bump is intentional.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PallasProofTranscript;

impl PallasProofTranscript {
    /// Derive a Fiat-Shamir challenge scalar for public mask-proof inputs.
    #[must_use]
    pub fn challenge_scalar(label: &[u8], public_inputs: &ProofPublicInputs) -> PallasScalar {
        let mut state = Params::new().hash_length(64).to_state();
        state.update(CHALLENGE_DOMAIN);
        update_len_prefixed(&mut state, label);
        update_public_inputs(&mut state, public_inputs);

        let hash = state.finalize();
        let mut uniform = [0_u8; 64];
        uniform.copy_from_slice(hash.as_bytes());
        PallasScalar::from_uniform_bytes(&uniform)
    }

    fn proof_challenge(
        public_inputs: &ProofPublicInputs,
        constraint_commitment: PallasMaskConstraintCommitment,
        opening_nonce_commitment: PallasPoint,
        mask_trace: PallasMaskHashTrace,
    ) -> PallasScalar {
        let mut state = Params::new().hash_length(64).to_state();
        state.update(CHALLENGE_DOMAIN);
        update_len_prefixed(&mut state, PROOF_CHALLENGE_LABEL);
        update_public_inputs(&mut state, public_inputs);
        state.update(&constraint_commitment.mask_variable.to_bytes());
        state.update(&opening_nonce_commitment.to_bytes());
        mask_trace.update_transcript(&mut state);

        let hash = state.finalize();
        let mut uniform = [0_u8; 64];
        uniform.copy_from_slice(hash.as_bytes());
        PallasScalar::from_uniform_bytes(&uniform)
    }
}

/// Deterministic trace for the mask hash-to-field relation.
///
/// This is an intermediate circuit-facing format. It records the public
/// transcript digest, raw hash output, and reduced Pallas scalar that a later
/// arithmetic circuit must constrain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PallasMaskHashTrace {
    /// Encoded shared Vesta point used as hash input.
    pub shared_point: [u8; 32],
    /// Digest of the DKG mask transcript bytes.
    pub transcript_digest: [u8; 32],
    /// Raw 64-byte hash-to-field output before reduction.
    pub mask_digest: [u8; 64],
    /// Reduced Pallas scalar mask.
    pub mask: PallasScalar,
}

impl PallasMaskHashTrace {
    /// Build the deterministic trace from public mask inputs.
    #[must_use]
    pub fn from_public_inputs(public_inputs: &ProofPublicInputs) -> Self {
        let transcript = public_inputs.mask_transcript();
        let transcript_digest = trace_transcript_digest(&transcript);
        let mut mask_digest = [0_u8; 64];
        let hash = Params::new()
            .hash_length(64)
            .to_state()
            .update(domains::MASK_TO_FIELD)
            .update(&public_inputs.shared_point.point().to_bytes())
            .update(&transcript)
            .finalize();
        mask_digest.copy_from_slice(hash.as_bytes());
        let mask = PallasScalar::from_uniform_bytes(&mask_digest);

        Self {
            shared_point: public_inputs.shared_point.point().to_bytes(),
            transcript_digest,
            mask_digest,
            mask,
        }
    }

    /// Validate this trace against the public inputs.
    pub fn verify(self, public_inputs: &ProofPublicInputs) -> Result<PallasScalar, ProofError> {
        let transcript = public_inputs.mask_transcript();
        if self.shared_point != public_inputs.shared_point.point().to_bytes() {
            return Err(ProofError::InvalidProof);
        }

        if self.transcript_digest != trace_transcript_digest(&transcript) {
            return Err(ProofError::InvalidProof);
        }

        let mut expected_digest = [0_u8; 64];
        let hash = Params::new()
            .hash_length(64)
            .to_state()
            .update(domains::MASK_TO_FIELD)
            .update(&self.shared_point)
            .update(&transcript)
            .finalize();
        expected_digest.copy_from_slice(hash.as_bytes());
        if self.mask_digest != expected_digest {
            return Err(ProofError::InvalidProof);
        }

        let mask = PallasScalar::from_uniform_bytes(&self.mask_digest);
        if self.mask != mask || public_inputs.mask != mask {
            return Err(ProofError::InvalidProof);
        }

        Ok(mask)
    }

    fn update_transcript(self, state: &mut State) {
        state.update(&self.shared_point);
        state.update(&self.transcript_digest);
        state.update(&self.mask_digest);
        state.update(&self.mask.to_bytes());
    }
}

/// Derive a deterministic Pallas point for backend tests.
///
/// This is a skeleton boundary, not a substitute for independently generated
/// Bulletproof generator vectors.
#[must_use]
pub fn derive_pallas_generator(label: &[u8]) -> PallasPoint {
    let mut state = Params::new().hash_length(64).to_state();
    state.update(GENERATOR_DOMAIN);
    update_len_prefixed(&mut state, label);

    let hash = state.finalize();
    let mut uniform = [0_u8; 64];
    uniform.copy_from_slice(hash.as_bytes());
    PallasPoint::generator_mul(PallasScalar::from_uniform_bytes(&uniform))
}

/// Schnorr-style proof that the mask commitment opens to the public mask.
///
/// The response proves knowledge of the mask-commitment blinding without
/// serializing the blinding itself. The production backend should eventually
/// fold this relation into the Pallas-field proof system.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PallasMaskOpeningProof {
    /// Fiat-Shamir challenge.
    pub challenge: PallasScalar,
    /// Nonce commitment for the blinding-generator relation.
    pub nonce_commitment: PallasPoint,
    /// Schnorr response for the hidden blinding.
    pub response: PallasScalar,
}

/// Public commitment emitted by the Pallas mask constraint layer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PallasMaskConstraintCommitment {
    /// Commitment to the mask witness variable.
    pub mask_variable: PallasPoint,
}

/// Executable Pallas mask-relation constraints.
///
/// This layer checks the public part of Golden's mask relation:
/// `mask = H(shared_point, transcript)` and
/// `mask_commitment = mask * Pallas::generator()`. It also commits the mask
/// variable against backend-specific Pallas generators. The current proof uses a
/// Schnorr-style opening proof for that commitment; a real Bulletproofs backend
/// will replace this with an integrated zero-knowledge proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PallasMaskConstraints;

impl PallasMaskConstraints {
    /// Check the public mask relation and return the expected mask.
    pub fn verify_public_relation(
        public_inputs: &ProofPublicInputs,
        mask_trace: PallasMaskHashTrace,
    ) -> Result<PallasScalar, ProofError> {
        let mask = mask_trace.verify(public_inputs)?;

        if public_inputs.mask_commitment != PallasPoint::generator_mul(mask) {
            return Err(ProofError::InvalidProof);
        }

        Ok(mask)
    }

    /// Commit to the mask variable with backend-specific Pallas generators.
    #[must_use]
    pub fn commit_mask(
        mask: PallasScalar,
        blinding: PallasScalar,
    ) -> PallasMaskConstraintCommitment {
        let mask_generator = derive_pallas_generator(MASK_VARIABLE_GENERATOR_LABEL);
        let blinding_generator = derive_pallas_generator(MASK_BLINDING_GENERATOR_LABEL);
        PallasMaskConstraintCommitment {
            mask_variable: mask_generator.mul_scalar(mask)
                + blinding_generator.mul_scalar(blinding),
        }
    }

    fn prove_opening(
        public_inputs: &ProofPublicInputs,
        mask: PallasScalar,
        blinding: PallasScalar,
        constraint_commitment: PallasMaskConstraintCommitment,
        mask_trace: PallasMaskHashTrace,
    ) -> PallasMaskOpeningProof {
        let nonce = derive_opening_nonce(public_inputs, mask, blinding, constraint_commitment);
        let nonce_commitment =
            derive_pallas_generator(MASK_BLINDING_GENERATOR_LABEL).mul_scalar(nonce);
        let challenge = PallasProofTranscript::proof_challenge(
            public_inputs,
            constraint_commitment,
            nonce_commitment,
            mask_trace,
        );
        PallasMaskOpeningProof {
            challenge,
            nonce_commitment,
            response: nonce + challenge * blinding,
        }
    }

    fn verify_opening_proof(
        public_inputs: &ProofPublicInputs,
        constraint_commitment: PallasMaskConstraintCommitment,
        opening_proof: PallasMaskOpeningProof,
        mask_trace: PallasMaskHashTrace,
    ) -> Result<(), ProofError> {
        let mask = Self::verify_public_relation(public_inputs, mask_trace)?;
        let challenge = PallasProofTranscript::proof_challenge(
            public_inputs,
            constraint_commitment,
            opening_proof.nonce_commitment,
            mask_trace,
        );
        if opening_proof.challenge != challenge {
            return Err(ProofError::InvalidProof);
        }

        let mask_generator = derive_pallas_generator(MASK_VARIABLE_GENERATOR_LABEL);
        let blinding_generator = derive_pallas_generator(MASK_BLINDING_GENERATOR_LABEL);
        let hidden_blinding_component =
            constraint_commitment.mask_variable - mask_generator.mul_scalar(mask);
        let lhs = blinding_generator.mul_scalar(opening_proof.response);
        let rhs = opening_proof.nonce_commitment
            + hidden_blinding_component.mul_scalar(opening_proof.challenge);
        if lhs != rhs {
            return Err(ProofError::InvalidProof);
        }

        Ok(())
    }
}

/// Feature-gated non-zero-knowledge Pallas proof backend skeleton.
///
/// This backend is useful for stabilizing transcript domains, proof framing, and
/// mask-relation constraint checks before the R1CS constraints land. It
/// validates the same public/witness consistency as the fixture backend and
/// emits deterministic proof bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PallasProofSkeleton;

impl ProofSystem for PallasProofSkeleton {
    fn prove(
        public_inputs: &ProofPublicInputs,
        witness: &ProofWitness,
    ) -> Result<MaskProof, ProofError> {
        validate_witness(public_inputs, witness)?;
        let mask_trace = PallasMaskHashTrace::from_public_inputs(public_inputs);
        PallasMaskConstraints::verify_public_relation(public_inputs, mask_trace)
            .map_err(|_| ProofError::InvalidWitness)?;
        Ok(MaskProof {
            backend: BACKEND,
            bytes: encode_skeleton_proof(public_inputs, witness),
        })
    }

    fn verify(public_inputs: &ProofPublicInputs, proof: &MaskProof) -> Result<(), ProofError> {
        if proof.backend != BACKEND {
            return Err(ProofError::BackendMismatch);
        }

        let decoded = decode_skeleton_proof(&proof.bytes)?;
        PallasMaskConstraints::verify_opening_proof(
            public_inputs,
            decoded.constraint_commitment,
            decoded.opening_proof,
            decoded.mask_trace,
        )?;
        let constraint_digest = constraint_digest(
            public_inputs,
            decoded.constraint_commitment,
            decoded.opening_proof,
            decoded.mask_trace,
        )?;

        if decoded.opening_proof.challenge != decoded.challenge
            || decoded.constraint_digest != constraint_digest
        {
            Err(ProofError::InvalidProof)
        } else {
            Ok(())
        }
    }

    fn verify_batch(items: &[ProofBatchItem<'_>]) -> Result<(), ProofError> {
        for item in items {
            Self::verify(item.public_inputs, item.proof)?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SkeletonProof {
    challenge: PallasScalar,
    constraint_commitment: PallasMaskConstraintCommitment,
    opening_proof: PallasMaskOpeningProof,
    mask_trace: PallasMaskHashTrace,
    constraint_digest: [u8; 32],
}

fn encode_skeleton_proof(public_inputs: &ProofPublicInputs, witness: &ProofWitness) -> Vec<u8> {
    let mask_blinding = derive_mask_blinding(public_inputs, witness);
    let mask_trace = PallasMaskHashTrace::from_public_inputs(public_inputs);
    let constraint_commitment = PallasMaskConstraints::commit_mask(witness.mask, mask_blinding);
    let opening_proof = PallasMaskConstraints::prove_opening(
        public_inputs,
        witness.mask,
        mask_blinding,
        constraint_commitment,
        mask_trace,
    );
    let constraint_digest = constraint_digest(
        public_inputs,
        constraint_commitment,
        opening_proof,
        mask_trace,
    )
    .expect("validated proof inputs");

    let mut bytes = Vec::with_capacity(PROOF_LEN);
    bytes.extend_from_slice(PROOF_MAGIC);
    bytes.push(PROOF_VERSION);
    bytes.extend_from_slice(&opening_proof.challenge.to_bytes());
    bytes.extend_from_slice(&constraint_commitment.mask_variable.to_bytes());
    bytes.extend_from_slice(&opening_proof.nonce_commitment.to_bytes());
    bytes.extend_from_slice(&opening_proof.response.to_bytes());
    bytes.extend_from_slice(&mask_trace.shared_point);
    bytes.extend_from_slice(&mask_trace.transcript_digest);
    bytes.extend_from_slice(&mask_trace.mask_digest);
    bytes.extend_from_slice(&mask_trace.mask.to_bytes());
    bytes.extend_from_slice(&constraint_digest);
    bytes
}

fn decode_skeleton_proof(bytes: &[u8]) -> Result<SkeletonProof, ProofError> {
    if bytes.len() != PROOF_LEN {
        return Err(ProofError::InvalidProof);
    }

    if &bytes[..4] != PROOF_MAGIC || bytes[4] != PROOF_VERSION {
        return Err(ProofError::InvalidProof);
    }

    let mut challenge_bytes = [0_u8; 32];
    challenge_bytes.copy_from_slice(&bytes[CHALLENGE_OFFSET..MASK_COMMITMENT_OFFSET]);
    let challenge = PallasScalar::from_bytes(challenge_bytes).ok_or(ProofError::InvalidProof)?;

    let mut commitment_bytes = [0_u8; 32];
    commitment_bytes
        .copy_from_slice(&bytes[MASK_COMMITMENT_OFFSET..OPENING_NONCE_COMMITMENT_OFFSET]);
    let constraint_commitment = PallasMaskConstraintCommitment {
        mask_variable: PallasPoint::from_bytes(commitment_bytes).ok_or(ProofError::InvalidProof)?,
    };

    let mut nonce_commitment_bytes = [0_u8; 32];
    nonce_commitment_bytes
        .copy_from_slice(&bytes[OPENING_NONCE_COMMITMENT_OFFSET..OPENING_RESPONSE_OFFSET]);
    let nonce_commitment =
        PallasPoint::from_bytes(nonce_commitment_bytes).ok_or(ProofError::InvalidProof)?;

    let mut response_bytes = [0_u8; 32];
    response_bytes.copy_from_slice(&bytes[OPENING_RESPONSE_OFFSET..TRACE_SHARED_POINT_OFFSET]);
    let response = PallasScalar::from_bytes(response_bytes).ok_or(ProofError::InvalidProof)?;

    let mut shared_point = [0_u8; 32];
    shared_point.copy_from_slice(&bytes[TRACE_SHARED_POINT_OFFSET..TRACE_TRANSCRIPT_DIGEST_OFFSET]);

    let mut transcript_digest = [0_u8; 32];
    transcript_digest
        .copy_from_slice(&bytes[TRACE_TRANSCRIPT_DIGEST_OFFSET..TRACE_MASK_DIGEST_OFFSET]);

    let mut mask_digest = [0_u8; 64];
    mask_digest.copy_from_slice(&bytes[TRACE_MASK_DIGEST_OFFSET..TRACE_MASK_OFFSET]);

    let mut mask_bytes = [0_u8; 32];
    mask_bytes.copy_from_slice(&bytes[TRACE_MASK_OFFSET..CONSTRAINT_DIGEST_OFFSET]);
    let mask = PallasScalar::from_bytes(mask_bytes).ok_or(ProofError::InvalidProof)?;

    let mut constraint_digest = [0_u8; 32];
    constraint_digest.copy_from_slice(&bytes[CONSTRAINT_DIGEST_OFFSET..PROOF_LEN]);

    Ok(SkeletonProof {
        challenge,
        constraint_commitment,
        opening_proof: PallasMaskOpeningProof {
            challenge,
            nonce_commitment,
            response,
        },
        mask_trace: PallasMaskHashTrace {
            shared_point,
            transcript_digest,
            mask_digest,
            mask,
        },
        constraint_digest,
    })
}

fn derive_mask_blinding(public_inputs: &ProofPublicInputs, witness: &ProofWitness) -> PallasScalar {
    let mut state = Params::new().hash_length(64).to_state();
    state.update(MASK_BLINDING_DOMAIN);
    update_public_inputs(&mut state, public_inputs);
    state.update(&witness.dealer_secret.to_bytes());
    state.update(&witness.shared_point.to_bytes());
    state.update(&witness.mask.to_bytes());

    let hash = state.finalize();
    let mut uniform = [0_u8; 64];
    uniform.copy_from_slice(hash.as_bytes());
    PallasScalar::from_uniform_bytes(&uniform)
}

fn derive_opening_nonce(
    public_inputs: &ProofPublicInputs,
    mask: PallasScalar,
    blinding: PallasScalar,
    constraint_commitment: PallasMaskConstraintCommitment,
) -> PallasScalar {
    let mut state = Params::new().hash_length(64).to_state();
    state.update(MASK_OPENING_NONCE_DOMAIN);
    update_public_inputs(&mut state, public_inputs);
    state.update(&mask.to_bytes());
    state.update(&blinding.to_bytes());
    state.update(&constraint_commitment.mask_variable.to_bytes());

    let hash = state.finalize();
    let mut uniform = [0_u8; 64];
    uniform.copy_from_slice(hash.as_bytes());
    PallasScalar::from_uniform_bytes(&uniform)
}

fn constraint_digest(
    public_inputs: &ProofPublicInputs,
    constraint_commitment: PallasMaskConstraintCommitment,
    opening_proof: PallasMaskOpeningProof,
    mask_trace: PallasMaskHashTrace,
) -> Result<[u8; 32], ProofError> {
    let mask = PallasMaskConstraints::verify_public_relation(public_inputs, mask_trace)?;
    let mut state = Params::new().hash_length(32).to_state();
    state.update(CONSTRAINT_DOMAIN);
    update_public_inputs(&mut state, public_inputs);
    mask_trace.update_transcript(&mut state);
    state.update(&constraint_commitment.mask_variable.to_bytes());
    state.update(&opening_proof.nonce_commitment.to_bytes());
    state.update(&opening_proof.response.to_bytes());
    state.update(&opening_proof.challenge.to_bytes());
    state.update(&mask.to_bytes());
    state.update(&PallasPoint::generator_mul(mask).to_bytes());

    let hash = state.finalize();
    let mut digest = [0_u8; 32];
    digest.copy_from_slice(hash.as_bytes());
    Ok(digest)
}

fn trace_transcript_digest(transcript: &[u8]) -> [u8; 32] {
    let hash = Params::new()
        .hash_length(32)
        .to_state()
        .update(MASK_TRACE_DOMAIN)
        .update(transcript)
        .finalize();
    let mut digest = [0_u8; 32];
    digest.copy_from_slice(hash.as_bytes());
    digest
}

fn update_public_inputs(state: &mut State, public_inputs: &ProofPublicInputs) {
    state.update(&public_inputs.mask_transcript());
    state.update(&public_inputs.shared_point.point().to_bytes());
    state.update(&public_inputs.mask.to_bytes());
    state.update(&public_inputs.mask_commitment.to_bytes());
}

fn update_len_prefixed(state: &mut State, bytes: &[u8]) {
    state.update(&(bytes.len() as u64).to_le_bytes());
    state.update(bytes);
}

#[cfg(test)]
mod tests {
    use golden_core::{FieldElement, ParticipantId, Polynomial};
    use golden_pallas::{
        HelperPublicKey, HelperSecretKey, PallasPoint, PallasScalar, VestaScalar,
        commit_polynomial, derive_mask,
    };

    use super::{
        MASK_COMMITMENT_OFFSET, OPENING_NONCE_COMMITMENT_OFFSET, OPENING_RESPONSE_OFFSET,
        PallasMaskConstraints, PallasMaskHashTrace, PallasProofSkeleton, PallasProofTranscript,
        TRACE_MASK_DIGEST_OFFSET, TRACE_MASK_OFFSET, TRACE_SHARED_POINT_OFFSET,
        TRACE_TRANSCRIPT_DIGEST_OFFSET, decode_skeleton_proof, derive_pallas_generator,
    };
    use crate::{ProofBatchItem, ProofError, ProofPublicInputs, ProofSystem, ProofWitness};

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
            session_id: b"pallas-proof-session".to_vec(),
            dealer_id: id(10),
            participant_id: id(1),
            dealer_public: dealer_secret.public_key(),
            participant_public: participant_secret.public_key(),
            shared_point: dealer_secret.diffie_hellman(participant_secret.public_key()),
            mask: PallasScalar::ZERO,
            mask_commitment: PallasPoint::identity(),
            public_polynomial,
        };
        refresh_mask(&mut public_inputs);
        let witness = ProofWitness {
            dealer_secret: dealer_secret.scalar(),
            shared_point: public_inputs.shared_point.point(),
            mask: public_inputs.mask,
        };
        (public_inputs, witness)
    }

    fn refresh_mask(public_inputs: &mut ProofPublicInputs) {
        let mask = derive_mask(public_inputs.shared_point, &public_inputs.mask_transcript());
        public_inputs.mask = mask;
        public_inputs.mask_commitment = PallasPoint::generator_mul(mask);
    }

    #[test]
    fn challenge_is_deterministic() {
        let (public_inputs, _) = valid_case();

        assert_eq!(
            PallasProofTranscript::challenge_scalar(b"alpha", &public_inputs),
            PallasProofTranscript::challenge_scalar(b"alpha", &public_inputs)
        );
    }

    #[test]
    fn challenge_is_label_separated() {
        let (public_inputs, _) = valid_case();

        assert_ne!(
            PallasProofTranscript::challenge_scalar(b"alpha", &public_inputs),
            PallasProofTranscript::challenge_scalar(b"beta", &public_inputs)
        );
    }

    #[test]
    fn challenge_binds_session_and_public_polynomial() {
        let (public_inputs, _) = valid_case();
        let challenge = PallasProofTranscript::challenge_scalar(b"alpha", &public_inputs);
        let mut other_session = public_inputs.clone();
        other_session.session_id = b"other-session".to_vec();
        let mut other_polynomial = public_inputs.clone();
        other_polynomial.public_polynomial = commit_polynomial(&Polynomial::new(vec![
            PallasScalar::from_u64(5),
            PallasScalar::from_u64(8),
        ]));

        assert_ne!(
            challenge,
            PallasProofTranscript::challenge_scalar(b"alpha", &other_session)
        );
        assert_ne!(
            challenge,
            PallasProofTranscript::challenge_scalar(b"alpha", &other_polynomial)
        );
    }

    #[test]
    fn derived_generators_are_deterministic_and_label_separated() {
        assert_eq!(
            derive_pallas_generator(b"commitment-g"),
            derive_pallas_generator(b"commitment-g")
        );
        assert_ne!(
            derive_pallas_generator(b"commitment-g"),
            derive_pallas_generator(b"commitment-h")
        );
    }

    #[test]
    fn mask_constraints_accept_valid_public_relation() {
        let (public_inputs, _) = valid_case();
        let mask_trace = PallasMaskHashTrace::from_public_inputs(&public_inputs);

        assert_eq!(
            PallasMaskConstraints::verify_public_relation(&public_inputs, mask_trace),
            Ok(public_inputs.mask)
        );
    }

    #[test]
    fn mask_hash_trace_accepts_valid_trace() {
        let (public_inputs, _) = valid_case();
        let mask_trace = PallasMaskHashTrace::from_public_inputs(&public_inputs);

        assert_eq!(mask_trace.verify(&public_inputs), Ok(public_inputs.mask));
    }

    #[test]
    fn mask_hash_trace_rejects_wrong_shared_point() {
        let (public_inputs, _) = valid_case();
        let mut mask_trace = PallasMaskHashTrace::from_public_inputs(&public_inputs);
        mask_trace.shared_point[0] ^= 1;

        assert_eq!(
            mask_trace.verify(&public_inputs),
            Err(ProofError::InvalidProof)
        );
    }

    #[test]
    fn mask_hash_trace_rejects_wrong_transcript_digest() {
        let (public_inputs, _) = valid_case();
        let mut mask_trace = PallasMaskHashTrace::from_public_inputs(&public_inputs);
        mask_trace.transcript_digest[0] ^= 1;

        assert_eq!(
            mask_trace.verify(&public_inputs),
            Err(ProofError::InvalidProof)
        );
    }

    #[test]
    fn mask_hash_trace_rejects_wrong_mask_digest() {
        let (public_inputs, _) = valid_case();
        let mut mask_trace = PallasMaskHashTrace::from_public_inputs(&public_inputs);
        mask_trace.mask_digest[0] ^= 1;

        assert_eq!(
            mask_trace.verify(&public_inputs),
            Err(ProofError::InvalidProof)
        );
    }

    #[test]
    fn mask_hash_trace_rejects_wrong_mask() {
        let (public_inputs, _) = valid_case();
        let mut mask_trace = PallasMaskHashTrace::from_public_inputs(&public_inputs);
        mask_trace.mask += PallasScalar::ONE;

        assert_eq!(
            mask_trace.verify(&public_inputs),
            Err(ProofError::InvalidProof)
        );
    }

    #[test]
    fn mask_constraints_reject_wrong_public_mask() {
        let (mut public_inputs, _) = valid_case();
        public_inputs.mask += PallasScalar::ONE;
        let mask_trace = PallasMaskHashTrace::from_public_inputs(&public_inputs);

        assert_eq!(
            PallasMaskConstraints::verify_public_relation(&public_inputs, mask_trace),
            Err(ProofError::InvalidProof)
        );
    }

    #[test]
    fn mask_constraints_reject_wrong_public_mask_commitment() {
        let (mut public_inputs, _) = valid_case();
        public_inputs.mask_commitment += PallasPoint::generator();
        let mask_trace = PallasMaskHashTrace::from_public_inputs(&public_inputs);

        assert_eq!(
            PallasMaskConstraints::verify_public_relation(&public_inputs, mask_trace),
            Err(ProofError::InvalidProof)
        );
    }

    #[test]
    fn mask_constraint_commitment_is_blinding_sensitive() {
        let (public_inputs, _) = valid_case();

        assert_ne!(
            PallasMaskConstraints::commit_mask(public_inputs.mask, PallasScalar::from_u64(1)),
            PallasMaskConstraints::commit_mask(public_inputs.mask, PallasScalar::from_u64(2))
        );
    }

    #[test]
    fn skeleton_backend_proves_and_verifies_valid_inputs() {
        let (public_inputs, witness) = valid_case();
        let proof = PallasProofSkeleton::prove(&public_inputs, &witness).expect("proof");

        assert_eq!(PallasProofSkeleton::verify(&public_inputs, &proof), Ok(()));
        assert!(decode_skeleton_proof(&proof.bytes).is_ok());
    }

    #[test]
    fn skeleton_rejects_malformed_proof_bytes() {
        let (public_inputs, witness) = valid_case();
        let mut proof = PallasProofSkeleton::prove(&public_inputs, &witness).expect("proof");
        proof.bytes.pop();

        assert_eq!(
            PallasProofSkeleton::verify(&public_inputs, &proof),
            Err(ProofError::InvalidProof)
        );
    }

    #[test]
    fn skeleton_rejects_tampered_proof_bytes() {
        let (public_inputs, witness) = valid_case();
        let mut proof = PallasProofSkeleton::prove(&public_inputs, &witness).expect("proof");
        proof.bytes[5] ^= 1;

        assert_eq!(
            PallasProofSkeleton::verify(&public_inputs, &proof),
            Err(ProofError::InvalidProof)
        );
    }

    #[test]
    fn skeleton_rejects_tampered_constraint_commitment() {
        let (public_inputs, witness) = valid_case();
        let mut proof = PallasProofSkeleton::prove(&public_inputs, &witness).expect("proof");
        proof.bytes[MASK_COMMITMENT_OFFSET] ^= 1;

        assert_eq!(
            PallasProofSkeleton::verify(&public_inputs, &proof),
            Err(ProofError::InvalidProof)
        );
    }

    #[test]
    fn skeleton_rejects_tampered_opening_nonce_commitment() {
        let (public_inputs, witness) = valid_case();
        let mut proof = PallasProofSkeleton::prove(&public_inputs, &witness).expect("proof");
        proof.bytes[OPENING_NONCE_COMMITMENT_OFFSET] ^= 1;

        assert_eq!(
            PallasProofSkeleton::verify(&public_inputs, &proof),
            Err(ProofError::InvalidProof)
        );
    }

    #[test]
    fn skeleton_rejects_tampered_opening_response() {
        let (public_inputs, witness) = valid_case();
        let mut proof = PallasProofSkeleton::prove(&public_inputs, &witness).expect("proof");
        proof.bytes[OPENING_RESPONSE_OFFSET] ^= 1;

        assert_eq!(
            PallasProofSkeleton::verify(&public_inputs, &proof),
            Err(ProofError::InvalidProof)
        );
    }

    #[test]
    fn skeleton_rejects_tampered_trace_shared_point() {
        let (public_inputs, witness) = valid_case();
        let mut proof = PallasProofSkeleton::prove(&public_inputs, &witness).expect("proof");
        proof.bytes[TRACE_SHARED_POINT_OFFSET] ^= 1;

        assert_eq!(
            PallasProofSkeleton::verify(&public_inputs, &proof),
            Err(ProofError::InvalidProof)
        );
    }

    #[test]
    fn skeleton_rejects_tampered_trace_transcript_digest() {
        let (public_inputs, witness) = valid_case();
        let mut proof = PallasProofSkeleton::prove(&public_inputs, &witness).expect("proof");
        proof.bytes[TRACE_TRANSCRIPT_DIGEST_OFFSET] ^= 1;

        assert_eq!(
            PallasProofSkeleton::verify(&public_inputs, &proof),
            Err(ProofError::InvalidProof)
        );
    }

    #[test]
    fn skeleton_rejects_tampered_trace_mask_digest() {
        let (public_inputs, witness) = valid_case();
        let mut proof = PallasProofSkeleton::prove(&public_inputs, &witness).expect("proof");
        proof.bytes[TRACE_MASK_DIGEST_OFFSET] ^= 1;

        assert_eq!(
            PallasProofSkeleton::verify(&public_inputs, &proof),
            Err(ProofError::InvalidProof)
        );
    }

    #[test]
    fn skeleton_rejects_tampered_trace_mask() {
        let (public_inputs, witness) = valid_case();
        let mut proof = PallasProofSkeleton::prove(&public_inputs, &witness).expect("proof");
        proof.bytes[TRACE_MASK_OFFSET] ^= 1;

        assert_eq!(
            PallasProofSkeleton::verify(&public_inputs, &proof),
            Err(ProofError::InvalidProof)
        );
    }

    #[test]
    fn skeleton_rejects_wrong_public_input() {
        let (public_inputs, witness) = valid_case();
        let proof = PallasProofSkeleton::prove(&public_inputs, &witness).expect("proof");
        let mut tampered = public_inputs;
        tampered.dealer_public = HelperPublicKey::from_point(
            HelperSecretKey::from_scalar(VestaScalar::from_u64(99))
                .public_key()
                .point(),
        );

        assert_eq!(
            PallasProofSkeleton::verify(&tampered, &proof),
            Err(ProofError::InvalidProof)
        );
    }

    #[test]
    fn skeleton_rejects_invalid_witness() {
        let (public_inputs, mut witness) = valid_case();
        witness.mask += PallasScalar::ONE;

        assert_eq!(
            PallasProofSkeleton::prove(&public_inputs, &witness),
            Err(ProofError::InvalidWitness)
        );
    }

    #[test]
    fn batch_verifies_valid_inputs() {
        let (first_inputs, first_witness) = valid_case();
        let first_proof = PallasProofSkeleton::prove(&first_inputs, &first_witness).expect("proof");
        let (mut second_inputs, mut second_witness) = valid_case();
        second_inputs.participant_id = id(2);
        refresh_mask(&mut second_inputs);
        second_witness.mask = second_inputs.mask;
        let second_proof =
            PallasProofSkeleton::prove(&second_inputs, &second_witness).expect("proof");
        let batch = [
            ProofBatchItem {
                public_inputs: &first_inputs,
                proof: &first_proof,
            },
            ProofBatchItem {
                public_inputs: &second_inputs,
                proof: &second_proof,
            },
        ];

        assert_eq!(PallasProofSkeleton::verify_batch(&batch), Ok(()));
    }

    #[test]
    fn batch_rejects_invalid_member() {
        let (first_inputs, first_witness) = valid_case();
        let first_proof = PallasProofSkeleton::prove(&first_inputs, &first_witness).expect("proof");
        let (second_inputs, second_witness) = valid_case();
        let mut second_proof =
            PallasProofSkeleton::prove(&second_inputs, &second_witness).expect("proof");
        second_proof.bytes[5] ^= 1;
        let batch = [
            ProofBatchItem {
                public_inputs: &first_inputs,
                proof: &first_proof,
            },
            ProofBatchItem {
                public_inputs: &second_inputs,
                proof: &second_proof,
            },
        ];

        assert_eq!(
            PallasProofSkeleton::verify_batch(&batch),
            Err(ProofError::InvalidProof)
        );
    }
}
