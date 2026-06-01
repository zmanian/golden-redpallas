//! Feature-gated Pallas proof backend.
//!
//! This module is an unaudited Pallas Bulletproofs backend candidate. It pins
//! the Pallas transcript domains, proof framing, generator derivation boundary,
//! and executable circuit-proof layer. The active proof bytes are opaque
//! circuit proof bytes. The mask circuit now synthesizes the Blake2b
//! hash-to-field relation and the Vesta shared-coordinate binding, while the
//! DH circuit proves the matching Vesta scalar multiplication relation.

use ark_ec::{AffineRepr, PrimeGroup};
use ark_ff::{BigInteger, PrimeField, Zero};
use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    boolean::Boolean,
    convert::{ToBitsGadget, ToBytesGadget},
    eq::EqGadget,
    fields::{
        FieldVar,
        fp::{AllocatedFp, FpVar},
    },
    groups::CurveVar,
    uint8::UInt8,
    uint64::UInt64,
};
use ark_relations::r1cs::{
    ConstraintMatrices, ConstraintSystem, OptimizationGoal, SynthesisError, SynthesisMode,
};
use blake2b_simd::{Params, State};
use golden_core::FieldElement;
use golden_pallas::{PallasPoint, PallasScalar, VestaPoint, VestaScalar, domains};
use rand_core::{CryptoRng, OsRng, RngCore};

use crate::{
    MaskProof, ProofBatchItem, ProofError, ProofPublicInputs, ProofSystem, ProofWitness,
    witness::validate_witness_with_hash,
};

pub mod circuit;
pub mod ipa;
pub use circuit::{
    PallasCircuit, PallasCircuitClaim, PallasCircuitProof, PallasCircuitSetup,
    PallasCircuitWitness, PallasR1cs, PallasSparseMatrix,
};
pub use ipa::{PallasIpaClaim, PallasIpaProof, PallasIpaSetup, PallasIpaWitness};

pub use crate::MaskHashKind;

#[cfg(feature = "poseidon-mask")]
pub use poseidon::poseidon_mask_config;

/// Poseidon mask hash-to-field relation built on `ark-crypto-primitives` 0.5.
///
/// The native [`PoseidonSponge`] and the in-circuit [`PoseidonSpongeVar`] share a
/// single memoized [`PoseidonConfig`] over `ark_vesta::Fq` and absorb the
/// identical preimage bytes, so the squeezed native and circuit field elements
/// are guaranteed equal.
#[cfg(feature = "poseidon-mask")]
pub mod poseidon {
    use std::sync::OnceLock;

    use ark_crypto_primitives::sponge::{
        CryptographicSponge,
        constraints::CryptographicSpongeVar,
        poseidon::{
            PoseidonConfig, PoseidonSponge, constraints::PoseidonSpongeVar,
            traits::find_poseidon_ark_and_mds,
        },
    };
    use ark_r1cs_std::{fields::fp::FpVar, uint8::UInt8};
    use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};

    /// Number of full rounds in the mask Poseidon permutation.
    pub const POSEIDON_FULL_ROUNDS: usize = 8;
    /// Number of partial rounds in the mask Poseidon permutation.
    pub const POSEIDON_PARTIAL_ROUNDS: usize = 56;
    /// S-box exponent for the mask Poseidon permutation.
    pub const POSEIDON_ALPHA: u64 = 5;
    /// Sponge rate (field elements) for the mask Poseidon permutation.
    pub const POSEIDON_RATE: usize = 2;
    /// Sponge capacity (field elements) for the mask Poseidon permutation.
    pub const POSEIDON_CAPACITY: usize = 1;
    /// Bit size of the `ark_vesta::Fq` prime modulus used by the generator.
    const POSEIDON_PRIME_BITS: u64 = 255;
    /// Number of Grain-LFSR MDS matrices to skip during constant generation.
    const POSEIDON_SKIP_MATRICES: u64 = 0;

    static MASK_CONFIG: OnceLock<PoseidonConfig<ark_vesta::Fq>> = OnceLock::new();

    /// Return the memoized Poseidon configuration for the mask relation.
    ///
    /// The `(ark, mds)` constants are generated deterministically once via the
    /// arkworks Grain-LFSR reference generator and cached so the native sponge
    /// and the R1CS gadget always share one identical parameter set.
    #[must_use]
    pub fn poseidon_mask_config() -> &'static PoseidonConfig<ark_vesta::Fq> {
        MASK_CONFIG.get_or_init(|| {
            let (ark, mds) = find_poseidon_ark_and_mds::<ark_vesta::Fq>(
                POSEIDON_PRIME_BITS,
                POSEIDON_RATE,
                POSEIDON_FULL_ROUNDS as u64,
                POSEIDON_PARTIAL_ROUNDS as u64,
                POSEIDON_SKIP_MATRICES,
            );
            // NOTE: `PoseidonConfig::new` takes `mds` BEFORE `ark`, which is the
            // reverse of the `(ark, mds)` tuple returned by the generator.
            PoseidonConfig::new(
                POSEIDON_FULL_ROUNDS,
                POSEIDON_PARTIAL_ROUNDS,
                POSEIDON_ALPHA,
                mds,
                ark,
                POSEIDON_RATE,
                POSEIDON_CAPACITY,
            )
        })
    }

    /// Squeeze one mask field element in-circuit from the preimage bytes.
    ///
    /// The same message byte vector assembled for the Blake2b path is absorbed
    /// into a [`PoseidonSpongeVar`]; the single squeezed [`FpVar`] is the mask.
    pub fn poseidon_hash_circuit(
        cs: ConstraintSystemRef<ark_vesta::Fq>,
        message: &[UInt8<ark_vesta::Fq>],
    ) -> Result<FpVar<ark_vesta::Fq>, SynthesisError> {
        let mut sponge = PoseidonSpongeVar::<ark_vesta::Fq>::new(cs, poseidon_mask_config());
        sponge.absorb(&message)?;
        let squeezed = sponge.squeeze_field_elements(1)?;
        squeezed.into_iter().next().ok_or(SynthesisError::Unsatisfiable)
    }

    /// Squeeze one mask field element natively from the preimage bytes.
    ///
    /// `domain`, `shared_point`, and `transcript` are absorbed as one contiguous
    /// byte stream, matching the bytes the gadget absorbs.
    #[must_use]
    pub fn poseidon_hash_native(
        domain: &[u8],
        shared_point: &[u8],
        transcript: &[u8],
    ) -> ark_vesta::Fq {
        let mut message = Vec::with_capacity(domain.len() + shared_point.len() + transcript.len());
        message.extend_from_slice(domain);
        message.extend_from_slice(shared_point);
        message.extend_from_slice(transcript);
        let mut sponge = PoseidonSponge::<ark_vesta::Fq>::new(poseidon_mask_config());
        sponge.absorb(&message.as_slice());
        sponge.squeeze_field_elements(1)[0]
    }

    /// Derive the Poseidon mask scalar from a shared helper-curve point and the
    /// mask transcript.
    ///
    /// This is the native counterpart to the in-circuit Poseidon mask relation
    /// and matches the mask value enforced by [`crate::MaskHashKind::Poseidon`].
    /// It is exposed so benchmark harnesses can build a valid Poseidon witness
    /// without re-deriving the sponge parameters or domain separator.
    #[must_use]
    pub fn poseidon_mask_from_shared(
        shared_point: golden_pallas::VestaPoint,
        transcript: &[u8],
    ) -> golden_pallas::PallasScalar {
        let field = poseidon_hash_native(
            golden_pallas::domains::MASK_TO_FIELD,
            &shared_point.to_bytes(),
            transcript,
        );
        super::ark_fq_to_pallas_scalar(field)
    }
}

const BACKEND: &str = "golden-pallas-proof-skeleton/v7";
const CHALLENGE_DOMAIN: &[u8] = b"GoldenRedPallas/PallasProofChallenge/v0";
const GENERATOR_DOMAIN: &str = "GoldenRedPallas/PallasProofGenerator/v1";
const PROOF_CIRCUIT_DOMAIN: &[u8] = b"GoldenRedPallas/PallasProofCircuitBundle/v0";
const MASK_TRACE_DOMAIN: &[u8] = b"GoldenRedPallas/PallasMaskHashTrace/v0";
const MASK_VARIABLE_GENERATOR_LABEL: &[u8] = b"mask-variable";
const MASK_BLINDING_GENERATOR_LABEL: &[u8] = b"mask-blinding";
const PROOF_MAGIC: &[u8; 4] = b"GPBP";
const PROOF_VERSION: u8 = 7;
const PROOF_HEADER_LEN: usize = 5;
const COMMITMENT_BYTES: usize = 32;
const PROOF_LEN_BYTES: usize = 8;
const SHARED_X_COMMITMENT_OFFSET: usize = PROOF_HEADER_LEN;
const SHARED_Y_COMMITMENT_OFFSET: usize = SHARED_X_COMMITMENT_OFFSET + COMMITMENT_BYTES;
const MASK_CIRCUIT_PROOF_LEN_OFFSET: usize = SHARED_Y_COMMITMENT_OFFSET + COMMITMENT_BYTES;
const CIRCUIT_PROOF_OFFSET: usize = MASK_CIRCUIT_PROOF_LEN_OFFSET + PROOF_LEN_BYTES;
#[cfg(test)]
const MASK_CIRCUIT_COMMITTED_VARS: usize = 3;
const MASK_DIGEST_BYTES: usize = 64;
const BYTE_BITS: usize = 8;
const SHARED_POINT_X_BITS: usize = 255;
const SHARED_POINT_Y_BITS: usize = 255;
const BLAKE2B_BLOCK_BYTES: usize = 128;
const BLAKE2B_PARAM_WORD: u64 = 0x0101_0040;
const BLAKE2B_IV: [u64; 8] = [
    0x6a09_e667_f3bc_c908,
    0xbb67_ae85_84ca_a73b,
    0x3c6e_f372_fe94_f82b,
    0xa54f_f53a_5f1d_36f1,
    0x510e_527f_ade6_82d1,
    0x9b05_688c_2b3e_6c1f,
    0x1f83_d9ab_fb41_bd6b,
    0x5be0_cd19_137e_2179,
];
const BLAKE2B_SIGMA: [[usize; 16]; 12] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
];

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
    /// Build the deterministic trace from private mask witness material.
    #[must_use]
    pub fn from_witness(
        public_inputs: &ProofPublicInputs,
        witness: &ProofWitness,
        hash_kind: MaskHashKind,
    ) -> Self {
        let transcript = public_inputs.mask_transcript();
        let transcript_digest = trace_transcript_digest(&transcript);
        let mut mask_digest = [0_u8; 64];
        let shared_point = witness.shared_point.to_bytes();
        let mask = match hash_kind {
            MaskHashKind::Blake2b => {
                let hash = Params::new()
                    .hash_length(64)
                    .to_state()
                    .update(domains::MASK_TO_FIELD)
                    .update(&shared_point)
                    .update(&transcript)
                    .finalize();
                mask_digest.copy_from_slice(hash.as_bytes());
                PallasScalar::from_uniform_bytes(&mask_digest)
            }
            #[cfg(feature = "poseidon-mask")]
            MaskHashKind::Poseidon => {
                let field = poseidon::poseidon_hash_native(
                    domains::MASK_TO_FIELD,
                    &shared_point,
                    &transcript,
                );
                // Store the squeezed field element in the low 32 bytes of the
                // 64-byte digest slot (high bytes zero) so the existing trace
                // layout is preserved for the Poseidon arm.
                let mask = ark_fq_to_pallas_scalar(field);
                mask_digest[..32].copy_from_slice(&mask.to_bytes());
                mask
            }
        };

        Self {
            shared_point,
            transcript_digest,
            mask_digest,
            mask,
        }
    }

    /// Validate this trace against the public inputs.
    pub fn verify(
        self,
        public_inputs: &ProofPublicInputs,
        hash_kind: MaskHashKind,
    ) -> Result<PallasScalar, ProofError> {
        PallasMaskHashFieldConstraintTrace::from_trace(self).verify(public_inputs, hash_kind)
    }
}

/// Constraint-oriented byte-limb view of the mask hash trace.
///
/// Limbs are represented as `u16` so tests and future parsers can detect
/// out-of-range byte witnesses before lowering them into field constraints.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PallasMaskHashConstraintTrace {
    /// Domain separator bytes for mask hash-to-field.
    pub domain_limbs: Vec<u16>,
    /// Encoded shared Vesta point limbs.
    pub shared_point_limbs: Vec<u16>,
    /// Digest limbs for the DKG mask transcript.
    pub transcript_digest_limbs: Vec<u16>,
    /// Raw 64-byte hash output limbs.
    pub mask_digest_limbs: Vec<u16>,
    /// Canonical Pallas mask encoding limbs.
    pub mask_limbs: Vec<u16>,
}

impl PallasMaskHashConstraintTrace {
    /// Convert a deterministic hash trace into constraint rows.
    #[must_use]
    pub fn from_trace(trace: PallasMaskHashTrace) -> Self {
        Self {
            domain_limbs: bytes_to_limbs(domains::MASK_TO_FIELD),
            shared_point_limbs: bytes_to_limbs(&trace.shared_point),
            transcript_digest_limbs: bytes_to_limbs(&trace.transcript_digest),
            mask_digest_limbs: bytes_to_limbs(&trace.mask_digest),
            mask_limbs: bytes_to_limbs(&trace.mask.to_bytes()),
        }
    }

    /// Validate limb lengths, byte ranges, canonical mask encoding, and trace
    /// consistency against public inputs.
    pub fn verify(
        &self,
        public_inputs: &ProofPublicInputs,
        hash_kind: MaskHashKind,
    ) -> Result<PallasScalar, ProofError> {
        let domain = limbs_to_vec(&self.domain_limbs)?;
        if domain.as_slice() != domains::MASK_TO_FIELD {
            return Err(ProofError::InvalidProof);
        }

        let shared_point = limbs_to_array::<32>(&self.shared_point_limbs)?;
        let transcript_digest = limbs_to_array::<32>(&self.transcript_digest_limbs)?;
        let mask_digest = limbs_to_array::<64>(&self.mask_digest_limbs)?;
        let mask_bytes = limbs_to_array::<32>(&self.mask_limbs)?;
        verify_mask_hash_bytes(
            public_inputs,
            shared_point,
            transcript_digest,
            mask_digest,
            mask_bytes,
            hash_kind,
        )
    }
}

/// Pallas-field view of the mask hash relation constraints.
///
/// Each byte witness is represented as a Pallas scalar and range checked back to
/// one byte before the public mask relation is evaluated.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PallasMaskHashFieldConstraintTrace {
    /// Domain separator field limbs for mask hash-to-field.
    pub domain_limbs: Vec<PallasScalar>,
    /// Encoded shared Vesta point field limbs.
    pub shared_point_limbs: Vec<PallasScalar>,
    /// Digest field limbs for the DKG mask transcript.
    pub transcript_digest_limbs: Vec<PallasScalar>,
    /// Raw 64-byte hash output field limbs.
    pub mask_digest_limbs: Vec<PallasScalar>,
    /// Canonical Pallas mask encoding field limbs.
    pub mask_limbs: Vec<PallasScalar>,
}

impl PallasMaskHashFieldConstraintTrace {
    /// Convert a deterministic hash trace into Pallas-field constraint rows.
    #[must_use]
    pub fn from_trace(trace: PallasMaskHashTrace) -> Self {
        Self {
            domain_limbs: bytes_to_field_limbs(domains::MASK_TO_FIELD),
            shared_point_limbs: bytes_to_field_limbs(&trace.shared_point),
            transcript_digest_limbs: bytes_to_field_limbs(&trace.transcript_digest),
            mask_digest_limbs: bytes_to_field_limbs(&trace.mask_digest),
            mask_limbs: bytes_to_field_limbs(&trace.mask.to_bytes()),
        }
    }

    /// Validate field-limb lengths, byte ranges, canonical mask encoding, and
    /// trace consistency against public inputs.
    pub fn verify(
        &self,
        public_inputs: &ProofPublicInputs,
        hash_kind: MaskHashKind,
    ) -> Result<PallasScalar, ProofError> {
        let domain = field_limbs_to_vec(&self.domain_limbs)?;
        if domain.as_slice() != domains::MASK_TO_FIELD {
            return Err(ProofError::InvalidProof);
        }

        verify_mask_hash_bytes(
            public_inputs,
            field_limbs_to_array::<32>(&self.shared_point_limbs)?,
            field_limbs_to_array::<32>(&self.transcript_digest_limbs)?,
            field_limbs_to_array::<64>(&self.mask_digest_limbs)?,
            field_limbs_to_array::<32>(&self.mask_limbs)?,
            hash_kind,
        )
    }
}

/// Prover-side byte-limb trace for the Vesta Diffie-Hellman relation.
///
/// This trace intentionally contains the dealer helper secret limbs and is not
/// serialized into public proof bytes. It is an intermediate representation for
/// the future zero-knowledge eVRF circuit constraints.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PallasVestaDhConstraintTrace {
    /// Dealer helper secret scalar limbs.
    pub dealer_secret_limbs: Vec<u16>,
    /// Dealer helper public key encoding limbs.
    pub dealer_public_limbs: Vec<u16>,
    /// Participant helper public key encoding limbs.
    pub participant_public_limbs: Vec<u16>,
    /// Shared Vesta point encoding limbs.
    pub shared_point_limbs: Vec<u16>,
}

impl PallasVestaDhConstraintTrace {
    /// Build a prover-side DH trace from public inputs and witness.
    #[must_use]
    pub fn from_witness(public_inputs: &ProofPublicInputs, witness: &ProofWitness) -> Self {
        Self {
            dealer_secret_limbs: bytes_to_limbs(&witness.dealer_secret.to_bytes()),
            dealer_public_limbs: bytes_to_limbs(&public_inputs.dealer_public.point().to_bytes()),
            participant_public_limbs: bytes_to_limbs(
                &public_inputs.participant_public.point().to_bytes(),
            ),
            shared_point_limbs: bytes_to_limbs(&witness.shared_point.to_bytes()),
        }
    }

    /// Validate limb lengths, byte ranges, canonical encodings, and Vesta
    /// scalar-multiplication relations against public inputs.
    pub fn verify(&self, public_inputs: &ProofPublicInputs) -> Result<(), ProofError> {
        verify_vesta_dh_bytes(
            public_inputs,
            limbs_to_array::<32>(&self.dealer_secret_limbs)?,
            limbs_to_array::<32>(&self.dealer_public_limbs)?,
            limbs_to_array::<32>(&self.participant_public_limbs)?,
            limbs_to_array::<32>(&self.shared_point_limbs)?,
        )
    }
}

/// Pallas-field view of the Vesta Diffie-Hellman relation constraints.
///
/// This trace keeps the same private witness shape as
/// [`PallasVestaDhConstraintTrace`] but stores every byte witness as a Pallas
/// scalar limb.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PallasVestaDhFieldConstraintTrace {
    /// Dealer helper secret scalar field limbs.
    pub dealer_secret_limbs: Vec<PallasScalar>,
    /// Dealer helper public key encoding field limbs.
    pub dealer_public_limbs: Vec<PallasScalar>,
    /// Participant helper public key encoding field limbs.
    pub participant_public_limbs: Vec<PallasScalar>,
    /// Shared Vesta point encoding field limbs.
    pub shared_point_limbs: Vec<PallasScalar>,
}

impl PallasVestaDhFieldConstraintTrace {
    /// Build a prover-side Pallas-field DH trace from public inputs and witness.
    #[must_use]
    pub fn from_witness(public_inputs: &ProofPublicInputs, witness: &ProofWitness) -> Self {
        Self {
            dealer_secret_limbs: bytes_to_field_limbs(&witness.dealer_secret.to_bytes()),
            dealer_public_limbs: bytes_to_field_limbs(
                &public_inputs.dealer_public.point().to_bytes(),
            ),
            participant_public_limbs: bytes_to_field_limbs(
                &public_inputs.participant_public.point().to_bytes(),
            ),
            shared_point_limbs: bytes_to_field_limbs(&witness.shared_point.to_bytes()),
        }
    }

    /// Validate field-limb lengths, byte ranges, canonical encodings, and Vesta
    /// scalar-multiplication relations against public inputs.
    pub fn verify(&self, public_inputs: &ProofPublicInputs) -> Result<(), ProofError> {
        verify_vesta_dh_bytes(
            public_inputs,
            field_limbs_to_array::<32>(&self.dealer_secret_limbs)?,
            field_limbs_to_array::<32>(&self.dealer_public_limbs)?,
            field_limbs_to_array::<32>(&self.participant_public_limbs)?,
            field_limbs_to_array::<32>(&self.shared_point_limbs)?,
        )
    }
}

/// Derive a deterministic Pallas point for backend tests.
///
/// This uses Pasta's hash-to-curve random oracle to avoid publishing generators
/// whose discrete logarithms relative to the Orchard basepoint are known.
#[must_use]
pub fn derive_pallas_generator(label: &[u8]) -> PallasPoint {
    PallasPoint::hash_to_curve(GENERATOR_DOMAIN, label)
}

/// Legacy Schnorr-style proof that a mask-variable commitment opens correctly.
///
/// The active backend now uses the Pallas circuit proof envelope instead; this
/// type remains for callers and tests that exercise the older constraint helper
/// boundary.
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
/// This layer checks the executable host-side part of Golden's mask relation:
/// `mask = H(shared_point, transcript)` and
/// `mask_commitment = mask * Pallas::generator()`. It also commits the mask
/// variable against backend-specific Pallas generators for tests and future
/// circuit lowering.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PallasMaskConstraints;

impl PallasMaskConstraints {
    /// Check the public mask relation and return the expected mask.
    pub fn verify_public_relation(
        public_inputs: &ProofPublicInputs,
        mask_trace: PallasMaskHashTrace,
        hash_kind: MaskHashKind,
    ) -> Result<PallasScalar, ProofError> {
        let mask = mask_trace.verify(public_inputs, hash_kind)?;

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
}

/// Feature-gated Pallas proof backend candidate.
///
/// This backend is useful for stabilizing transcript domains, proof framing, and
/// the eVRF R1CS constraints. It validates the same public/witness consistency
/// as the fixture backend and emits randomized opaque circuit proof bytes for
/// the public mask commitment opening. The verifier proves Blake2b mask
/// derivation, shared-point compressed encoding/curve constraints, y-parity
/// sign binding, and the Vesta DH scalar-multiplication relation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PallasProofSkeleton;

/// Circuit-size profile for one side of the Pallas proof backend.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PallasCircuitProfile {
    /// Number of committed witness values.
    pub committed_vars: usize,
    /// Number of left/right/output internal multiplication wires.
    pub internal_vars: usize,
    /// Number of R1CS constraint rows.
    pub constraints: usize,
    /// Number of assignment columns in the circuit layout.
    pub columns: usize,
    /// Internal wire count after power-of-two padding for the IPA layer.
    pub padded_vars: usize,
    /// Base-2 logarithm of `padded_vars`.
    pub ipa_log_len: u8,
}

impl PallasCircuitProfile {
    fn from_circuit(circuit: &PallasCircuit) -> Self {
        let padded_vars = circuit.internal_vars().max(1).next_power_of_two();
        Self {
            committed_vars: circuit.committed_vars(),
            internal_vars: circuit.internal_vars(),
            constraints: circuit.constraint_count(),
            columns: circuit.column_count(),
            padded_vars,
            ipa_log_len: circuit_log_len(circuit),
        }
    }
}

/// Circuit-size profile for the linked mask-hash and Vesta-DH proofs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PallasProofCircuitProfile {
    /// Profile for the mask hash/commitment circuit.
    pub mask: PallasCircuitProfile,
    /// Profile for the Vesta dealer-key and shared-point DH circuit.
    pub vesta_dh: PallasCircuitProfile,
}

impl PallasProofCircuitProfile {
    /// Total R1CS constraint rows across the linked proof circuits.
    #[must_use]
    pub const fn total_constraints(self) -> usize {
        self.mask.constraints + self.vesta_dh.constraints
    }
}

impl PallasProofSkeleton {
    /// Return circuit dimensions for the backend proof statement.
    ///
    /// This synthesizes the verifier-side public circuits but does not create a
    /// witness, derive generators, or produce a proof.
    pub fn circuit_profile(
        public_inputs: &ProofPublicInputs,
        hash_kind: MaskHashKind,
    ) -> Result<PallasProofCircuitProfile, ProofError> {
        let mask_hash = synthesize_mask_hash_r1cs(public_inputs, None, hash_kind)?;
        let mask_circuit = mask_hash
            .r1cs
            .to_circuit(&[
                mask_hash.mask_index,
                mask_hash.shared_x_index,
                mask_hash.shared_y_index,
            ])
            .ok_or(ProofError::InvalidProof)?;
        let dh = synthesize_vesta_dh_r1cs(public_inputs, None)?;
        let dh_circuit = dh
            .r1cs
            .to_circuit(&[dh.shared_x_index, dh.shared_y_index])
            .ok_or(ProofError::InvalidProof)?;

        Ok(PallasProofCircuitProfile {
            mask: PallasCircuitProfile::from_circuit(&mask_circuit),
            vesta_dh: PallasCircuitProfile::from_circuit(&dh_circuit),
        })
    }
}

impl ProofSystem for PallasProofSkeleton {
    fn prove_with_hash(
        public_inputs: &ProofPublicInputs,
        witness: &ProofWitness,
        hash_kind: MaskHashKind,
    ) -> Result<MaskProof, ProofError> {
        validate_witness_with_hash(public_inputs, witness, hash_kind)?;
        let dh_trace = PallasVestaDhFieldConstraintTrace::from_witness(public_inputs, witness);
        dh_trace
            .verify(public_inputs)
            .map_err(|_| ProofError::InvalidWitness)?;
        let mask_trace = PallasMaskHashTrace::from_witness(public_inputs, witness, hash_kind);
        PallasMaskConstraints::verify_public_relation(public_inputs, mask_trace, hash_kind)
            .map_err(|_| ProofError::InvalidWitness)?;
        Ok(MaskProof {
            backend: BACKEND,
            bytes: encode_skeleton_proof(public_inputs, witness, hash_kind)?,
        })
    }

    fn verify_with_hash(
        public_inputs: &ProofPublicInputs,
        proof: &MaskProof,
        hash_kind: MaskHashKind,
    ) -> Result<(), ProofError> {
        if proof.backend != BACKEND {
            return Err(ProofError::BackendMismatch);
        }

        let decoded = decode_skeleton_proof(&proof.bytes)?;
        let (mask_setup, mask_circuit, mask_claim) =
            mask_circuit_claim(public_inputs, decoded.shared_commitments, hash_kind)?;
        decoded
            .mask_circuit_proof
            .verify(&mask_setup, &mask_circuit, &mask_claim)?;
        let (dh_setup, dh_circuit, dh_claim) =
            vesta_dh_circuit_claim(public_inputs, decoded.shared_commitments)?;
        decoded
            .dh_circuit_proof
            .verify(&dh_setup, &dh_circuit, &dh_claim)
    }

    fn verify_batch(items: &[ProofBatchItem<'_>]) -> Result<(), ProofError> {
        for item in items {
            Self::verify(item.public_inputs, item.proof)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SkeletonProof {
    shared_commitments: SharedPointCommitments,
    mask_circuit_proof: PallasCircuitProof,
    dh_circuit_proof: PallasCircuitProof,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SharedPointCommitments {
    x: PallasPoint,
    y: PallasPoint,
}

impl SharedPointCommitments {
    fn as_vec(self) -> Vec<PallasPoint> {
        vec![self.x, self.y]
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SharedPointOpening {
    x: PallasScalar,
    y: PallasScalar,
    x_blinding: PallasScalar,
    y_blinding: PallasScalar,
}

impl SharedPointOpening {
    fn from_witness(
        witness: &ProofWitness,
        x_blinding: PallasScalar,
        y_blinding: PallasScalar,
    ) -> Result<Self, ProofError> {
        let (x, y) = witness
            .shared_point
            .affine_coordinates()
            .ok_or(ProofError::InvalidWitness)?;
        Ok(Self {
            x,
            y,
            x_blinding,
            y_blinding,
        })
    }

    fn commitments(self, setup: &PallasCircuitSetup) -> SharedPointCommitments {
        SharedPointCommitments {
            x: setup.commit_value(self.x, self.x_blinding),
            y: setup.commit_value(self.y, self.y_blinding),
        }
    }
}

fn encode_skeleton_proof(
    public_inputs: &ProofPublicInputs,
    witness: &ProofWitness,
    hash_kind: MaskHashKind,
) -> Result<Vec<u8>, ProofError> {
    let mut rng = OsRng;
    encode_skeleton_proof_with_rng(&mut rng, public_inputs, witness, hash_kind)
}

fn encode_skeleton_proof_with_rng<R: RngCore + CryptoRng>(
    rng: &mut R,
    public_inputs: &ProofPublicInputs,
    witness: &ProofWitness,
    hash_kind: MaskHashKind,
) -> Result<Vec<u8>, ProofError> {
    let shared_opening = SharedPointOpening::from_witness(
        witness,
        random_pallas_scalar(rng),
        random_pallas_scalar(rng),
    )?;

    let (mask_setup, mask_circuit, mask_claim, mask_witness) =
        mask_circuit_witness(public_inputs, witness, shared_opening, hash_kind)?;
    let shared_commitments = shared_opening.commitments(&mask_setup);
    let mask_circuit_proof =
        PallasCircuitProof::prove(rng, &mask_setup, &mask_circuit, &mask_claim, &mask_witness)?;
    let (dh_setup, dh_circuit, dh_claim, dh_witness) =
        vesta_dh_circuit_witness(public_inputs, witness, shared_opening, shared_commitments)?;
    let dh_circuit_proof =
        PallasCircuitProof::prove(rng, &dh_setup, &dh_circuit, &dh_claim, &dh_witness)?;
    let mask_circuit_bytes = mask_circuit_proof.to_bytes();
    let dh_circuit_bytes = dh_circuit_proof.to_bytes();

    let mut bytes = Vec::with_capacity(
        CIRCUIT_PROOF_OFFSET + mask_circuit_bytes.len() + PROOF_LEN_BYTES + dh_circuit_bytes.len(),
    );
    bytes.extend_from_slice(PROOF_MAGIC);
    bytes.push(PROOF_VERSION);
    bytes.extend_from_slice(&shared_commitments.x.to_bytes());
    bytes.extend_from_slice(&shared_commitments.y.to_bytes());
    write_len_prefixed(&mut bytes, &mask_circuit_bytes)?;
    write_len_prefixed(&mut bytes, &dh_circuit_bytes)?;
    Ok(bytes)
}

fn decode_skeleton_proof(bytes: &[u8]) -> Result<SkeletonProof, ProofError> {
    if bytes.len() <= CIRCUIT_PROOF_OFFSET {
        return Err(ProofError::InvalidProof);
    }

    if &bytes[..4] != PROOF_MAGIC || bytes[4] != PROOF_VERSION {
        return Err(ProofError::InvalidProof);
    }

    let mut offset = SHARED_X_COMMITMENT_OFFSET;
    let shared_commitments = SharedPointCommitments {
        x: read_pallas_point(bytes, &mut offset)?,
        y: read_pallas_point(bytes, &mut offset)?,
    };
    let mask_circuit_proof = read_circuit_proof(bytes, &mut offset)?;
    let dh_circuit_proof = read_circuit_proof(bytes, &mut offset)?;
    if offset != bytes.len() {
        return Err(ProofError::InvalidProof);
    }

    Ok(SkeletonProof {
        shared_commitments,
        mask_circuit_proof,
        dh_circuit_proof,
    })
}

fn write_len_prefixed(out: &mut Vec<u8>, payload: &[u8]) -> Result<(), ProofError> {
    let len = u64::try_from(payload.len()).map_err(|_| ProofError::InvalidProof)?;
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(payload);
    Ok(())
}

fn read_circuit_proof(bytes: &[u8], offset: &mut usize) -> Result<PallasCircuitProof, ProofError> {
    let len = usize::try_from(u64::from_le_bytes(read_array(bytes, offset)?))
        .map_err(|_| ProofError::InvalidProof)?;
    let end = offset.checked_add(len).ok_or(ProofError::InvalidProof)?;
    let proof_bytes = bytes.get(*offset..end).ok_or(ProofError::InvalidProof)?;
    *offset = end;
    PallasCircuitProof::from_bytes(proof_bytes)
}

fn read_pallas_point(bytes: &[u8], offset: &mut usize) -> Result<PallasPoint, ProofError> {
    PallasPoint::from_bytes(read_array(bytes, offset)?).ok_or(ProofError::InvalidProof)
}

fn read_array<const N: usize>(bytes: &[u8], offset: &mut usize) -> Result<[u8; N], ProofError> {
    let end = offset.checked_add(N).ok_or(ProofError::InvalidProof)?;
    let slice = bytes.get(*offset..end).ok_or(ProofError::InvalidProof)?;
    *offset = end;
    slice.try_into().map_err(|_| ProofError::InvalidProof)
}

fn mask_circuit_claim(
    public_inputs: &ProofPublicInputs,
    shared_commitments: SharedPointCommitments,
    hash_kind: MaskHashKind,
) -> Result<(PallasCircuitSetup, PallasCircuit, PallasCircuitClaim), ProofError> {
    let mask_hash = synthesize_mask_hash_r1cs(public_inputs, None, hash_kind)?;
    let circuit = mask_hash
        .r1cs
        .to_circuit(&[
            mask_hash.mask_index,
            mask_hash.shared_x_index,
            mask_hash.shared_y_index,
        ])
        .ok_or(ProofError::InvalidProof)?;
    let setup = circuit_setup(&circuit);
    let claim = PallasCircuitClaim {
        commitments: vec![
            public_inputs.mask_commitment,
            shared_commitments.x,
            shared_commitments.y,
        ],
    };
    Ok((setup, circuit, claim))
}

fn mask_circuit_witness(
    public_inputs: &ProofPublicInputs,
    witness: &ProofWitness,
    shared_opening: SharedPointOpening,
    hash_kind: MaskHashKind,
) -> Result<
    (
        PallasCircuitSetup,
        PallasCircuit,
        PallasCircuitClaim,
        PallasCircuitWitness,
    ),
    ProofError,
> {
    let mask_trace = PallasMaskHashTrace::from_witness(public_inputs, witness, hash_kind);
    mask_circuit_witness_from_trace_with_opening(
        public_inputs,
        witness,
        mask_trace,
        shared_opening,
        hash_kind,
    )
}

#[cfg(test)]
fn mask_circuit_witness_from_trace(
    public_inputs: &ProofPublicInputs,
    witness: &ProofWitness,
    mask_trace: PallasMaskHashTrace,
    hash_kind: MaskHashKind,
) -> Result<
    (
        PallasCircuitSetup,
        PallasCircuit,
        PallasCircuitClaim,
        PallasCircuitWitness,
    ),
    ProofError,
> {
    let shared_opening =
        SharedPointOpening::from_witness(witness, PallasScalar::ZERO, PallasScalar::ZERO)
            .expect("test witness shared point is affine");
    mask_circuit_witness_from_trace_with_opening(
        public_inputs,
        witness,
        mask_trace,
        shared_opening,
        hash_kind,
    )
}

fn mask_circuit_witness_from_trace_with_opening(
    public_inputs: &ProofPublicInputs,
    _witness: &ProofWitness,
    mask_trace: PallasMaskHashTrace,
    shared_opening: SharedPointOpening,
    hash_kind: MaskHashKind,
) -> Result<
    (
        PallasCircuitSetup,
        PallasCircuit,
        PallasCircuitClaim,
        PallasCircuitWitness,
    ),
    ProofError,
> {
    let mask_hash = synthesize_mask_hash_r1cs(
        public_inputs,
        Some(MaskHashAssignment {
            mask: mask_trace.mask,
            shared_x: shared_opening.x,
            shared_y: shared_opening.y,
        }),
        hash_kind,
    )?;
    let full_witness = mask_hash.full_witness.ok_or(ProofError::InvalidWitness)?;
    let committed_indices = [
        mask_hash.mask_index,
        mask_hash.shared_x_index,
        mask_hash.shared_y_index,
    ];
    let (circuit, circuit_witness) = mask_hash
        .r1cs
        .to_circuit_with_witness(
            &full_witness,
            &committed_indices,
            vec![
                PallasScalar::ZERO,
                shared_opening.x_blinding,
                shared_opening.y_blinding,
            ],
        )
        .ok_or(ProofError::InvalidWitness)?;
    let setup = circuit_setup(&circuit);
    let shared_commitments = shared_opening.commitments(&setup);
    let claim = PallasCircuitClaim {
        commitments: vec![
            public_inputs.mask_commitment,
            shared_commitments.x,
            shared_commitments.y,
        ],
    };
    Ok((setup, circuit, claim, circuit_witness))
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct MaskHashR1cs {
    r1cs: PallasR1cs,
    full_witness: Option<Vec<PallasScalar>>,
    mask_index: usize,
    shared_x_index: usize,
    shared_y_index: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct MaskHashAssignment {
    mask: PallasScalar,
    shared_x: PallasScalar,
    shared_y: PallasScalar,
}

#[allow(clippy::similar_names)]
fn synthesize_mask_hash_r1cs(
    public_inputs: &ProofPublicInputs,
    assignment: Option<MaskHashAssignment>,
    hash_kind: MaskHashKind,
) -> Result<MaskHashR1cs, ProofError> {
    let cs = ConstraintSystem::<ark_vesta::Fq>::new_ref();
    cs.set_optimization_goal(OptimizationGoal::Constraints);
    cs.set_mode(SynthesisMode::Prove {
        construct_matrices: true,
    });

    let mask_alloc = AllocatedFp::<ark_vesta::Fq>::new_witness(cs.clone(), || {
        Ok(pallas_scalar_to_ark_fq(
            assignment.map_or(PallasScalar::ZERO, |assignment| assignment.mask),
        ))
    })
    .map_err(|_| ProofError::InvalidWitness)?;
    let mask_index = mask_alloc
        .variable
        .get_index_unchecked(cs.num_instance_variables())
        .ok_or(ProofError::InvalidWitness)?;
    let shared_x_alloc = AllocatedFp::<ark_vesta::Fq>::new_witness(cs.clone(), || {
        Ok(pallas_scalar_to_ark_fq(
            assignment.map_or(PallasScalar::ZERO, |assignment| assignment.shared_x),
        ))
    })
    .map_err(|_| ProofError::InvalidWitness)?;
    let shared_x_index = shared_x_alloc
        .variable
        .get_index_unchecked(cs.num_instance_variables())
        .ok_or(ProofError::InvalidWitness)?;
    let shared_y_alloc = AllocatedFp::<ark_vesta::Fq>::new_witness(cs.clone(), || {
        Ok(pallas_scalar_to_ark_fq(
            assignment.map_or(PallasScalar::ZERO, |assignment| assignment.shared_y),
        ))
    })
    .map_err(|_| ProofError::InvalidWitness)?;
    let shared_y_index = shared_y_alloc
        .variable
        .get_index_unchecked(cs.num_instance_variables())
        .ok_or(ProofError::InvalidWitness)?;

    let mask_var = FpVar::from(mask_alloc);
    let shared_x_var = FpVar::from(shared_x_alloc);
    let shared_y_var = FpVar::from(shared_y_alloc);
    enforce_vesta_curve_equation(&shared_x_var, &shared_y_var)
        .map_err(|_| ProofError::InvalidWitness)?;

    let shared_point_bytes = compressed_vesta_point_bytes(&shared_x_var, &shared_y_var)
        .map_err(|_| ProofError::InvalidWitness)?;
    let mut message = UInt8::constant_vec(domains::MASK_TO_FIELD);
    message.extend(shared_point_bytes);
    message.extend(UInt8::constant_vec(&public_inputs.mask_transcript()));
    match hash_kind {
        MaskHashKind::Blake2b => {
            let digest = blake2b_512_circuit(&message).map_err(|_| ProofError::InvalidWitness)?;
            enforce_digest_reduces_to_mask(&digest, &mask_var)
                .map_err(|_| ProofError::InvalidWitness)?;
        }
        #[cfg(feature = "poseidon-mask")]
        MaskHashKind::Poseidon => {
            let squeezed = poseidon::poseidon_hash_circuit(cs.clone(), &message)
                .map_err(|_| ProofError::InvalidWitness)?;
            squeezed
                .enforce_equal(&mask_var)
                .map_err(|_| ProofError::InvalidWitness)?;
        }
    }

    cs.finalize();
    if assignment.is_some() && !cs.is_satisfied().map_err(|_| ProofError::InvalidWitness)? {
        return Err(ProofError::InvalidWitness);
    }

    let matrices = cs.to_matrices().ok_or(ProofError::InvalidProof)?;
    let full_witness = if assignment.is_some() {
        let assignments = cs.borrow().ok_or(ProofError::InvalidWitness)?;
        Some(
            assignments
                .instance_assignment
                .iter()
                .chain(&assignments.witness_assignment)
                .copied()
                .map(ark_fq_to_pallas_scalar)
                .collect(),
        )
    } else {
        None
    };

    Ok(MaskHashR1cs {
        r1cs: constraint_matrices_to_pallas_r1cs(&matrices),
        full_witness,
        mask_index,
        shared_x_index,
        shared_y_index,
    })
}

fn enforce_vesta_curve_equation(
    x: &FpVar<ark_vesta::Fq>,
    y: &FpVar<ark_vesta::Fq>,
) -> Result<(), SynthesisError> {
    let x2 = x.square()?;
    let x3 = &x2 * x;
    let rhs = x3 + FpVar::constant(ark_vesta::Fq::from(5_u64));
    y.square()?.enforce_equal(&rhs)
}

fn compressed_vesta_point_bytes(
    x: &FpVar<ark_vesta::Fq>,
    y: &FpVar<ark_vesta::Fq>,
) -> Result<Vec<UInt8<ark_vesta::Fq>>, SynthesisError> {
    let mut x_bits = x.to_bits_le()?;
    let y_bits = y.to_bits_le()?;
    if x_bits.len() != SHARED_POINT_X_BITS || y_bits.len() != SHARED_POINT_Y_BITS {
        return Err(SynthesisError::Unsatisfiable);
    }
    x_bits.push(y_bits[0].clone());
    Ok(x_bits.chunks(BYTE_BITS).map(UInt8::from_bits_le).collect())
}

fn enforce_digest_reduces_to_mask(
    digest: &[UInt8<ark_vesta::Fq>],
    mask: &FpVar<ark_vesta::Fq>,
) -> Result<(), SynthesisError> {
    let mut accumulator = FpVar::<ark_vesta::Fq>::zero();
    let mut coefficient = ark_vesta::Fq::from(1_u64);
    for bit in digest.to_bits_le()? {
        accumulator += FpVar::from(bit) * coefficient;
        coefficient += coefficient;
    }
    accumulator.enforce_equal(mask)
}

fn blake2b_512_circuit(
    message: &[UInt8<ark_vesta::Fq>],
) -> Result<Vec<UInt8<ark_vesta::Fq>>, SynthesisError> {
    let mut h = BLAKE2B_IV.map(UInt64::<ark_vesta::Fq>::constant);
    h[0] = UInt64::constant(BLAKE2B_IV[0] ^ BLAKE2B_PARAM_WORD);

    let block_count = message.len().div_ceil(BLAKE2B_BLOCK_BYTES).max(1);
    for block_index in 0..block_count {
        let start = block_index * BLAKE2B_BLOCK_BYTES;
        let end = message.len().min(start + BLAKE2B_BLOCK_BYTES);
        let is_last = block_index + 1 == block_count;
        let counter = u64::try_from(end).map_err(|_| SynthesisError::Unsatisfiable)?;
        let mut block = message[start..end].to_vec();
        block.resize(BLAKE2B_BLOCK_BYTES, UInt8::constant(0));
        h = blake2b_compress(&h, &block, counter, is_last)?;
    }

    let mut digest = Vec::with_capacity(MASK_DIGEST_BYTES);
    for word in h {
        digest.extend(word.to_bytes_le()?);
    }
    Ok(digest)
}

fn blake2b_compress(
    chaining_value: &[UInt64<ark_vesta::Fq>; 8],
    block: &[UInt8<ark_vesta::Fq>],
    counter: u64,
    is_last: bool,
) -> Result<[UInt64<ark_vesta::Fq>; 8], SynthesisError> {
    if block.len() != BLAKE2B_BLOCK_BYTES {
        return Err(SynthesisError::Unsatisfiable);
    }

    let mut message_words = Vec::with_capacity(16);
    for chunk in block.chunks(8) {
        message_words.push(UInt64::from_bytes_le(chunk)?);
    }

    let mut v = Vec::with_capacity(16);
    v.extend(chaining_value.iter().cloned());
    v.extend(BLAKE2B_IV.map(UInt64::<ark_vesta::Fq>::constant));
    v[12] = &v[12] ^ counter;
    if is_last {
        v[14] = !v[14].clone();
    }

    for schedule in BLAKE2B_SIGMA {
        blake2b_g(
            &mut v,
            [0, 4, 8, 12],
            &message_words[schedule[0]],
            &message_words[schedule[1]],
        )?;
        blake2b_g(
            &mut v,
            [1, 5, 9, 13],
            &message_words[schedule[2]],
            &message_words[schedule[3]],
        )?;
        blake2b_g(
            &mut v,
            [2, 6, 10, 14],
            &message_words[schedule[4]],
            &message_words[schedule[5]],
        )?;
        blake2b_g(
            &mut v,
            [3, 7, 11, 15],
            &message_words[schedule[6]],
            &message_words[schedule[7]],
        )?;
        blake2b_g(
            &mut v,
            [0, 5, 10, 15],
            &message_words[schedule[8]],
            &message_words[schedule[9]],
        )?;
        blake2b_g(
            &mut v,
            [1, 6, 11, 12],
            &message_words[schedule[10]],
            &message_words[schedule[11]],
        )?;
        blake2b_g(
            &mut v,
            [2, 7, 8, 13],
            &message_words[schedule[12]],
            &message_words[schedule[13]],
        )?;
        blake2b_g(
            &mut v,
            [3, 4, 9, 14],
            &message_words[schedule[14]],
            &message_words[schedule[15]],
        )?;
    }

    Ok(std::array::from_fn(|index| {
        &chaining_value[index] ^ &v[index] ^ &v[index + 8]
    }))
}

fn blake2b_g(
    state: &mut [UInt64<ark_vesta::Fq>],
    [a_index, b_index, c_index, d_index]: [usize; 4],
    message_x: &UInt64<ark_vesta::Fq>,
    message_y: &UInt64<ark_vesta::Fq>,
) -> Result<(), SynthesisError> {
    state[a_index] = UInt64::wrapping_add_many(&[
        state[a_index].clone(),
        state[b_index].clone(),
        message_x.clone(),
    ])?;
    state[d_index] = (&state[d_index] ^ &state[a_index]).rotate_right(32);
    state[c_index] = state[c_index].wrapping_add(&state[d_index]);
    state[b_index] = (&state[b_index] ^ &state[c_index]).rotate_right(24);
    state[a_index] = UInt64::wrapping_add_many(&[
        state[a_index].clone(),
        state[b_index].clone(),
        message_y.clone(),
    ])?;
    state[d_index] = (&state[d_index] ^ &state[a_index]).rotate_right(16);
    state[c_index] = state[c_index].wrapping_add(&state[d_index]);
    state[b_index] = (&state[b_index] ^ &state[c_index]).rotate_right(63);
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct VestaDhR1cs {
    r1cs: PallasR1cs,
    full_witness: Option<Vec<PallasScalar>>,
    shared_x_index: usize,
    shared_y_index: usize,
}

fn vesta_dh_circuit_claim(
    public_inputs: &ProofPublicInputs,
    shared_commitments: SharedPointCommitments,
) -> Result<(PallasCircuitSetup, PallasCircuit, PallasCircuitClaim), ProofError> {
    let dh = synthesize_vesta_dh_r1cs(public_inputs, None)?;
    let circuit = dh
        .r1cs
        .to_circuit(&[dh.shared_x_index, dh.shared_y_index])
        .ok_or(ProofError::InvalidProof)?;
    let setup = circuit_setup(&circuit);
    let claim = PallasCircuitClaim {
        commitments: shared_commitments.as_vec(),
    };
    Ok((setup, circuit, claim))
}

fn vesta_dh_circuit_witness(
    public_inputs: &ProofPublicInputs,
    witness: &ProofWitness,
    shared_opening: SharedPointOpening,
    shared_commitments: SharedPointCommitments,
) -> Result<
    (
        PallasCircuitSetup,
        PallasCircuit,
        PallasCircuitClaim,
        PallasCircuitWitness,
    ),
    ProofError,
> {
    let dh = synthesize_vesta_dh_r1cs(public_inputs, Some(witness))?;
    let full_witness = dh.full_witness.ok_or(ProofError::InvalidWitness)?;
    let (circuit, circuit_witness) = dh
        .r1cs
        .to_circuit_with_witness(
            &full_witness,
            &[dh.shared_x_index, dh.shared_y_index],
            vec![shared_opening.x_blinding, shared_opening.y_blinding],
        )
        .ok_or(ProofError::InvalidWitness)?;
    let setup = circuit_setup(&circuit);
    let claim = PallasCircuitClaim {
        commitments: shared_commitments.as_vec(),
    };
    Ok((setup, circuit, claim, circuit_witness))
}

#[allow(clippy::similar_names, clippy::too_many_lines)]
fn synthesize_vesta_dh_r1cs(
    public_inputs: &ProofPublicInputs,
    witness: Option<&ProofWitness>,
) -> Result<VestaDhR1cs, ProofError> {
    let cs = ConstraintSystem::<ark_vesta::Fq>::new_ref();
    cs.set_optimization_goal(OptimizationGoal::Constraints);
    cs.set_mode(SynthesisMode::Prove {
        construct_matrices: true,
    });

    let secret_bits = witness
        .map_or_else(dummy_vesta_scalar_bits, |witness| {
            vesta_scalar_bits_le(witness.dealer_secret)
        })
        .into_iter()
        .map(|bit| Boolean::new_witness(cs.clone(), || Ok(bit)))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| ProofError::InvalidWitness)?;

    let generator_var = ark_vesta::constraints::GVar::new_variable_omit_on_curve_check(
        cs.clone(),
        || Ok(ark_vesta::Projective::generator()),
        AllocationMode::Constant,
    )
    .map_err(|_| ProofError::InvalidProof)?;
    let dealer_public_var = ark_vesta::constraints::GVar::new_variable_omit_on_curve_check(
        cs.clone(),
        || {
            vesta_point_to_ark(public_inputs.dealer_public.point())
                .map_err(|_| SynthesisError::AssignmentMissing)
        },
        AllocationMode::Constant,
    )
    .map_err(|_| ProofError::InvalidProof)?;
    let participant_public_var = ark_vesta::constraints::GVar::new_variable_omit_on_curve_check(
        cs.clone(),
        || {
            vesta_point_to_ark(public_inputs.participant_public.point())
                .map_err(|_| SynthesisError::AssignmentMissing)
        },
        AllocationMode::Constant,
    )
    .map_err(|_| ProofError::InvalidProof)?;

    let shared_point = witness.map_or_else(
        || public_inputs.participant_public.point(),
        |witness| witness.shared_point,
    );
    let shared_point_var = ark_vesta::constraints::GVar::new_variable_omit_on_curve_check(
        cs.clone(),
        || vesta_point_to_ark(shared_point).map_err(|_| SynthesisError::AssignmentMissing),
        AllocationMode::Witness,
    )
    .map_err(|_| ProofError::InvalidWitness)?;
    let (shared_x, shared_y) = shared_point
        .affine_coordinates()
        .ok_or(ProofError::InvalidWitness)?;
    let shared_x_alloc = AllocatedFp::<ark_vesta::Fq>::new_witness(cs.clone(), || {
        Ok(pallas_scalar_to_ark_fq(shared_x))
    })
    .map_err(|_| ProofError::InvalidWitness)?;
    let shared_x_index = shared_x_alloc
        .variable
        .get_index_unchecked(cs.num_instance_variables())
        .ok_or(ProofError::InvalidWitness)?;
    let shared_y_alloc = AllocatedFp::<ark_vesta::Fq>::new_witness(cs.clone(), || {
        Ok(pallas_scalar_to_ark_fq(shared_y))
    })
    .map_err(|_| ProofError::InvalidWitness)?;
    let shared_y_index = shared_y_alloc
        .variable
        .get_index_unchecked(cs.num_instance_variables())
        .ok_or(ProofError::InvalidWitness)?;
    let shared_x_var = ark_vesta::constraints::FBaseVar::from(shared_x_alloc);
    let shared_y_var = ark_vesta::constraints::FBaseVar::from(shared_y_alloc);

    let dealer_product = generator_var
        .scalar_mul_le(secret_bits.iter())
        .map_err(|_| ProofError::InvalidWitness)?;
    dealer_product
        .enforce_equal(&dealer_public_var)
        .map_err(|_| ProofError::InvalidWitness)?;
    let shared_product = participant_public_var
        .scalar_mul_le(secret_bits.iter())
        .map_err(|_| ProofError::InvalidWitness)?;
    shared_product
        .enforce_equal(&shared_point_var)
        .map_err(|_| ProofError::InvalidWitness)?;
    shared_point_var
        .z
        .enforce_equal(&ark_vesta::constraints::FBaseVar::one())
        .map_err(|_| ProofError::InvalidWitness)?;
    shared_point_var
        .x
        .enforce_equal(&shared_x_var)
        .map_err(|_| ProofError::InvalidWitness)?;
    shared_point_var
        .y
        .enforce_equal(&shared_y_var)
        .map_err(|_| ProofError::InvalidWitness)?;

    cs.finalize();
    if witness.is_some() && !cs.is_satisfied().map_err(|_| ProofError::InvalidWitness)? {
        return Err(ProofError::InvalidWitness);
    }

    let matrices = cs.to_matrices().ok_or(ProofError::InvalidProof)?;
    let full_witness = if witness.is_some() {
        let assignments = cs.borrow().ok_or(ProofError::InvalidWitness)?;
        Some(
            assignments
                .instance_assignment
                .iter()
                .chain(&assignments.witness_assignment)
                .copied()
                .map(ark_fq_to_pallas_scalar)
                .collect(),
        )
    } else {
        None
    };

    Ok(VestaDhR1cs {
        r1cs: constraint_matrices_to_pallas_r1cs(&matrices),
        full_witness,
        shared_x_index,
        shared_y_index,
    })
}

fn constraint_matrices_to_pallas_r1cs(matrices: &ConstraintMatrices<ark_vesta::Fq>) -> PallasR1cs {
    let width = matrices.num_instance_variables + matrices.num_witness_variables;
    let height = matrices.num_constraints;
    PallasR1cs {
        a: ark_matrix_to_pallas_sparse(&matrices.a, width, height),
        b: ark_matrix_to_pallas_sparse(&matrices.b, width, height),
        c: ark_matrix_to_pallas_sparse(&matrices.c, width, height),
    }
}

fn ark_matrix_to_pallas_sparse(
    matrix: &[Vec<(ark_vesta::Fq, usize)>],
    width: usize,
    height: usize,
) -> PallasSparseMatrix {
    let mut sparse = PallasSparseMatrix::with_dimensions(width, height);
    for (row, terms) in matrix.iter().enumerate() {
        for &(coefficient, column) in terms {
            sparse[(row, column)] += ark_fq_to_pallas_scalar(coefficient);
        }
    }
    sparse
}

fn vesta_scalar_bits_le(scalar: VestaScalar) -> Vec<bool> {
    vesta_scalar_to_ark_fr(scalar).into_bigint().to_bits_le()
}

fn dummy_vesta_scalar_bits() -> Vec<bool> {
    ark_vesta::Fr::zero().into_bigint().to_bits_le()
}

fn pallas_scalar_to_ark_fq(scalar: PallasScalar) -> ark_vesta::Fq {
    ark_vesta::Fq::from_le_bytes_mod_order(&scalar.to_bytes())
}

fn vesta_scalar_to_ark_fr(scalar: VestaScalar) -> ark_vesta::Fr {
    ark_vesta::Fr::from_le_bytes_mod_order(&scalar.to_bytes())
}

pub(crate) fn ark_fq_to_pallas_scalar(field: ark_vesta::Fq) -> PallasScalar {
    let mut bytes = field.into_bigint().to_bytes_le();
    bytes.resize(32, 0);
    PallasScalar::from_bytes(bytes.try_into().expect("resized field bytes are 32 bytes"))
        .expect("ark-vesta Fq is the Pallas scalar field")
}

fn vesta_point_to_ark(point: VestaPoint) -> Result<ark_vesta::Projective, ProofError> {
    if point == VestaPoint::identity() {
        return Ok(ark_vesta::Projective::zero());
    }

    let (x, y) = point.affine_coordinates().ok_or(ProofError::InvalidProof)?;
    Ok(
        ark_vesta::Affine::new_unchecked(pallas_scalar_to_ark_fq(x), pallas_scalar_to_ark_fq(y))
            .into_group(),
    )
}

fn circuit_setup(circuit: &PallasCircuit) -> PallasCircuitSetup {
    PallasCircuitSetup::deterministic(
        PROOF_CIRCUIT_DOMAIN,
        circuit_log_len(circuit),
        PallasPoint::generator(),
    )
}

fn circuit_log_len(circuit: &PallasCircuit) -> u8 {
    let padded_vars = circuit.internal_vars().max(1).next_power_of_two();
    u8::try_from(padded_vars.trailing_zeros()).expect("circuit length log fits in u8")
}

fn random_pallas_scalar(rng: &mut impl RngCore) -> PallasScalar {
    let mut bytes = [0_u8; 64];
    rng.fill_bytes(&mut bytes);
    PallasScalar::from_uniform_bytes(&bytes)
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

fn bytes_to_limbs(bytes: &[u8]) -> Vec<u16> {
    bytes.iter().map(|byte| u16::from(*byte)).collect()
}

fn bytes_to_field_limbs(bytes: &[u8]) -> Vec<PallasScalar> {
    bytes
        .iter()
        .map(|byte| PallasScalar::from_u64(u64::from(*byte)))
        .collect()
}

fn limbs_to_vec(limbs: &[u16]) -> Result<Vec<u8>, ProofError> {
    limbs
        .iter()
        .map(|limb| u8::try_from(*limb).map_err(|_| ProofError::InvalidProof))
        .collect()
}

fn limbs_to_array<const N: usize>(limbs: &[u16]) -> Result<[u8; N], ProofError> {
    if limbs.len() != N {
        return Err(ProofError::InvalidProof);
    }

    let mut bytes = [0_u8; N];
    for (index, limb) in limbs.iter().enumerate() {
        bytes[index] = u8::try_from(*limb).map_err(|_| ProofError::InvalidProof)?;
    }
    Ok(bytes)
}

fn field_limbs_to_vec(limbs: &[PallasScalar]) -> Result<Vec<u8>, ProofError> {
    limbs.iter().map(|limb| field_limb_to_byte(*limb)).collect()
}

fn field_limbs_to_array<const N: usize>(limbs: &[PallasScalar]) -> Result<[u8; N], ProofError> {
    if limbs.len() != N {
        return Err(ProofError::InvalidProof);
    }

    let mut bytes = [0_u8; N];
    for (index, limb) in limbs.iter().enumerate() {
        bytes[index] = field_limb_to_byte(*limb)?;
    }
    Ok(bytes)
}

fn field_limb_to_byte(limb: PallasScalar) -> Result<u8, ProofError> {
    for byte in u8::MIN..=u8::MAX {
        if limb == PallasScalar::from_u64(u64::from(byte)) {
            return Ok(byte);
        }
    }
    Err(ProofError::InvalidProof)
}

fn verify_mask_hash_bytes(
    public_inputs: &ProofPublicInputs,
    shared_point: [u8; 32],
    transcript_digest: [u8; 32],
    mask_digest: [u8; 64],
    mask_bytes: [u8; 32],
    hash_kind: MaskHashKind,
) -> Result<PallasScalar, ProofError> {
    let mask = PallasScalar::from_bytes(mask_bytes).ok_or(ProofError::InvalidProof)?;
    let transcript = public_inputs.mask_transcript();
    if transcript_digest != trace_transcript_digest(&transcript) {
        return Err(ProofError::InvalidProof);
    }

    match hash_kind {
        MaskHashKind::Blake2b => {
            let mut expected_digest = [0_u8; 64];
            let hash = Params::new()
                .hash_length(64)
                .to_state()
                .update(domains::MASK_TO_FIELD)
                .update(&shared_point)
                .update(&transcript)
                .finalize();
            expected_digest.copy_from_slice(hash.as_bytes());
            if mask_digest != expected_digest {
                return Err(ProofError::InvalidProof);
            }

            let reduced_mask = PallasScalar::from_uniform_bytes(&mask_digest);
            if mask != reduced_mask {
                return Err(ProofError::InvalidProof);
            }

            Ok(reduced_mask)
        }
        #[cfg(feature = "poseidon-mask")]
        MaskHashKind::Poseidon => {
            // Poseidon outputs a field element directly. Recompute it and
            // compare field values; the mask_digest slot holds the field bytes
            // in its low 32 bytes (high 32 zero).
            let field =
                poseidon::poseidon_hash_native(domains::MASK_TO_FIELD, &shared_point, &transcript);
            let expected_mask = ark_fq_to_pallas_scalar(field);
            if mask != expected_mask {
                return Err(ProofError::InvalidProof);
            }
            let mut expected_digest = [0_u8; 64];
            expected_digest[..32].copy_from_slice(&expected_mask.to_bytes());
            if mask_digest != expected_digest {
                return Err(ProofError::InvalidProof);
            }
            Ok(expected_mask)
        }
    }
}

fn verify_vesta_dh_bytes(
    public_inputs: &ProofPublicInputs,
    dealer_secret: [u8; 32],
    dealer_public: [u8; 32],
    participant_public: [u8; 32],
    shared_point: [u8; 32],
) -> Result<(), ProofError> {
    let dealer_secret = VestaScalar::from_bytes(dealer_secret).ok_or(ProofError::InvalidProof)?;
    let dealer_public = VestaPoint::from_bytes(dealer_public).ok_or(ProofError::InvalidProof)?;
    let participant_public =
        VestaPoint::from_bytes(participant_public).ok_or(ProofError::InvalidProof)?;
    let shared_point = VestaPoint::from_bytes(shared_point).ok_or(ProofError::InvalidProof)?;

    if dealer_public != public_inputs.dealer_public.point()
        || participant_public != public_inputs.participant_public.point()
    {
        return Err(ProofError::InvalidProof);
    }

    if VestaPoint::generator_mul(dealer_secret) != dealer_public {
        return Err(ProofError::InvalidProof);
    }

    if participant_public.mul_scalar(dealer_secret) != shared_point {
        return Err(ProofError::InvalidProof);
    }

    Ok(())
}

fn update_public_inputs(state: &mut State, public_inputs: &ProofPublicInputs) {
    state.update(&public_inputs.mask_transcript());
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
        HelperPublicKey, HelperSecretKey, PallasPoint, PallasScalar, SharedSecret, VestaPoint,
        VestaScalar, commit_polynomial, derive_mask,
    };
    use rand_core::{CryptoRng, Error, RngCore};

    use super::{
        CIRCUIT_PROOF_OFFSET, MASK_CIRCUIT_COMMITTED_VARS, MASK_CIRCUIT_PROOF_LEN_OFFSET,
        PROOF_LEN_BYTES, PallasMaskConstraints, PallasMaskHashConstraintTrace,
        PallasMaskHashFieldConstraintTrace, PallasMaskHashTrace, PallasProofSkeleton,
        PallasProofTranscript, PallasVestaDhConstraintTrace, PallasVestaDhFieldConstraintTrace,
        SHARED_X_COMMITMENT_OFFSET, SharedPointCommitments, SharedPointOpening,
        decode_skeleton_proof, derive_pallas_generator, encode_skeleton_proof_with_rng,
        mask_circuit_claim, mask_circuit_witness, mask_circuit_witness_from_trace,
        vesta_dh_circuit_claim, vesta_dh_circuit_witness,
    };
    use crate::{
        MaskHashKind, MaskProof, ProofBatchItem, ProofError, ProofPublicInputs, ProofSystem,
        ProofWitness,
    };

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
        let shared_point = dealer_secret.diffie_hellman(participant_secret.public_key());
        let mask = derive_mask(shared_point, &{
            let inputs = ProofPublicInputs {
                session_id: b"pallas-proof-session".to_vec(),
                dealer_id: id(10),
                participant_id: id(1),
                dealer_public: dealer_secret.public_key(),
                participant_public: participant_secret.public_key(),
                mask_commitment: PallasPoint::identity(),
                public_polynomial: public_polynomial.clone(),
            };
            inputs.mask_transcript()
        });
        let public_inputs = ProofPublicInputs {
            session_id: b"pallas-proof-session".to_vec(),
            dealer_id: id(10),
            participant_id: id(1),
            dealer_public: dealer_secret.public_key(),
            participant_public: participant_secret.public_key(),
            mask_commitment: PallasPoint::generator_mul(mask),
            public_polynomial,
        };
        let witness = ProofWitness {
            dealer_secret: dealer_secret.scalar(),
            shared_point: shared_point.point(),
            mask,
        };
        (public_inputs, witness)
    }

    fn refresh_mask(public_inputs: &mut ProofPublicInputs, witness: &mut ProofWitness) {
        let mask = derive_mask(
            SharedSecret::from_point(witness.shared_point),
            &public_inputs.mask_transcript(),
        );
        witness.mask = mask;
        public_inputs.mask_commitment = PallasPoint::generator_mul(mask);
    }

    fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
        haystack
            .windows(needle.len())
            .any(|window| window == needle)
    }

    #[test]
    fn backend_version_tracks_universal_circuit_setup() {
        assert_eq!(super::BACKEND, "golden-pallas-proof-skeleton/v7");
        assert_eq!(super::PROOF_VERSION, 7);
    }

    #[test]
    fn circuit_setup_is_reusable_across_same_shape_public_inputs() {
        let (first_inputs, _) = valid_case();
        let (mut second_inputs, mut second_witness) = valid_case();
        second_inputs.participant_id = id(2);
        refresh_mask(&mut second_inputs, &mut second_witness);
        let shared_commitments = SharedPointCommitments {
            x: PallasPoint::generator_mul(PallasScalar::from_u64(101)),
            y: PallasPoint::generator_mul(PallasScalar::from_u64(103)),
        };

        let (first_mask_setup, first_mask_circuit, _) =
            mask_circuit_claim(&first_inputs, shared_commitments, MaskHashKind::default()).expect("first mask claim");
        let (second_mask_setup, second_mask_circuit, _) =
            mask_circuit_claim(&second_inputs, shared_commitments, MaskHashKind::default()).expect("second mask claim");
        assert_eq!(
            first_mask_circuit.internal_vars(),
            second_mask_circuit.internal_vars()
        );
        assert_eq!(first_mask_setup, second_mask_setup);

        let (first_dh_setup, first_dh_circuit, _) =
            vesta_dh_circuit_claim(&first_inputs, shared_commitments).expect("first dh claim");
        let (second_dh_setup, second_dh_circuit, _) =
            vesta_dh_circuit_claim(&second_inputs, shared_commitments).expect("second dh claim");
        assert_eq!(
            first_dh_circuit.internal_vars(),
            second_dh_circuit.internal_vars()
        );
        assert_eq!(first_dh_setup, second_dh_setup);
    }

    #[test]
    fn backend_reports_circuit_profile_for_audit_artifacts() {
        let (public_inputs, _) = valid_case();
        let profile = PallasProofSkeleton::circuit_profile(&public_inputs, MaskHashKind::default()).expect("profile");

        assert_eq!(profile.mask.committed_vars, 3);
        assert_eq!(profile.vesta_dh.committed_vars, 2);
        assert!(profile.mask.constraints > profile.vesta_dh.constraints);
        assert!(profile.mask.internal_vars > 0);
        assert!(profile.vesta_dh.internal_vars > 0);
        assert_eq!(
            profile.total_constraints(),
            profile.mask.constraints + profile.vesta_dh.constraints
        );
    }

    struct TestRng(u64);

    impl RngCore for TestRng {
        fn next_u32(&mut self) -> u32 {
            let bytes = self.next_u64().to_le_bytes();
            u32::from_le_bytes(bytes[..4].try_into().expect("slice has four bytes"))
        }

        fn next_u64(&mut self) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1);
            self.0
        }

        fn fill_bytes(&mut self, dest: &mut [u8]) {
            for chunk in dest.chunks_mut(8) {
                let bytes = self.next_u64().to_le_bytes();
                chunk.copy_from_slice(&bytes[..chunk.len()]);
            }
        }

        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }

    impl CryptoRng for TestRng {}

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
    fn derived_generators_do_not_use_hash_to_scalar_basepoint_multiples() {
        let label = b"commitment-g";
        let mut state = blake2b_simd::Params::new().hash_length(64).to_state();
        state.update(super::GENERATOR_DOMAIN.as_bytes());
        super::update_len_prefixed(&mut state, label);
        let hash = state.finalize();
        let mut uniform = [0_u8; 64];
        uniform.copy_from_slice(hash.as_bytes());
        let hash_to_scalar_generator =
            PallasPoint::generator_mul(PallasScalar::from_uniform_bytes(&uniform));

        assert_ne!(derive_pallas_generator(label), hash_to_scalar_generator);
    }

    #[test]
    fn mask_constraints_accept_valid_public_relation() {
        let (public_inputs, witness) = valid_case();
        let mask_trace = PallasMaskHashTrace::from_witness(&public_inputs, &witness, MaskHashKind::default());

        assert_eq!(
            PallasMaskConstraints::verify_public_relation(&public_inputs, mask_trace, MaskHashKind::default()),
            Ok(witness.mask)
        );
    }

    #[test]
    fn mask_hash_trace_accepts_valid_trace() {
        let (public_inputs, witness) = valid_case();
        let mask_trace = PallasMaskHashTrace::from_witness(&public_inputs, &witness, MaskHashKind::default());

        assert_eq!(mask_trace.verify(&public_inputs, MaskHashKind::default()), Ok(witness.mask));
    }

    #[test]
    fn mask_hash_constraint_trace_accepts_valid_limbs() {
        let (public_inputs, witness) = valid_case();
        let mask_trace = PallasMaskHashTrace::from_witness(&public_inputs, &witness, MaskHashKind::default());
        let constraint_trace = PallasMaskHashConstraintTrace::from_trace(mask_trace);

        assert_eq!(constraint_trace.verify(&public_inputs, MaskHashKind::default()), Ok(witness.mask));
    }

    #[test]
    fn mask_hash_constraint_trace_rejects_malformed_limb_length() {
        let (public_inputs, witness) = valid_case();
        let mask_trace = PallasMaskHashTrace::from_witness(&public_inputs, &witness, MaskHashKind::default());
        let mut constraint_trace = PallasMaskHashConstraintTrace::from_trace(mask_trace);
        constraint_trace.mask_digest_limbs.pop();

        assert_eq!(
            constraint_trace.verify(&public_inputs, MaskHashKind::default()),
            Err(ProofError::InvalidProof)
        );
    }

    #[test]
    fn mask_hash_constraint_trace_rejects_out_of_range_limb() {
        let (public_inputs, witness) = valid_case();
        let mask_trace = PallasMaskHashTrace::from_witness(&public_inputs, &witness, MaskHashKind::default());
        let mut constraint_trace = PallasMaskHashConstraintTrace::from_trace(mask_trace);
        constraint_trace.mask_digest_limbs[0] = 256;

        assert_eq!(
            constraint_trace.verify(&public_inputs, MaskHashKind::default()),
            Err(ProofError::InvalidProof)
        );
    }

    #[test]
    fn mask_hash_constraint_trace_rejects_non_canonical_mask_encoding() {
        let (public_inputs, witness) = valid_case();
        let mask_trace = PallasMaskHashTrace::from_witness(&public_inputs, &witness, MaskHashKind::default());
        let mut constraint_trace = PallasMaskHashConstraintTrace::from_trace(mask_trace);
        constraint_trace.mask_limbs = vec![255; 32];

        assert_eq!(
            constraint_trace.verify(&public_inputs, MaskHashKind::default()),
            Err(ProofError::InvalidProof)
        );
    }

    #[test]
    fn mask_hash_constraint_trace_rejects_altered_digest_limb() {
        let (public_inputs, witness) = valid_case();
        let mask_trace = PallasMaskHashTrace::from_witness(&public_inputs, &witness, MaskHashKind::default());
        let mut constraint_trace = PallasMaskHashConstraintTrace::from_trace(mask_trace);
        constraint_trace.mask_digest_limbs[0] ^= 1;

        assert_eq!(
            constraint_trace.verify(&public_inputs, MaskHashKind::default()),
            Err(ProofError::InvalidProof)
        );
    }

    #[test]
    fn mask_hash_field_constraint_trace_accepts_valid_limbs() {
        let (public_inputs, witness) = valid_case();
        let mask_trace = PallasMaskHashTrace::from_witness(&public_inputs, &witness, MaskHashKind::default());
        let constraint_trace = PallasMaskHashFieldConstraintTrace::from_trace(mask_trace);

        assert_eq!(constraint_trace.verify(&public_inputs, MaskHashKind::default()), Ok(witness.mask));
    }

    #[test]
    fn mask_hash_field_constraint_trace_rejects_out_of_range_limb() {
        let (public_inputs, witness) = valid_case();
        let mask_trace = PallasMaskHashTrace::from_witness(&public_inputs, &witness, MaskHashKind::default());
        let mut constraint_trace = PallasMaskHashFieldConstraintTrace::from_trace(mask_trace);
        constraint_trace.mask_digest_limbs[0] = PallasScalar::from_u64(256);

        assert_eq!(
            constraint_trace.verify(&public_inputs, MaskHashKind::default()),
            Err(ProofError::InvalidProof)
        );
    }

    #[test]
    fn vesta_dh_constraint_trace_accepts_valid_trace() {
        let (public_inputs, witness) = valid_case();
        let dh_trace = PallasVestaDhConstraintTrace::from_witness(&public_inputs, &witness);

        assert_eq!(dh_trace.verify(&public_inputs), Ok(()));
    }

    #[test]
    fn vesta_dh_constraint_trace_rejects_malformed_secret_length() {
        let (public_inputs, witness) = valid_case();
        let mut dh_trace = PallasVestaDhConstraintTrace::from_witness(&public_inputs, &witness);
        dh_trace.dealer_secret_limbs.pop();

        assert_eq!(
            dh_trace.verify(&public_inputs),
            Err(ProofError::InvalidProof)
        );
    }

    #[test]
    fn vesta_dh_constraint_trace_rejects_out_of_range_point_limb() {
        let (public_inputs, witness) = valid_case();
        let mut dh_trace = PallasVestaDhConstraintTrace::from_witness(&public_inputs, &witness);
        dh_trace.dealer_public_limbs[0] = 256;

        assert_eq!(
            dh_trace.verify(&public_inputs),
            Err(ProofError::InvalidProof)
        );
    }

    #[test]
    fn vesta_dh_constraint_trace_rejects_non_canonical_secret() {
        let (public_inputs, witness) = valid_case();
        let mut dh_trace = PallasVestaDhConstraintTrace::from_witness(&public_inputs, &witness);
        dh_trace.dealer_secret_limbs = vec![255; 32];

        assert_eq!(
            dh_trace.verify(&public_inputs),
            Err(ProofError::InvalidProof)
        );
    }

    #[test]
    fn vesta_dh_constraint_trace_rejects_wrong_dealer_public() {
        let (public_inputs, witness) = valid_case();
        let mut dh_trace = PallasVestaDhConstraintTrace::from_witness(&public_inputs, &witness);
        dh_trace.dealer_public_limbs =
            super::bytes_to_limbs(&VestaPoint::generator_mul(VestaScalar::from_u64(99)).to_bytes());

        assert_eq!(
            dh_trace.verify(&public_inputs),
            Err(ProofError::InvalidProof)
        );
    }

    #[test]
    fn vesta_dh_constraint_trace_rejects_wrong_shared_point() {
        let (public_inputs, witness) = valid_case();
        let mut dh_trace = PallasVestaDhConstraintTrace::from_witness(&public_inputs, &witness);
        dh_trace.shared_point_limbs =
            super::bytes_to_limbs(&VestaPoint::generator_mul(VestaScalar::from_u64(99)).to_bytes());

        assert_eq!(
            dh_trace.verify(&public_inputs),
            Err(ProofError::InvalidProof)
        );
    }

    #[test]
    fn vesta_dh_field_constraint_trace_accepts_valid_trace() {
        let (public_inputs, witness) = valid_case();
        let dh_trace = PallasVestaDhFieldConstraintTrace::from_witness(&public_inputs, &witness);

        assert_eq!(dh_trace.verify(&public_inputs), Ok(()));
    }

    #[test]
    fn vesta_dh_field_constraint_trace_rejects_wrong_shared_point() {
        let (public_inputs, witness) = valid_case();
        let mut dh_trace =
            PallasVestaDhFieldConstraintTrace::from_witness(&public_inputs, &witness);
        dh_trace.shared_point_limbs = super::bytes_to_field_limbs(
            &VestaPoint::generator_mul(VestaScalar::from_u64(99)).to_bytes(),
        );

        assert_eq!(
            dh_trace.verify(&public_inputs),
            Err(ProofError::InvalidProof)
        );
    }

    #[test]
    fn mask_hash_trace_rejects_wrong_shared_point() {
        let (public_inputs, witness) = valid_case();
        let mut mask_trace = PallasMaskHashTrace::from_witness(&public_inputs, &witness, MaskHashKind::default());
        mask_trace.shared_point[0] ^= 1;

        assert_eq!(
            mask_trace.verify(&public_inputs, MaskHashKind::default()),
            Err(ProofError::InvalidProof)
        );
    }

    #[test]
    fn mask_hash_trace_rejects_wrong_transcript_digest() {
        let (public_inputs, witness) = valid_case();
        let mut mask_trace = PallasMaskHashTrace::from_witness(&public_inputs, &witness, MaskHashKind::default());
        mask_trace.transcript_digest[0] ^= 1;

        assert_eq!(
            mask_trace.verify(&public_inputs, MaskHashKind::default()),
            Err(ProofError::InvalidProof)
        );
    }

    #[test]
    fn mask_hash_trace_rejects_wrong_mask_digest() {
        let (public_inputs, witness) = valid_case();
        let mut mask_trace = PallasMaskHashTrace::from_witness(&public_inputs, &witness, MaskHashKind::default());
        mask_trace.mask_digest[0] ^= 1;

        assert_eq!(
            mask_trace.verify(&public_inputs, MaskHashKind::default()),
            Err(ProofError::InvalidProof)
        );
    }

    #[test]
    fn mask_hash_trace_rejects_wrong_mask() {
        let (public_inputs, witness) = valid_case();
        let mut mask_trace = PallasMaskHashTrace::from_witness(&public_inputs, &witness, MaskHashKind::default());
        mask_trace.mask += PallasScalar::ONE;

        assert_eq!(
            mask_trace.verify(&public_inputs, MaskHashKind::default()),
            Err(ProofError::InvalidProof)
        );
    }

    #[test]
    fn mask_constraints_reject_wrong_trace_mask() {
        let (public_inputs, witness) = valid_case();
        let mut mask_trace = PallasMaskHashTrace::from_witness(&public_inputs, &witness, MaskHashKind::default());
        mask_trace.mask += PallasScalar::ONE;

        assert_eq!(
            PallasMaskConstraints::verify_public_relation(&public_inputs, mask_trace, MaskHashKind::default()),
            Err(ProofError::InvalidProof)
        );
    }

    #[test]
    fn mask_constraints_reject_wrong_public_mask_commitment() {
        let (mut public_inputs, witness) = valid_case();
        public_inputs.mask_commitment += PallasPoint::generator();
        let mask_trace = PallasMaskHashTrace::from_witness(&public_inputs, &witness, MaskHashKind::default());

        assert_eq!(
            PallasMaskConstraints::verify_public_relation(&public_inputs, mask_trace, MaskHashKind::default()),
            Err(ProofError::InvalidProof)
        );
    }

    #[test]
    fn mask_constraint_commitment_is_blinding_sensitive() {
        let (_, witness) = valid_case();

        assert_ne!(
            PallasMaskConstraints::commit_mask(witness.mask, PallasScalar::from_u64(1)),
            PallasMaskConstraints::commit_mask(witness.mask, PallasScalar::from_u64(2))
        );
    }

    #[test]
    fn mask_circuit_enforces_hash_digest_reduction_to_mask() {
        let (public_inputs, witness) = valid_case();
        let mask_trace = PallasMaskHashTrace::from_witness(&public_inputs, &witness, MaskHashKind::default());
        let (_, circuit, claim, circuit_witness) =
            mask_circuit_witness_from_trace(&public_inputs, &witness, mask_trace, MaskHashKind::default())
                .expect("valid mask circuit witness");

        assert_eq!(circuit.committed_vars(), MASK_CIRCUIT_COMMITTED_VARS);
        assert!(circuit.internal_vars() > 0);
        assert_eq!(claim.commitments[0], public_inputs.mask_commitment);
        assert_eq!(claim.commitments.len(), MASK_CIRCUIT_COMMITTED_VARS);
        assert!(circuit_witness.is_satisfied(&circuit));

        let mut tampered_trace = mask_trace;
        tampered_trace.mask += PallasScalar::ONE;

        assert!(mask_circuit_witness_from_trace(&public_inputs, &witness, tampered_trace, MaskHashKind::default()).is_err());
    }

    #[test]
    fn mask_circuit_enforces_blake2b_digest_generation() {
        let (mut public_inputs, mut witness) = valid_case();
        let mut mask_trace = PallasMaskHashTrace::from_witness(&public_inputs, &witness, MaskHashKind::default());
        mask_trace.mask_digest[0] ^= 1;
        let wrong_mask = PallasScalar::from_uniform_bytes(&mask_trace.mask_digest);
        mask_trace.mask = wrong_mask;
        witness.mask = wrong_mask;
        public_inputs.mask_commitment = PallasPoint::generator_mul(wrong_mask);

        assert!(mask_circuit_witness_from_trace(&public_inputs, &witness, mask_trace, MaskHashKind::default()).is_err());
    }

    #[test]
    fn vesta_dh_circuit_enforces_dealer_and_shared_scalar_mul() {
        let (public_inputs, witness) = valid_case();
        let shared_opening =
            SharedPointOpening::from_witness(&witness, PallasScalar::ZERO, PallasScalar::ZERO)
                .expect("affine shared point");
        let (mask_setup, _, _, _) = mask_circuit_witness(&public_inputs, &witness, shared_opening, MaskHashKind::default())
            .expect("valid mask circuit witness");
        let shared_commitments = shared_opening.commitments(&mask_setup);
        let (_, circuit, _, circuit_witness) =
            vesta_dh_circuit_witness(&public_inputs, &witness, shared_opening, shared_commitments)
                .expect("valid DH circuit witness");

        assert!(circuit_witness.is_satisfied(&circuit));

        let mut wrong_witness = witness;
        wrong_witness.shared_point = VestaPoint::generator_mul(VestaScalar::from_u64(99));
        let wrong_opening = SharedPointOpening::from_witness(
            &wrong_witness,
            PallasScalar::ZERO,
            PallasScalar::ZERO,
        )
        .expect("affine wrong point");
        let wrong_commitments = wrong_opening.commitments(&mask_setup);

        assert!(
            vesta_dh_circuit_witness(
                &public_inputs,
                &wrong_witness,
                wrong_opening,
                wrong_commitments,
            )
            .is_err()
        );
    }

    #[test]
    fn mask_circuit_enforces_shared_point_x_encoding_and_curve_equation() {
        let (public_inputs, witness) = valid_case();
        let mask_trace = PallasMaskHashTrace::from_witness(&public_inputs, &witness, MaskHashKind::default());
        let (_, circuit, _, circuit_witness) =
            mask_circuit_witness_from_trace(&public_inputs, &witness, mask_trace, MaskHashKind::default())
                .expect("valid mask circuit witness");

        assert!(circuit_witness.is_satisfied(&circuit));

        let mut wrong_witness = witness;
        wrong_witness.shared_point = VestaPoint::generator_mul(VestaScalar::from_u64(99));

        assert!(
            mask_circuit_witness_from_trace(&public_inputs, &wrong_witness, mask_trace, MaskHashKind::default()).is_err()
        );
    }

    #[test]
    fn mask_circuit_enforces_shared_point_compressed_sign_bit() {
        let (public_inputs, witness) = valid_case();
        let mask_trace = PallasMaskHashTrace::from_witness(&public_inputs, &witness, MaskHashKind::default());
        let (_, circuit, _, circuit_witness) =
            mask_circuit_witness_from_trace(&public_inputs, &witness, mask_trace, MaskHashKind::default())
                .expect("valid mask circuit witness");

        assert!(circuit_witness.is_satisfied(&circuit));

        let mut wrong_sign_witness = witness;
        wrong_sign_witness.shared_point = -witness.shared_point;

        assert!(
            mask_circuit_witness_from_trace(&public_inputs, &wrong_sign_witness, mask_trace, MaskHashKind::default())
                .is_err()
        );
    }

    #[test]
    #[cfg_attr(
        debug_assertions,
        ignore = "full Pallas skeleton proof generation is expensive in debug builds"
    )]
    fn skeleton_backend_proves_and_verifies_valid_inputs() {
        let (public_inputs, witness) = valid_case();
        let proof = PallasProofSkeleton::prove(&public_inputs, &witness).expect("proof");

        assert_eq!(PallasProofSkeleton::verify(&public_inputs, &proof), Ok(()));
        assert!(decode_skeleton_proof(&proof.bytes).is_ok());
    }

    #[test]
    #[cfg_attr(
        debug_assertions,
        ignore = "full Pallas skeleton proof generation is expensive in debug builds"
    )]
    fn skeleton_deterministic_rng_reproduces_proof_vector_bytes() {
        let (public_inputs, witness) = valid_case();
        let first = encode_skeleton_proof_with_rng(
            &mut TestRng(7),
            &public_inputs,
            &witness,
            MaskHashKind::default(),
        )
        .expect("first proof");
        let second = encode_skeleton_proof_with_rng(
            &mut TestRng(7),
            &public_inputs,
            &witness,
            MaskHashKind::default(),
        )
        .expect("second proof");
        let proof = MaskProof {
            backend: super::BACKEND,
            bytes: first.clone(),
        };

        assert_eq!(first, second);
        assert_eq!(PallasProofSkeleton::verify(&public_inputs, &proof), Ok(()));
        assert!(decode_skeleton_proof(&first).is_ok());
    }

    #[test]
    #[cfg_attr(
        debug_assertions,
        ignore = "full Pallas skeleton proof generation is expensive in debug builds"
    )]
    fn skeleton_proof_bytes_do_not_serialize_private_trace_material() {
        let (public_inputs, witness) = valid_case();
        let proof = PallasProofSkeleton::prove(&public_inputs, &witness).expect("proof");

        assert!(!contains_subslice(
            &proof.bytes,
            &witness.shared_point.to_bytes()
        ));
        assert!(!contains_subslice(&proof.bytes, &witness.mask.to_bytes()));
    }

    #[test]
    fn skeleton_rejects_malformed_proof_bytes() {
        let (public_inputs, _) = valid_case();
        let proof = MaskProof {
            backend: super::BACKEND,
            bytes: vec![0; CIRCUIT_PROOF_OFFSET],
        };

        assert_eq!(
            PallasProofSkeleton::verify(&public_inputs, &proof),
            Err(ProofError::InvalidProof)
        );
    }

    #[test]
    fn skeleton_rejects_tampered_proof_bytes() {
        let (public_inputs, _) = valid_case();
        let mut proof = MaskProof {
            backend: super::BACKEND,
            bytes: vec![0; CIRCUIT_PROOF_OFFSET + 1],
        };
        proof.bytes[..4].copy_from_slice(super::PROOF_MAGIC);
        proof.bytes[4] = super::PROOF_VERSION ^ 1;

        assert_eq!(
            PallasProofSkeleton::verify(&public_inputs, &proof),
            Err(ProofError::InvalidProof)
        );
    }

    #[test]
    #[cfg_attr(
        debug_assertions,
        ignore = "full Pallas skeleton proof generation is expensive in debug builds"
    )]
    fn skeleton_rejects_tampered_circuit_proof_header() {
        let (public_inputs, witness) = valid_case();
        let mut proof = PallasProofSkeleton::prove(&public_inputs, &witness).expect("proof");
        proof.bytes[CIRCUIT_PROOF_OFFSET] ^= 1;

        assert_eq!(
            PallasProofSkeleton::verify(&public_inputs, &proof),
            Err(ProofError::InvalidProof)
        );
    }

    #[test]
    #[cfg_attr(
        debug_assertions,
        ignore = "full Pallas skeleton proof generation is expensive in debug builds"
    )]
    fn skeleton_rejects_tampered_shared_coordinate_commitment() {
        let (public_inputs, witness) = valid_case();
        let mut proof = PallasProofSkeleton::prove(&public_inputs, &witness).expect("proof");
        proof.bytes[SHARED_X_COMMITMENT_OFFSET] ^= 1;

        assert_eq!(
            PallasProofSkeleton::verify(&public_inputs, &proof),
            Err(ProofError::InvalidProof)
        );
    }

    #[test]
    #[cfg_attr(
        debug_assertions,
        ignore = "full Pallas skeleton proof generation is expensive in debug builds"
    )]
    fn skeleton_rejects_tampered_dh_circuit_proof() {
        let (public_inputs, witness) = valid_case();
        let mut proof = PallasProofSkeleton::prove(&public_inputs, &witness).expect("proof");
        let mask_len = usize::try_from(u64::from_le_bytes(
            proof.bytes[MASK_CIRCUIT_PROOF_LEN_OFFSET..CIRCUIT_PROOF_OFFSET]
                .try_into()
                .expect("mask proof length prefix"),
        ))
        .expect("usize mask proof length");
        let dh_circuit_proof_offset = CIRCUIT_PROOF_OFFSET + mask_len + PROOF_LEN_BYTES;
        proof.bytes[dh_circuit_proof_offset] ^= 1;

        assert_eq!(
            PallasProofSkeleton::verify(&public_inputs, &proof),
            Err(ProofError::InvalidProof)
        );
    }

    #[test]
    #[cfg_attr(
        debug_assertions,
        ignore = "full Pallas skeleton proof generation is expensive in debug builds"
    )]
    fn skeleton_rejects_tampered_circuit_wire_commitment() {
        let (public_inputs, witness) = valid_case();
        let mut proof = PallasProofSkeleton::prove(&public_inputs, &witness).expect("proof");
        proof.bytes[CIRCUIT_PROOF_OFFSET + 5] ^= 1;

        assert_eq!(
            PallasProofSkeleton::verify(&public_inputs, &proof),
            Err(ProofError::InvalidProof)
        );
    }

    #[test]
    #[cfg_attr(
        debug_assertions,
        ignore = "full Pallas skeleton proof generation is expensive in debug builds"
    )]
    fn skeleton_rejects_tampered_circuit_scalar() {
        let (public_inputs, witness) = valid_case();
        let mut proof = PallasProofSkeleton::prove(&public_inputs, &witness).expect("proof");
        let scalar_offset = CIRCUIT_PROOF_OFFSET + 5 + (8 * 32);
        proof.bytes[scalar_offset] ^= 1;

        assert_eq!(
            PallasProofSkeleton::verify(&public_inputs, &proof),
            Err(ProofError::InvalidProof)
        );
    }

    #[test]
    #[cfg_attr(
        debug_assertions,
        ignore = "full Pallas skeleton proof generation is expensive in debug builds"
    )]
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
    #[cfg_attr(
        debug_assertions,
        ignore = "full Pallas skeleton proof generation is expensive in debug builds"
    )]
    fn skeleton_rejects_wrong_public_mask_commitment() {
        let (public_inputs, witness) = valid_case();
        let proof = PallasProofSkeleton::prove(&public_inputs, &witness).expect("proof");
        let mut tampered = public_inputs;
        tampered.mask_commitment += PallasPoint::generator();

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
    #[cfg_attr(
        debug_assertions,
        ignore = "full Pallas skeleton proof generation is expensive in debug builds"
    )]
    fn batch_verifies_valid_inputs() {
        let (first_inputs, first_witness) = valid_case();
        let first_proof = PallasProofSkeleton::prove(&first_inputs, &first_witness).expect("proof");
        let (mut second_inputs, mut second_witness) = valid_case();
        second_inputs.participant_id = id(2);
        refresh_mask(&mut second_inputs, &mut second_witness);
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
        let (public_inputs, _) = valid_case();
        let invalid_proof = MaskProof {
            backend: super::BACKEND,
            bytes: Vec::new(),
        };
        let batch = [ProofBatchItem {
            public_inputs: &public_inputs,
            proof: &invalid_proof,
        }];

        assert_eq!(
            PallasProofSkeleton::verify_batch(&batch),
            Err(ProofError::InvalidProof)
        );
    }
}

#[cfg(all(test, feature = "poseidon-mask"))]
mod poseidon_tests {
    use ark_ff::{BigInteger, PrimeField};
    use ark_r1cs_std::{R1CSVar, alloc::AllocVar, uint8::UInt8};
    use ark_relations::r1cs::ConstraintSystem;
    use golden_core::{FieldElement, ParticipantId, Polynomial};
    use golden_pallas::{
        HelperSecretKey, PallasPoint, PallasScalar, SharedSecret, VestaScalar, commit_polynomial,
        domains,
    };

    use super::{
        ark_fq_to_pallas_scalar, decode_skeleton_proof,
        poseidon::{poseidon_hash_circuit, poseidon_hash_native, poseidon_mask_config},
    };
    use crate::{
        MaskHashKind, MaskProof, ProofError, ProofPublicInputs, ProofSystem, ProofWitness,
        pallas::PallasProofSkeleton,
    };

    fn id(value: u64) -> ParticipantId {
        ParticipantId::new(value).expect("non-zero id")
    }

    /// Build a fixed witness whose mask is derived via the Poseidon native path.
    fn poseidon_case() -> (ProofPublicInputs, ProofWitness) {
        let dealer_secret = HelperSecretKey::from_scalar(VestaScalar::from_u64(13));
        let participant_secret = HelperSecretKey::from_scalar(VestaScalar::from_u64(29));
        let public_polynomial = commit_polynomial(&Polynomial::new(vec![
            PallasScalar::from_u64(5),
            PallasScalar::from_u64(7),
        ]));
        let shared = dealer_secret.diffie_hellman(participant_secret.public_key());
        let public_inputs = ProofPublicInputs {
            session_id: b"poseidon-mask-session".to_vec(),
            dealer_id: id(10),
            participant_id: id(1),
            dealer_public: dealer_secret.public_key(),
            participant_public: participant_secret.public_key(),
            mask_commitment: PallasPoint::identity(),
            public_polynomial,
        };
        let transcript = public_inputs.mask_transcript();
        let shared_point = shared.point();
        let field =
            poseidon_hash_native(domains::MASK_TO_FIELD, &shared_point.to_bytes(), &transcript);
        let mask = ark_fq_to_pallas_scalar(field);
        let public_inputs = ProofPublicInputs {
            mask_commitment: PallasPoint::generator_mul(mask),
            ..public_inputs
        };
        let witness = ProofWitness {
            dealer_secret: dealer_secret.scalar(),
            shared_point,
            mask,
        };
        (public_inputs, witness)
    }

    fn poseidon_message(shared_point: &[u8], transcript: &[u8]) -> Vec<u8> {
        let mut message = Vec::new();
        message.extend_from_slice(domains::MASK_TO_FIELD);
        message.extend_from_slice(shared_point);
        message.extend_from_slice(transcript);
        message
    }

    #[test]
    fn poseidon_native_matches_circuit_digest() {
        let (public_inputs, witness) = poseidon_case();
        let transcript = public_inputs.mask_transcript();
        let shared_point = witness.shared_point.to_bytes();

        let native =
            poseidon_hash_native(domains::MASK_TO_FIELD, &shared_point, &transcript);

        let cs = ConstraintSystem::<ark_vesta::Fq>::new_ref();
        let message_bytes = poseidon_message(&shared_point, &transcript);
        let message: Vec<UInt8<ark_vesta::Fq>> = message_bytes
            .iter()
            .map(|byte| UInt8::new_witness(cs.clone(), || Ok(*byte)).expect("alloc byte"))
            .collect();
        let circuit = poseidon_hash_circuit(cs.clone(), &message).expect("circuit hash");

        assert_eq!(circuit.value().expect("circuit value"), native);
        assert!(cs.is_satisfied().expect("cs satisfied"));
    }

    fn to_hex(bytes: &[u8]) -> String {
        use std::fmt::Write as _;
        let mut hex = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            write!(hex, "{byte:02x}").expect("writing to a String never fails");
        }
        hex
    }

    #[test]
    fn poseidon_config_known_answer_vector() {
        let config = poseidon_mask_config();
        assert_eq!(config.full_rounds, 8);
        assert_eq!(config.partial_rounds, 56);
        assert_eq!(config.alpha, 5);
        assert_eq!(config.rate, 2);
        assert_eq!(config.capacity, 1);
        assert_eq!(config.ark.len(), config.full_rounds + config.partial_rounds);
        assert_eq!(config.ark.len(), 64);
        assert_eq!(config.mds.len(), 3);
        for row in &config.mds {
            assert_eq!(row.len(), 3);
        }

        // Known-answer vector: hash a fixed pinned preimage and assert the
        // squeezed field element serializes to a pinned little-endian hex string.
        let shared_point = [7_u8; 32];
        let transcript = [9_u8; 16];
        let field = poseidon_hash_native(domains::MASK_TO_FIELD, &shared_point, &transcript);
        let bytes = field.into_bigint().to_bytes_le();
        let hex = to_hex(&bytes);
        assert_eq!(hex, POSEIDON_MASK_KAT_HEX);
    }

    #[test]
    fn poseidon_prove_verify_round_trip() {
        let (public_inputs, witness) = poseidon_case();

        let proof =
            PallasProofSkeleton::prove_with_hash(&public_inputs, &witness, MaskHashKind::Poseidon)
                .expect("poseidon proof");
        assert_eq!(
            PallasProofSkeleton::verify_with_hash(
                &public_inputs,
                &proof,
                MaskHashKind::Poseidon
            ),
            Ok(())
        );
        assert!(decode_skeleton_proof(&proof.bytes).is_ok());

        // Coexistence: the same inputs still round-trip under Blake2b after
        // refreshing the mask to the Blake2b-derived value.
        let blake_mask = golden_pallas::derive_mask(
            SharedSecret::from_point(witness.shared_point),
            &public_inputs.mask_transcript(),
        );
        let blake_inputs = ProofPublicInputs {
            mask_commitment: PallasPoint::generator_mul(blake_mask),
            ..public_inputs.clone()
        };
        let blake_witness = ProofWitness {
            mask: blake_mask,
            ..witness
        };
        let blake_proof =
            PallasProofSkeleton::prove_with_hash(&blake_inputs, &blake_witness, MaskHashKind::Blake2b)
                .expect("blake proof");
        assert_eq!(
            PallasProofSkeleton::verify_with_hash(
                &blake_inputs,
                &blake_proof,
                MaskHashKind::Blake2b
            ),
            Ok(())
        );

        // Kind binding: a Poseidon proof verified as Blake2b is rejected.
        assert!(
            PallasProofSkeleton::verify_with_hash(
                &public_inputs,
                &proof,
                MaskHashKind::Blake2b
            )
            .is_err()
        );
    }

    #[test]
    fn poseidon_rejects_tampered_witness() {
        let (public_inputs, mut witness) = poseidon_case();
        witness.mask += PallasScalar::ONE;

        assert_eq!(
            PallasProofSkeleton::prove_with_hash(&public_inputs, &witness, MaskHashKind::Poseidon),
            Err(ProofError::InvalidWitness)
        );

        // A valid Poseidon proof with a flipped byte must fail verification.
        let (public_inputs, witness) = poseidon_case();
        let mut proof =
            PallasProofSkeleton::prove_with_hash(&public_inputs, &witness, MaskHashKind::Poseidon)
                .expect("poseidon proof");
        let last = proof.bytes.len() - 1;
        proof.bytes[last] ^= 1;
        assert!(
            PallasProofSkeleton::verify_with_hash(
                &public_inputs,
                &proof,
                MaskHashKind::Poseidon
            )
            .is_err()
        );
        let _ = MaskProof {
            backend: super::BACKEND,
            bytes: Vec::new(),
        };
    }

    /// Pinned little-endian hex of the squeezed mask field element for the
    /// fixed known-answer preimage. Regenerated once, then locked here.
    const POSEIDON_MASK_KAT_HEX: &str =
        "bbd0d35cd8c8ffcce52538b01d6666ef3775fc5e8d405b20375e570355e90717";
}
