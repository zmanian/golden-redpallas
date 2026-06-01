//! Common proof-system types.

use golden_core::{ParticipantId, PublicPolynomial};
use golden_pallas::{
    HelperPublicKey, PallasPoint, PallasScalar, VestaPoint, VestaScalar, dkg_mask_transcript,
};

const PUBLIC_INPUTS_MAGIC: &[u8; 4] = b"GPPI";
const PUBLIC_INPUTS_VERSION: u8 = 0;
const LEN_BYTES: usize = 8;
const PARTICIPANT_ID_BYTES: usize = 2;

/// Public inputs for one Golden mask proof.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProofPublicInputs {
    /// Session identifier bound to this DKG.
    pub session_id: Vec<u8>,
    /// Dealer identifier.
    pub dealer_id: ParticipantId,
    /// Participant identifier.
    pub participant_id: ParticipantId,
    /// Dealer helper-curve public key.
    pub dealer_public: HelperPublicKey,
    /// Participant helper-curve public key.
    pub participant_public: HelperPublicKey,
    /// Commitment to the mask in the DKG group.
    pub mask_commitment: PallasPoint,
    /// Dealer public polynomial commitments.
    pub public_polynomial: PublicPolynomial<PallasPoint>,
}

impl ProofPublicInputs {
    /// Return the transcript bytes used for mask derivation.
    #[must_use]
    pub fn mask_transcript(&self) -> Vec<u8> {
        dkg_mask_transcript(
            &self.session_id,
            self.dealer_id,
            self.participant_id,
            self.dealer_public,
            self.participant_public,
            &self.public_polynomial,
        )
    }

    /// Return the canonical byte encoding for these public inputs.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(
            PUBLIC_INPUTS_MAGIC.len()
                + 1
                + LEN_BYTES
                + self.session_id.len()
                + (PARTICIPANT_ID_BYTES * 2)
                + (32 * 3)
                + LEN_BYTES
                + (32 * self.public_polynomial.coefficient_commitments.len()),
        );
        bytes.extend_from_slice(PUBLIC_INPUTS_MAGIC);
        bytes.push(PUBLIC_INPUTS_VERSION);
        write_len(&mut bytes, self.session_id.len());
        bytes.extend_from_slice(&self.session_id);
        bytes.extend_from_slice(&self.dealer_id.as_u16().to_le_bytes());
        bytes.extend_from_slice(&self.participant_id.as_u16().to_le_bytes());
        bytes.extend_from_slice(&self.dealer_public.point().to_bytes());
        bytes.extend_from_slice(&self.participant_public.point().to_bytes());
        bytes.extend_from_slice(&self.mask_commitment.to_bytes());
        write_len(
            &mut bytes,
            self.public_polynomial.coefficient_commitments.len(),
        );
        for commitment in &self.public_polynomial.coefficient_commitments {
            bytes.extend_from_slice(&commitment.to_bytes());
        }
        bytes
    }

    /// Parse a canonical byte encoding produced by [`Self::to_bytes`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ProofError> {
        let mut offset = 0_usize;
        if read_array::<4>(bytes, &mut offset)? != *PUBLIC_INPUTS_MAGIC {
            return Err(ProofError::InvalidProof);
        }
        if read_array::<1>(bytes, &mut offset)?[0] != PUBLIC_INPUTS_VERSION {
            return Err(ProofError::InvalidProof);
        }

        let session_len = read_len(bytes, &mut offset)?;
        let session_id = read_slice(bytes, &mut offset, session_len)?.to_vec();
        let dealer_id = read_participant_id(bytes, &mut offset)?;
        let participant_id = read_participant_id(bytes, &mut offset)?;
        let dealer_public = HelperPublicKey::from_point(read_vesta_point(bytes, &mut offset)?);
        let participant_public = HelperPublicKey::from_point(read_vesta_point(bytes, &mut offset)?);
        let mask_commitment = read_pallas_point(bytes, &mut offset)?;
        let polynomial_len = read_len(bytes, &mut offset)?;
        if polynomial_len == 0 {
            return Err(ProofError::InvalidProof);
        }
        let mut coefficient_commitments = Vec::with_capacity(polynomial_len);
        for _ in 0..polynomial_len {
            coefficient_commitments.push(read_pallas_point(bytes, &mut offset)?);
        }

        if offset != bytes.len() {
            return Err(ProofError::InvalidProof);
        }

        Ok(Self {
            session_id,
            dealer_id,
            participant_id,
            dealer_public,
            participant_public,
            mask_commitment,
            public_polynomial: PublicPolynomial {
                coefficient_commitments,
            },
        })
    }
}

fn write_len(bytes: &mut Vec<u8>, len: usize) {
    let len = u64::try_from(len).expect("usize length fits in u64");
    bytes.extend_from_slice(&len.to_le_bytes());
}

fn read_len(bytes: &[u8], offset: &mut usize) -> Result<usize, ProofError> {
    usize::try_from(u64::from_le_bytes(read_array(bytes, offset)?))
        .map_err(|_| ProofError::InvalidProof)
}

fn read_participant_id(bytes: &[u8], offset: &mut usize) -> Result<ParticipantId, ProofError> {
    ParticipantId::try_from(u16::from_le_bytes(read_array(bytes, offset)?))
        .map_err(|_| ProofError::InvalidProof)
}

fn read_pallas_point(bytes: &[u8], offset: &mut usize) -> Result<PallasPoint, ProofError> {
    PallasPoint::from_bytes(read_array(bytes, offset)?).ok_or(ProofError::InvalidProof)
}

fn read_vesta_point(bytes: &[u8], offset: &mut usize) -> Result<VestaPoint, ProofError> {
    VestaPoint::from_bytes(read_array(bytes, offset)?).ok_or(ProofError::InvalidProof)
}

fn read_array<const N: usize>(bytes: &[u8], offset: &mut usize) -> Result<[u8; N], ProofError> {
    let slice = read_slice(bytes, offset, N)?;
    slice.try_into().map_err(|_| ProofError::InvalidProof)
}

fn read_slice<'a>(bytes: &'a [u8], offset: &mut usize, len: usize) -> Result<&'a [u8], ProofError> {
    let end = offset.checked_add(len).ok_or(ProofError::InvalidProof)?;
    let slice = bytes.get(*offset..end).ok_or(ProofError::InvalidProof)?;
    *offset = end;
    Ok(slice)
}

/// Private witness for one Golden mask proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProofWitness {
    /// Dealer helper-curve secret key scalar.
    pub dealer_secret: VestaScalar,
    /// Shared helper point computed from the witness and participant key.
    pub shared_point: VestaPoint,
    /// Derived mask.
    pub mask: PallasScalar,
}

/// Opaque proof bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MaskProof {
    /// Proof backend identifier.
    pub backend: &'static str,
    /// Backend-specific bytes.
    pub bytes: Vec<u8>,
}

/// Proof generation or verification failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProofError {
    /// Witness does not match public inputs.
    InvalidWitness,
    /// Proof bytes do not match public inputs.
    InvalidProof,
    /// Proof was produced by another backend.
    BackendMismatch,
}

/// One proof verification item in a batch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProofBatchItem<'a> {
    /// Public proof inputs.
    pub public_inputs: &'a ProofPublicInputs,
    /// Proof bytes.
    pub proof: &'a MaskProof,
}

/// Selector for the mask hash-to-field algorithm used by a backend.
///
/// The default is [`MaskHashKind::Blake2b`], preserving the existing proof
/// behavior. The [`MaskHashKind::Poseidon`] arm only exists when the crate is
/// built with the `poseidon-mask` feature.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum MaskHashKind {
    /// In-tree Blake2b-512 hash-to-field relation (default).
    #[default]
    Blake2b,
    /// `ark-crypto-primitives` Poseidon sponge over the circuit field.
    #[cfg(feature = "poseidon-mask")]
    Poseidon,
}

/// Proof-system interface for one Golden mask proof.
pub trait ProofSystem {
    /// Create a proof using the requested mask hash algorithm.
    fn prove_with_hash(
        public_inputs: &ProofPublicInputs,
        witness: &ProofWitness,
        hash_kind: MaskHashKind,
    ) -> Result<MaskProof, ProofError>;

    /// Verify a proof against public inputs using the requested mask hash
    /// algorithm.
    fn verify_with_hash(
        public_inputs: &ProofPublicInputs,
        proof: &MaskProof,
        hash_kind: MaskHashKind,
    ) -> Result<(), ProofError>;

    /// Create a proof for the provided public inputs and witness.
    ///
    /// Delegates to [`ProofSystem::prove_with_hash`] with the default
    /// ([`MaskHashKind::Blake2b`]) hash algorithm, so existing callers are
    /// unchanged.
    fn prove(
        public_inputs: &ProofPublicInputs,
        witness: &ProofWitness,
    ) -> Result<MaskProof, ProofError> {
        Self::prove_with_hash(public_inputs, witness, MaskHashKind::default())
    }

    /// Verify a proof against public inputs.
    ///
    /// Delegates to [`ProofSystem::verify_with_hash`] with the default
    /// ([`MaskHashKind::Blake2b`]) hash algorithm.
    fn verify(public_inputs: &ProofPublicInputs, proof: &MaskProof) -> Result<(), ProofError> {
        Self::verify_with_hash(public_inputs, proof, MaskHashKind::default())
    }

    /// Verify multiple proofs together.
    ///
    /// Backends that support true batch verification should override this
    /// method. The default preserves the same contract by verifying each item
    /// independently.
    fn verify_batch(items: &[ProofBatchItem<'_>]) -> Result<(), ProofError> {
        for item in items {
            Self::verify(item.public_inputs, item.proof)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use golden_core::{FieldElement, ParticipantId, PublicPolynomial};
    use golden_pallas::{
        HelperPublicKey, PallasPoint, PallasScalar, VestaPoint, VestaScalar, commit_polynomial,
    };

    use super::{ProofError, ProofPublicInputs};

    fn id(value: u64) -> ParticipantId {
        ParticipantId::new(value).expect("non-zero participant id")
    }

    fn public_inputs() -> ProofPublicInputs {
        let public_polynomial = commit_polynomial(&golden_core::Polynomial::new(vec![
            PallasScalar::from_u64(5),
            PallasScalar::from_u64(7),
        ]));
        ProofPublicInputs {
            session_id: b"proof-public-input-encoding-test".to_vec(),
            dealer_id: id(10),
            participant_id: id(2),
            dealer_public: HelperPublicKey::from_point(VestaPoint::generator_mul(
                VestaScalar::from_u64(13),
            )),
            participant_public: HelperPublicKey::from_point(VestaPoint::generator_mul(
                VestaScalar::from_u64(31),
            )),
            mask_commitment: PallasPoint::generator_mul(PallasScalar::from_u64(42)),
            public_polynomial,
        }
    }

    #[test]
    fn proof_public_inputs_roundtrip_through_canonical_bytes() {
        let inputs = public_inputs();
        let encoded = inputs.to_bytes();

        assert_eq!(ProofPublicInputs::from_bytes(&encoded), Ok(inputs));
    }

    #[test]
    fn proof_public_inputs_decoder_rejects_malformed_bytes() {
        assert_eq!(
            ProofPublicInputs::from_bytes(&[]),
            Err(ProofError::InvalidProof)
        );

        let mut encoded = public_inputs().to_bytes();
        for len in 0..encoded.len() {
            assert_eq!(
                ProofPublicInputs::from_bytes(&encoded[..len]),
                Err(ProofError::InvalidProof)
            );
        }

        encoded.push(0);
        assert_eq!(
            ProofPublicInputs::from_bytes(&encoded),
            Err(ProofError::InvalidProof)
        );
    }

    #[test]
    fn proof_public_inputs_decoder_rejects_zero_participant_ids() {
        let mut encoded = public_inputs().to_bytes();
        let dealer_id_offset = 4 + 1 + 8 + b"proof-public-input-encoding-test".len();
        encoded[dealer_id_offset] = 0;
        encoded[dealer_id_offset + 1] = 0;

        assert_eq!(
            ProofPublicInputs::from_bytes(&encoded),
            Err(ProofError::InvalidProof)
        );
    }

    #[test]
    fn proof_public_inputs_decoder_rejects_non_canonical_points() {
        let mut encoded = public_inputs().to_bytes();
        let dealer_public_offset = 4 + 1 + 8 + b"proof-public-input-encoding-test".len() + 4;
        encoded[dealer_public_offset..dealer_public_offset + 32].fill(0xff);

        assert_eq!(
            ProofPublicInputs::from_bytes(&encoded),
            Err(ProofError::InvalidProof)
        );
    }

    #[test]
    fn proof_public_inputs_decoder_rejects_empty_public_polynomial() {
        let mut encoded = public_inputs().to_bytes();
        let polynomial_len_offset = 4 + 1 + 8 + b"proof-public-input-encoding-test".len() + 4 + 96;
        encoded[polynomial_len_offset..polynomial_len_offset + 8].fill(0);
        encoded.truncate(polynomial_len_offset + 8);

        assert_eq!(
            ProofPublicInputs::from_bytes(&encoded),
            Err(ProofError::InvalidProof)
        );
    }

    #[test]
    fn proof_public_inputs_mask_transcript_survives_roundtrip() {
        let inputs = public_inputs();
        let decoded = ProofPublicInputs::from_bytes(&inputs.to_bytes()).expect("decode");

        assert_eq!(decoded.mask_transcript(), inputs.mask_transcript());
        assert_eq!(
            decoded.public_polynomial,
            PublicPolynomial {
                coefficient_commitments: inputs.public_polynomial.coefficient_commitments,
            }
        );
    }
}
