//! Common proof-system types.

use blake2b_simd::Params;
use golden_core::{ParticipantId, PublicPolynomial};
use golden_pallas::{
    HelperPublicKey, PallasPoint, PallasScalar, SharedSecret, VestaPoint, VestaScalar,
};

const MASK_TRANSCRIPT_DOMAIN: &[u8] = b"GoldenRedPallas/DKGMaskTranscript/v0";

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
    /// Diffie-Hellman shared helper point.
    pub shared_point: SharedSecret,
    /// Derived mask.
    pub mask: PallasScalar,
    /// Commitment to the mask in the DKG group.
    pub mask_commitment: PallasPoint,
    /// Dealer public polynomial commitments.
    pub public_polynomial: PublicPolynomial<PallasPoint>,
}

impl ProofPublicInputs {
    /// Return the transcript bytes used for mask derivation.
    #[must_use]
    pub fn mask_transcript(&self) -> Vec<u8> {
        let mut digest = Params::new().hash_length(32).to_state();
        digest.update(MASK_TRANSCRIPT_DOMAIN);
        digest.update(&(self.session_id.len() as u64).to_le_bytes());
        digest.update(&self.session_id);
        digest.update(&self.dealer_id.get().to_le_bytes());
        digest.update(&self.participant_id.get().to_le_bytes());
        digest.update(&self.dealer_public.point().to_bytes());
        digest.update(&self.participant_public.point().to_bytes());
        digest.update(&(self.public_polynomial.coefficient_commitments.len() as u64).to_le_bytes());
        for commitment in &self.public_polynomial.coefficient_commitments {
            digest.update(&commitment.to_bytes());
        }
        digest.finalize().as_bytes().to_vec()
    }
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

/// Proof-system interface for one Golden mask proof.
pub trait ProofSystem {
    /// Create a proof for the provided public inputs and witness.
    fn prove(
        public_inputs: &ProofPublicInputs,
        witness: &ProofWitness,
    ) -> Result<MaskProof, ProofError>;

    /// Verify a proof against public inputs.
    fn verify(public_inputs: &ProofPublicInputs, proof: &MaskProof) -> Result<(), ProofError>;
}
