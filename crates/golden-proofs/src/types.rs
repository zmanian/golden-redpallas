//! Common proof-system types.

use golden_core::{ParticipantId, PublicPolynomial};
use golden_pallas::{
    HelperPublicKey, PallasPoint, PallasScalar, SharedSecret, VestaPoint, VestaScalar,
};

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
