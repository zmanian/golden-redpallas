//! Proof-system boundary for Golden DKG.
//!
//! This crate defines the public proof API that a Pallas-field Bulletproofs
//! implementation must satisfy. The included fixture backend is deliberately not
//! zero-knowledge; it only pins public-input binding and integration behavior.

mod dkg;
mod fixture;
#[cfg(feature = "pallas-backend")]
pub mod pallas;
mod types;
mod witness;

#[cfg(feature = "pallas-backend")]
pub use dkg::PallasProofedDkgSimulation;
pub use dkg::{
    ProofedDkgProofProgress, ProofedDkgSimulation, ProofedTranscript, recover_with_proofs,
};
pub use fixture::FixtureProofSystem;
#[cfg(feature = "pallas-backend")]
pub use pallas::{
    PallasCircuit, PallasCircuitClaim, PallasCircuitProfile, PallasCircuitProof,
    PallasCircuitSetup, PallasCircuitWitness, PallasIpaClaim, PallasIpaProof, PallasIpaSetup,
    PallasIpaWitness, PallasMaskConstraintCommitment, PallasMaskConstraints,
    PallasMaskHashConstraintTrace, PallasMaskHashFieldConstraintTrace, PallasMaskHashTrace,
    PallasMaskOpeningProof, PallasProofCircuitProfile, PallasProofSkeleton, PallasProofTranscript,
    PallasR1cs, PallasSparseMatrix, PallasVestaDhConstraintTrace,
    PallasVestaDhFieldConstraintTrace, derive_pallas_generator,
};
#[cfg(feature = "poseidon-mask")]
pub use pallas::poseidon::poseidon_mask_from_shared;
pub use types::{
    MaskHashKind, MaskProof, ProofBatchItem, ProofError, ProofPublicInputs, ProofSystem,
    ProofWitness,
};
