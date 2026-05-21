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

pub use dkg::{ProofedDkgSimulation, ProofedTranscript, recover_with_proofs};
pub use fixture::FixtureProofSystem;
#[cfg(feature = "pallas-backend")]
pub use pallas::{
    PallasMaskConstraintCommitment, PallasMaskConstraints, PallasProofSkeleton,
    PallasProofTranscript, derive_pallas_generator,
};
pub use types::{
    MaskProof, ProofBatchItem, ProofError, ProofPublicInputs, ProofSystem, ProofWitness,
};
