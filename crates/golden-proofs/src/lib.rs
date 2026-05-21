//! Proof-system boundary for Golden DKG.
//!
//! This crate defines the public proof API that a Pallas-field Bulletproofs
//! implementation must satisfy. The included fixture backend is deliberately not
//! zero-knowledge; it only pins public-input binding and integration behavior.

mod fixture;
mod types;

pub use fixture::FixtureProofSystem;
pub use types::{MaskProof, ProofError, ProofPublicInputs, ProofSystem, ProofWitness};
