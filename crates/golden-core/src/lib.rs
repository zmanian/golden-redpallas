//! Protocol-independent core for Golden-style one-round DKG.
//!
//! This crate deliberately excludes concrete elliptic-curve and proof-system
//! code. It models the data flow that Pallas/Vesta and Bulletproofs adapters
//! must satisfy.

pub mod dealer;
pub mod field;
pub mod polynomial;
pub mod transcript;

pub use dealer::{DealerConfig, DealerError, DealerSecret, recover_share};
pub use field::FieldElement;
pub use polynomial::{InterpolationError, Polynomial, interpolate_at_zero};
pub use transcript::{
    MaskedShare, ParticipantId, ProofStatus, PublicPolynomial, Transcript, VerificationError,
    verify_transcript,
};
