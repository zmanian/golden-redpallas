//! Protocol-independent core for Golden-style one-round DKG.
//!
//! This crate deliberately excludes concrete elliptic-curve and proof-system
//! code. It models the data flow that Pallas/Vesta and Bulletproofs adapters
//! must satisfy.

pub mod aggregation;
pub mod config;
pub mod dealer;
pub mod field;
pub mod polynomial;
pub mod transcript;

pub use aggregation::{AggregatedShare, AggregationError, aggregate_public_key, aggregate_share};
pub use config::{ConfigError, ProtocolConfig};
pub use dealer::{DealerConfig, DealerError, DealerSecret, build_transcript, recover_share};
pub use field::FieldElement;
pub use polynomial::{InterpolationError, Polynomial, interpolate_at_zero};
pub use transcript::{
    MAX_FROST_PARTICIPANT_ID, MaskedShare, ParticipantId, ParticipantIdError, ProofStatus,
    PublicPolynomial, Transcript, VerificationError, VerifiedTranscript, validate_transcript,
    verify_transcript,
};
