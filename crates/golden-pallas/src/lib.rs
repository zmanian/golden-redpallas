//! Pallas/Vesta bindings for Golden.
//!
//! This crate binds the protocol-independent `golden-core` APIs to the Pasta
//! curve cycle used by Zcash Orchard. The proof system and eVRF are still
//! separate workstreams; this crate currently provides concrete scalar, group,
//! and commitment-equation operations.

mod evrf;
mod pallas_types;
mod vesta_types;

pub use evrf::{
    HelperPublicKey, HelperSecretKey, SharedSecret, derive_mask, hash_to_vesta_h1, hash_to_vesta_h2,
};
pub use pallas_types::{
    PallasPoint, PallasScalar, commit_polynomial, evaluate_public_polynomial,
    verify_masked_share_commitment,
};
pub use vesta_types::{VestaPoint, VestaScalar};

/// Domain separators reserved for the Pallas/Vesta Golden instantiation.
pub mod domains {
    /// Hash-to-Vesta domain for the first eVRF map.
    pub const H1_TO_VESTA: &str = "GoldenRedPallas/Vesta/H1/v0";

    /// Hash-to-Vesta domain for the second eVRF map.
    pub const H2_TO_VESTA: &str = "GoldenRedPallas/Vesta/H2/v0";

    /// Hash-to-Pallas-scalar domain for masks.
    pub const MASK_TO_FIELD: &[u8] = b"GoldenRedPallas/MaskToField/v0";
}

/// Unimplemented Pallas/Vesta eVRF marker.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PallasVestaEvrf;

impl PallasVestaEvrf {
    /// Return the current implementation status.
    #[must_use]
    pub const fn status() -> &'static str {
        "not implemented: eVRF mask derivation and Bulletproofs backend are pending"
    }
}
