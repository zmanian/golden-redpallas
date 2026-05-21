//! Pallas/Vesta adapter boundary for Golden.
//!
//! This crate is intentionally a placeholder until the concrete Pasta-cycle
//! dependencies and proof system are selected.

/// Domain separators reserved for the Pallas/Vesta Golden instantiation.
pub mod domains {
    /// Hash-to-Vesta domain for the first eVRF map.
    pub const H1_TO_VESTA: &[u8] = b"GoldenRedPallas/Vesta/H1/v0";

    /// Hash-to-Vesta domain for the second eVRF map.
    pub const H2_TO_VESTA: &[u8] = b"GoldenRedPallas/Vesta/H2/v0";

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
        "not implemented: select pasta_curves bindings and Bulletproofs backend"
    }
}
