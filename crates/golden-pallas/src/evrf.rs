//! Helper-curve eVRF primitives.
//!
//! These functions implement the concrete key-agreement and mask-derivation
//! boundary used by Golden. The zero-knowledge proof that these operations were
//! performed correctly is intentionally not implemented here.

use blake2b_simd::Params;
use pasta_curves::{arithmetic::CurveExt, vesta};

use crate::{PallasScalar, VestaPoint, VestaScalar, domains};

/// Dealer or participant helper-curve secret key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HelperSecretKey(VestaScalar);

impl HelperSecretKey {
    /// Construct from a Vesta scalar.
    #[must_use]
    pub const fn from_scalar(scalar: VestaScalar) -> Self {
        Self(scalar)
    }

    /// Return the wrapped scalar.
    #[must_use]
    pub const fn scalar(self) -> VestaScalar {
        self.0
    }

    /// Derive the corresponding helper public key.
    #[must_use]
    pub fn public_key(self) -> HelperPublicKey {
        HelperPublicKey(VestaPoint::generator_mul(self.0))
    }

    /// Compute a Diffie-Hellman shared helper point.
    #[must_use]
    pub fn diffie_hellman(self, peer: HelperPublicKey) -> SharedSecret {
        SharedSecret(peer.0.mul_scalar(self.0))
    }
}

/// Dealer or participant helper-curve public key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HelperPublicKey(VestaPoint);

impl HelperPublicKey {
    /// Construct from a Vesta point.
    #[must_use]
    pub const fn from_point(point: VestaPoint) -> Self {
        Self(point)
    }

    /// Return the wrapped point.
    #[must_use]
    pub const fn point(self) -> VestaPoint {
        self.0
    }
}

/// Shared helper-curve point produced by key agreement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SharedSecret(VestaPoint);

impl SharedSecret {
    /// Construct from a Vesta point.
    #[must_use]
    pub const fn from_point(point: VestaPoint) -> Self {
        Self(point)
    }

    /// Return the wrapped point.
    #[must_use]
    pub const fn point(self) -> VestaPoint {
        self.0
    }
}

/// Hash public input to Vesta using the H1 domain.
#[must_use]
pub fn hash_to_vesta_h1(message: &[u8]) -> VestaPoint {
    let hash = vesta::Point::hash_to_curve(domains::H1_TO_VESTA);
    VestaPoint::from_inner(hash(message))
}

/// Hash public input to Vesta using the H2 domain.
#[must_use]
pub fn hash_to_vesta_h2(message: &[u8]) -> VestaPoint {
    let hash = vesta::Point::hash_to_curve(domains::H2_TO_VESTA);
    VestaPoint::from_inner(hash(message))
}

/// Derive a Pallas scalar mask from a shared helper point and transcript bytes.
#[must_use]
pub fn derive_mask(shared: SharedSecret, transcript: &[u8]) -> PallasScalar {
    let hash = Params::new()
        .hash_length(64)
        .to_state()
        .update(domains::MASK_TO_FIELD)
        .update(&shared.point().to_bytes())
        .update(transcript)
        .finalize();
    let mut uniform = [0_u8; 64];
    uniform.copy_from_slice(hash.as_bytes());
    PallasScalar::from_uniform_bytes(&uniform)
}

#[cfg(test)]
mod tests {
    use super::{HelperSecretKey, derive_mask, hash_to_vesta_h1, hash_to_vesta_h2};
    use crate::VestaScalar;

    #[test]
    fn dealer_and_participant_derive_same_shared_secret() {
        let dealer = HelperSecretKey::from_scalar(VestaScalar::from_u64(13));
        let participant = HelperSecretKey::from_scalar(VestaScalar::from_u64(29));

        assert_eq!(
            dealer.diffie_hellman(participant.public_key()),
            participant.diffie_hellman(dealer.public_key())
        );
    }

    #[test]
    fn same_shared_secret_and_transcript_derives_same_mask() {
        let dealer = HelperSecretKey::from_scalar(VestaScalar::from_u64(13));
        let participant = HelperSecretKey::from_scalar(VestaScalar::from_u64(29));
        let shared = dealer.diffie_hellman(participant.public_key());

        assert_eq!(
            derive_mask(shared, b"session-1"),
            derive_mask(shared, b"session-1")
        );
    }

    #[test]
    fn transcript_changes_mask() {
        let dealer = HelperSecretKey::from_scalar(VestaScalar::from_u64(13));
        let participant = HelperSecretKey::from_scalar(VestaScalar::from_u64(29));
        let shared = dealer.diffie_hellman(participant.public_key());

        assert_ne!(
            derive_mask(shared, b"session-1"),
            derive_mask(shared, b"session-2")
        );
    }

    #[test]
    fn h1_and_h2_are_domain_separated() {
        assert_ne!(hash_to_vesta_h1(b"msg"), hash_to_vesta_h2(b"msg"));
    }
}
