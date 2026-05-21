//! Helper-curve eVRF primitives.
//!
//! These functions implement the concrete key-agreement and mask-derivation
//! boundary used by Golden. The zero-knowledge proof that these operations were
//! performed correctly is intentionally not implemented here.

use blake2b_simd::Params;
use golden_core::{ParticipantId, PublicPolynomial};
use pasta_curves::{arithmetic::CurveExt, vesta};

use crate::{PallasPoint, PallasScalar, VestaPoint, VestaScalar, domains};

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

/// Return the canonical DKG mask transcript binding.
#[must_use]
pub fn dkg_mask_transcript(
    session_id: &[u8],
    dealer_id: ParticipantId,
    participant_id: ParticipantId,
    dealer_public: HelperPublicKey,
    participant_public: HelperPublicKey,
    public_polynomial: &PublicPolynomial<PallasPoint>,
) -> Vec<u8> {
    let mut digest = Params::new().hash_length(32).to_state();
    digest.update(domains::DKG_MASK_TRANSCRIPT);
    digest.update(&(session_id.len() as u64).to_le_bytes());
    digest.update(session_id);
    digest.update(&dealer_id.get().to_le_bytes());
    digest.update(&participant_id.get().to_le_bytes());
    digest.update(&dealer_public.point().to_bytes());
    digest.update(&participant_public.point().to_bytes());
    digest.update(&(public_polynomial.coefficient_commitments.len() as u64).to_le_bytes());
    for commitment in &public_polynomial.coefficient_commitments {
        digest.update(&commitment.to_bytes());
    }
    digest.finalize().as_bytes().to_vec()
}

#[cfg(test)]
mod tests {
    use super::{
        HelperPublicKey, HelperSecretKey, SharedSecret, derive_mask, dkg_mask_transcript,
        hash_to_vesta_h1, hash_to_vesta_h2,
    };
    use crate::{PallasPoint, PallasScalar, VestaPoint, VestaScalar};
    use golden_core::{FieldElement, ParticipantId, PublicPolynomial};

    const EVRF_VECTOR_V0: &str = include_str!("../../../test-vectors/golden-pallas/evrf-v0.txt");

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

    #[test]
    fn dkg_mask_transcript_binds_public_inputs() {
        let dealer = HelperSecretKey::from_scalar(VestaScalar::from_u64(13));
        let participant = HelperSecretKey::from_scalar(VestaScalar::from_u64(29));
        let dealer_id = ParticipantId::new(10).expect("non-zero id");
        let participant_id = ParticipantId::new(1).expect("non-zero id");
        let public_polynomial = PublicPolynomial {
            coefficient_commitments: vec![
                PallasPoint::generator_mul(PallasScalar::from_u64(5)),
                PallasPoint::generator_mul(PallasScalar::from_u64(7)),
            ],
        };

        assert_ne!(
            dkg_mask_transcript(
                b"session-a",
                dealer_id,
                participant_id,
                dealer.public_key(),
                participant.public_key(),
                &public_polynomial,
            ),
            dkg_mask_transcript(
                b"session-b",
                dealer_id,
                participant_id,
                dealer.public_key(),
                participant.public_key(),
                &public_polynomial,
            )
        );
    }

    #[test]
    fn matches_checked_in_evrf_vector() {
        assert_eq!(vector_value("version"), "0");

        let dealer_secret = HelperSecretKey::from_scalar(
            VestaScalar::from_bytes(hex_array(vector_value("dealer_secret")))
                .expect("canonical dealer secret"),
        );
        let participant_secret = HelperSecretKey::from_scalar(
            VestaScalar::from_bytes(hex_array(vector_value("participant_secret")))
                .expect("canonical participant secret"),
        );
        let dealer_public = HelperPublicKey::from_point(
            VestaPoint::from_bytes(hex_array(vector_value("dealer_public")))
                .expect("canonical dealer public key"),
        );
        let participant_public = HelperPublicKey::from_point(
            VestaPoint::from_bytes(hex_array(vector_value("participant_public")))
                .expect("canonical participant public key"),
        );
        let shared = SharedSecret::from_point(
            VestaPoint::from_bytes(hex_array(vector_value("shared_point")))
                .expect("canonical shared point"),
        );
        let mask = PallasScalar::from_bytes(hex_array(vector_value("mask")))
            .expect("canonical mask scalar");
        let h1 = VestaPoint::from_bytes(hex_array(vector_value("h1"))).expect("canonical H1 point");
        let h2 = VestaPoint::from_bytes(hex_array(vector_value("h2"))).expect("canonical H2 point");

        assert_eq!(dealer_secret.public_key(), dealer_public);
        assert_eq!(participant_secret.public_key(), participant_public);
        assert_eq!(dealer_secret.diffie_hellman(participant_public), shared);
        assert_eq!(participant_secret.diffie_hellman(dealer_public), shared);
        assert_eq!(
            derive_mask(shared, vector_value("transcript").as_bytes()),
            mask
        );
        assert_eq!(
            hash_to_vesta_h1(vector_value("hash_message").as_bytes()),
            h1
        );
        assert_eq!(
            hash_to_vesta_h2(vector_value("hash_message").as_bytes()),
            h2
        );
    }

    fn vector_value(key: &str) -> &'static str {
        EVRF_VECTOR_V0
            .lines()
            .filter(|line| !line.starts_with('#'))
            .find_map(|line| {
                let (candidate, value) = line.split_once('=')?;
                (candidate == key).then_some(value)
            })
            .unwrap_or_else(|| panic!("missing vector key {key}"))
    }

    fn hex_array<const N: usize>(value: &str) -> [u8; N] {
        assert_eq!(value.len(), N * 2, "unexpected hex length");
        let mut out = [0_u8; N];
        for (idx, pair) in value.as_bytes().chunks_exact(2).enumerate() {
            out[idx] = (hex_nibble(pair[0]) << 4) | hex_nibble(pair[1]);
        }
        out
    }

    const fn hex_nibble(byte: u8) -> u8 {
        match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            b'A'..=b'F' => byte - b'A' + 10,
            _ => panic!("invalid hex character"),
        }
    }
}
