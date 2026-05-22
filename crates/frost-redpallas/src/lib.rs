//! `RedPallas` FROST adapter boundary.
//!
//! Golden output shares must be normalized for Zcash `RedPallas` even-y public
//! keys and then mapped into a re-randomized FROST signing flow.

use golden_core::ParticipantId;
use golden_pallas::PallasScalar;

/// Zcash `RedPallas` FROST ciphersuite from the `reddsa` crate.
pub type RedPallasFrostCiphersuite = reddsa::frost::redpallas::PallasBlake2b512;

/// Zcash `RedPallas` FROST participant identifier.
pub type FrostIdentifier = reddsa::frost::redpallas::Identifier;

/// Zcash `RedPallas` FROST signing share.
pub type FrostSigningShare =
    frost_rerandomized::frost_core::frost::keys::SigningShare<RedPallasFrostCiphersuite>;

/// Zcash `RedPallas` FROST verification share.
pub type FrostVerifyingShare =
    frost_rerandomized::frost_core::frost::keys::VerifyingShare<RedPallasFrostCiphersuite>;

/// Zcash `RedPallas` FROST group verifying key.
pub type FrostVerifyingKey = reddsa::frost::redpallas::VerifyingKey;

/// Zcash `RedPallas` FROST public key package.
pub type FrostPublicKeyPackage = reddsa::frost::redpallas::keys::PublicKeyPackage;

/// Zcash `RedPallas` FROST key package for one participant.
pub type FrostKeyPackage = reddsa::frost::redpallas::keys::KeyPackage;

/// ZIP-312 randomized signing parameters for `RedPallas` FROST.
pub type Zip312RandomizedParams = frost_rerandomized::RandomizedParams<RedPallasFrostCiphersuite>;

/// Convert a Golden participant identifier into a `RedPallas` FROST identifier.
pub fn frost_identifier(participant: ParticipantId) -> Result<FrostIdentifier, FrostAdapterError> {
    participant
        .as_u16()
        .try_into()
        .map_err(|_| FrostAdapterError::InvalidIdentifier)
}

/// Convert a Golden scalar share into a `RedPallas` FROST signing share.
pub fn signing_share_from_golden(
    share: PallasScalar,
) -> Result<FrostSigningShare, FrostAdapterError> {
    FrostSigningShare::deserialize(share.to_bytes())
        .map_err(|_| FrostAdapterError::InvalidSigningShare)
}

/// Derive the FROST verification share for a signing share.
#[must_use]
pub fn verifying_share_from_signing_share(share: FrostSigningShare) -> FrostVerifyingShare {
    share.into()
}

/// Golden share material after `RedPallas` even-y normalization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NormalizedFrostShare {
    /// The normalized FROST signing share.
    pub signing_share: FrostSigningShare,
    /// The even-y verification share matching `signing_share`.
    pub verifying_share: FrostVerifyingShare,
    /// The normalization action applied to the input scalar.
    pub action: EvenYAction,
}

/// Convert a Golden scalar share into an even-y `RedPallas` FROST signing share.
pub fn normalized_signing_share_from_golden(
    share: PallasScalar,
) -> Result<NormalizedFrostShare, FrostAdapterError> {
    let signing_share = signing_share_from_golden(share)?;
    let verifying_share = verifying_share_from_signing_share(signing_share);
    let action = even_y_action(verifying_share_y_parity(&verifying_share));

    match action {
        EvenYAction::Keep => Ok(NormalizedFrostShare {
            signing_share,
            verifying_share,
            action,
        }),
        EvenYAction::Negate => {
            let signing_share = signing_share_from_golden(-share)?;
            let verifying_share = verifying_share_from_signing_share(signing_share);
            debug_assert_eq!(verifying_share_y_parity(&verifying_share), YParity::Even);

            Ok(NormalizedFrostShare {
                signing_share,
                verifying_share,
                action,
            })
        }
    }
}

/// Return the y-coordinate parity encoded in a FROST verification share.
#[must_use]
pub fn verifying_share_y_parity(share: &FrostVerifyingShare) -> YParity {
    if (share.serialize()[31] >> 7) == 1 {
        YParity::Odd
    } else {
        YParity::Even
    }
}

/// Create ZIP-312 rerandomized FROST parameters from a Golden Pallas scalar.
#[must_use]
pub fn zip312_randomized_params_from_randomizer(
    public_key_package: &FrostPublicKeyPackage,
    randomizer: PallasScalar,
) -> Zip312RandomizedParams {
    Zip312RandomizedParams::from_randomizer(public_key_package, randomizer.into_inner())
}

/// Build a FROST key package from a Golden participant share.
pub fn key_package_from_golden_share(
    participant: ParticipantId,
    share: PallasScalar,
    group_public: FrostVerifyingKey,
) -> Result<FrostKeyPackage, FrostAdapterError> {
    let identifier = frost_identifier(participant)?;
    let normalized = normalized_signing_share_from_golden(share)?;

    Ok(FrostKeyPackage::new(
        identifier,
        normalized.signing_share,
        normalized.verifying_share,
        group_public,
    ))
}

/// Failure while adapting Golden output to `RedPallas` FROST types.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrostAdapterError {
    /// The participant identifier could not be represented by FROST.
    InvalidIdentifier,
    /// The signing share could not be represented by FROST.
    InvalidSigningShare,
}

/// `RedPallas` public-key parity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum YParity {
    /// Even y-coordinate.
    Even,
    /// Odd y-coordinate.
    Odd,
}

/// Decision made while adapting Golden output to `RedPallas`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvenYAction {
    /// Keep shares and commitments unchanged.
    Keep,
    /// Negate shares and public verification material.
    Negate,
}

/// Decide whether Golden shares must be negated to satisfy `RedPallas` even-y.
#[must_use]
pub const fn even_y_action(parity: YParity) -> EvenYAction {
    match parity {
        YParity::Even => EvenYAction::Keep,
        YParity::Odd => EvenYAction::Negate,
    }
}

/// ZIP-312 support marker.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Zip312RerandomizedFrost;

impl Zip312RerandomizedFrost {
    /// Return the current implementation status.
    #[must_use]
    pub const fn status() -> &'static str {
        "Golden shares map to normalized RedPallas FROST key packages with ZIP-312 randomized parameters"
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use golden_core::{FieldElement, ParticipantId};
    use golden_pallas::{PallasPoint, PallasScalar};

    use super::{
        EvenYAction, FrostPublicKeyPackage, FrostVerifyingKey, RedPallasFrostCiphersuite, YParity,
        even_y_action, frost_identifier, key_package_from_golden_share,
        normalized_signing_share_from_golden, signing_share_from_golden,
        verifying_share_from_signing_share, verifying_share_y_parity,
        zip312_randomized_params_from_randomizer,
    };

    #[test]
    fn maps_parity_to_normalization_action() {
        assert_eq!(even_y_action(YParity::Even), EvenYAction::Keep);
        assert_eq!(even_y_action(YParity::Odd), EvenYAction::Negate);
    }

    #[test]
    fn exposes_reddsa_redpallas_frost_ciphersuite() {
        assert_eq!(
            core::any::type_name::<RedPallasFrostCiphersuite>(),
            "reddsa::frost::redpallas::PallasBlake2b512"
        );
    }

    #[test]
    fn maps_golden_participant_id_to_frost_identifier() {
        let participant = ParticipantId::new(42).expect("valid participant");
        let frost = frost_identifier(participant).expect("frost identifier");
        let expected = 42_u16.try_into().expect("frost identifier");

        assert_eq!(frost, expected);
    }

    #[test]
    fn maps_golden_scalar_to_frost_signing_share() {
        let scalar = PallasScalar::from_u64(7);
        let signing_share = signing_share_from_golden(scalar).expect("signing share");
        let verifying_share = super::verifying_share_from_signing_share(signing_share);

        assert_eq!(signing_share.serialize(), scalar.to_bytes());
        assert_eq!(
            verifying_share.serialize(),
            PallasPoint::generator_mul(scalar).to_bytes()
        );
    }

    #[test]
    fn keeps_even_y_golden_scalar_when_mapping_to_frost() {
        let scalar = scalar_with_parity(YParity::Even);
        let normalized = normalized_signing_share_from_golden(scalar).expect("normalized share");

        assert_eq!(normalized.action, EvenYAction::Keep);
        assert_eq!(normalized.signing_share.serialize(), scalar.to_bytes());
        assert_eq!(
            verifying_share_y_parity(&normalized.verifying_share),
            YParity::Even
        );
    }

    #[test]
    fn negates_odd_y_golden_scalar_when_mapping_to_frost() {
        let scalar = scalar_with_parity(YParity::Odd);
        let normalized = normalized_signing_share_from_golden(scalar).expect("normalized share");
        let expected_scalar = -scalar;

        assert_eq!(normalized.action, EvenYAction::Negate);
        assert_eq!(
            normalized.signing_share.serialize(),
            expected_scalar.to_bytes()
        );
        assert_eq!(
            verifying_share_y_parity(&normalized.verifying_share),
            YParity::Even
        );
    }

    #[test]
    fn zip312_randomization_adds_alpha_to_group_public_key() {
        let participant = frost_identifier(ParticipantId::new(1).expect("participant"))
            .expect("frost identifier");
        let normalized =
            normalized_signing_share_from_golden(PallasScalar::from_u64(8)).expect("normalized");
        let mut signer_pubkeys = HashMap::new();
        signer_pubkeys.insert(participant, normalized.verifying_share);
        let group_public = FrostVerifyingKey::deserialize(normalized.verifying_share.serialize())
            .expect("group public");
        let pubkeys = FrostPublicKeyPackage::new(signer_pubkeys, group_public);
        let randomizer = PallasScalar::from_u64(11);

        let params = zip312_randomized_params_from_randomizer(&pubkeys, randomizer);

        let base = PallasPoint::from_bytes(normalized.verifying_share.serialize())
            .expect("normalized verifying share");
        let expected = (base + PallasPoint::generator_mul(randomizer)).to_bytes();
        assert_eq!(params.randomized_group_public_key().serialize(), expected);
    }

    #[test]
    fn builds_frostd_ready_key_package_from_golden_share() {
        let participant = ParticipantId::new(3).expect("participant");
        let share = PallasScalar::from_u64(8);
        let normalized = normalized_signing_share_from_golden(share).expect("normalized");
        let group_public = FrostVerifyingKey::deserialize(normalized.verifying_share.serialize())
            .expect("group public");

        let key_package =
            key_package_from_golden_share(participant, share, group_public).expect("key package");

        assert_eq!(
            key_package.identifier(),
            &frost_identifier(participant).unwrap()
        );
        assert_eq!(key_package.secret_share(), &normalized.signing_share);
        assert_eq!(key_package.public(), &normalized.verifying_share);
    }

    #[test]
    fn verifies_zcash_redpallas_spendauth_signature_vector() {
        let signature =
            reddsa::Signature::<reddsa::orchard::SpendAuth>::from(REDPALLAS_VECTOR_SIGNATURE);
        let public_key_bytes = reddsa::VerificationKeyBytes::<reddsa::orchard::SpendAuth>::from(
            REDPALLAS_VECTOR_PUBLIC_KEY,
        );
        let public_key =
            reddsa::VerificationKey::try_from(public_key_bytes).expect("verification key");

        assert!(
            public_key
                .verify(REDPALLAS_VECTOR_MESSAGE, &signature)
                .is_ok()
        );
    }

    const REDPALLAS_VECTOR_MESSAGE: &[u8] = b"Golden RedPallas SpendAuth vector v0";
    const REDPALLAS_VECTOR_PUBLIC_KEY: [u8; 32] = [
        90, 0, 54, 84, 0, 51, 106, 127, 128, 4, 96, 161, 208, 107, 40, 99, 239, 165, 172, 159, 0,
        5, 243, 95, 142, 15, 226, 184, 155, 81, 251, 187,
    ];
    const REDPALLAS_VECTOR_SIGNATURE: [u8; 64] = [
        20, 188, 182, 12, 113, 64, 187, 78, 193, 31, 154, 37, 118, 249, 13, 237, 88, 155, 173, 25,
        165, 15, 224, 181, 118, 77, 7, 12, 40, 13, 138, 23, 253, 73, 164, 188, 38, 177, 17, 79,
        132, 236, 84, 78, 26, 112, 134, 227, 7, 234, 29, 243, 178, 136, 187, 155, 230, 14, 15, 21,
        96, 251, 240, 63,
    ];

    fn scalar_with_parity(parity: YParity) -> PallasScalar {
        (1..=128)
            .map(PallasScalar::from_u64)
            .find(|scalar| {
                let share = signing_share_from_golden(*scalar).expect("signing share");
                let verifying_share = verifying_share_from_signing_share(share);
                verifying_share_y_parity(&verifying_share) == parity
            })
            .expect("test fixture scalar with requested parity")
    }
}
