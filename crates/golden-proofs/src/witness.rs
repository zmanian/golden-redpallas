//! Shared public/witness consistency checks.

use golden_pallas::{PallasPoint, SharedSecret, VestaPoint, derive_mask};

use crate::{MaskHashKind, ProofError, ProofPublicInputs, ProofWitness};

/// Validate a witness against public inputs using the default
/// ([`MaskHashKind::Blake2b`]) mask hash algorithm.
pub(crate) fn validate_witness(
    public_inputs: &ProofPublicInputs,
    witness: &ProofWitness,
) -> Result<(), ProofError> {
    validate_witness_with_hash(public_inputs, witness, MaskHashKind::default())
}

/// Validate a witness against public inputs for the requested mask hash
/// algorithm.
///
/// The dealer-key and shared-point Diffie-Hellman relations and the mask
/// commitment are always checked. The mask itself is recomputed against the
/// hash-to-field relation matching `hash_kind`, so a Poseidon-derived mask is
/// validated against the Poseidon native path rather than the Blake2b one.
pub(crate) fn validate_witness_with_hash(
    public_inputs: &ProofPublicInputs,
    witness: &ProofWitness,
    hash_kind: MaskHashKind,
) -> Result<(), ProofError> {
    let dealer_public = public_inputs.dealer_public.point();
    let expected_dealer_public = VestaPoint::generator_mul(witness.dealer_secret);
    if dealer_public != expected_dealer_public {
        return Err(ProofError::InvalidWitness);
    }

    let expected_shared = public_inputs
        .participant_public
        .point()
        .mul_scalar(witness.dealer_secret);
    if witness.shared_point != expected_shared {
        return Err(ProofError::InvalidWitness);
    }

    let mask = expected_mask(public_inputs, witness, hash_kind);
    if witness.mask != mask {
        return Err(ProofError::InvalidWitness);
    }

    if public_inputs.mask_commitment != PallasPoint::generator_mul(mask) {
        return Err(ProofError::InvalidWitness);
    }

    Ok(())
}

/// Recompute the mask a valid witness must carry for the given `hash_kind`.
///
/// Blake2b is always available; the Poseidon and eVRF arms are feature-gated.
/// The match stays exhaustive for every enabled subset of those features
/// because each non-default arm is cfg-gated to its own feature, exactly like
/// the [`MaskHashKind`] variants themselves.
fn expected_mask(
    public_inputs: &ProofPublicInputs,
    witness: &ProofWitness,
    hash_kind: MaskHashKind,
) -> golden_pallas::PallasScalar {
    match hash_kind {
        MaskHashKind::Blake2b => derive_mask(
            SharedSecret::from_point(witness.shared_point),
            &public_inputs.mask_transcript(),
        ),
        #[cfg(feature = "poseidon-mask")]
        MaskHashKind::Poseidon => {
            let field = crate::pallas::poseidon::poseidon_hash_native(
                golden_pallas::domains::MASK_TO_FIELD,
                &witness.shared_point.to_bytes(),
                &public_inputs.mask_transcript(),
            );
            crate::pallas::ark_fq_to_pallas_scalar(field)
        }
        #[cfg(feature = "evrf-mask")]
        MaskHashKind::Evrf => crate::pallas::evrf_mask_from_shared(witness.shared_point),
    }
}
