//! Shared public/witness consistency checks.

use golden_pallas::{PallasPoint, VestaPoint, derive_mask};

use crate::{ProofError, ProofPublicInputs, ProofWitness};

pub(crate) fn validate_witness(
    public_inputs: &ProofPublicInputs,
    witness: &ProofWitness,
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

    if public_inputs.shared_point.point() != witness.shared_point {
        return Err(ProofError::InvalidWitness);
    }

    let mask = derive_mask(public_inputs.shared_point, &public_inputs.mask_transcript());
    if public_inputs.mask != mask || witness.mask != mask {
        return Err(ProofError::InvalidWitness);
    }

    if public_inputs.mask_commitment != PallasPoint::generator_mul(mask) {
        return Err(ProofError::InvalidWitness);
    }

    Ok(())
}
