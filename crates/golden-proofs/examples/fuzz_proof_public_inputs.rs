//! Executable fuzz harness for proof public-input decoding.

use std::{env, fs};

use golden_proofs::ProofPublicInputs;

fn main() {
    for path in env::args().skip(1) {
        let input = fs::read(&path).expect("read fuzz input");
        fuzz_one(&input);
    }
}

fn fuzz_one(input: &[u8]) {
    if let Ok(public_inputs) = ProofPublicInputs::from_bytes(input) {
        let _ = public_inputs.mask_transcript();
        let _ = public_inputs.to_bytes();
    }
}

#[cfg(test)]
mod tests {
    use golden_core::{FieldElement, ParticipantId, Polynomial};
    use golden_pallas::{
        HelperPublicKey, PallasPoint, PallasScalar, VestaPoint, VestaScalar, commit_polynomial,
    };
    use golden_proofs::ProofPublicInputs;

    #[test]
    fn proof_public_inputs_fuzz_smoke_accepts_arbitrary_bytes() {
        super::fuzz_one(&[]);
        super::fuzz_one(b"not a proof public input");
        super::fuzz_one(&[0xff; 256]);
    }

    #[test]
    fn proof_public_inputs_fuzz_smoke_accepts_valid_encoding() {
        let public_inputs = ProofPublicInputs {
            session_id: b"proof-public-input-fuzz-smoke".to_vec(),
            dealer_id: ParticipantId::new(10).expect("dealer id"),
            participant_id: ParticipantId::new(2).expect("participant id"),
            dealer_public: HelperPublicKey::from_point(VestaPoint::generator_mul(
                VestaScalar::from_u64(13),
            )),
            participant_public: HelperPublicKey::from_point(VestaPoint::generator_mul(
                VestaScalar::from_u64(31),
            )),
            mask_commitment: PallasPoint::generator_mul(PallasScalar::from_u64(42)),
            public_polynomial: commit_polynomial(&Polynomial::new(vec![
                PallasScalar::from_u64(5),
                PallasScalar::from_u64(7),
            ])),
        };

        super::fuzz_one(&public_inputs.to_bytes());
    }
}
