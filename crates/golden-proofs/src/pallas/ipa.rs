//! Pallas inner-product argument scaffolding.
//!
//! This module implements the logarithmic inner-product proof layer used by
//! Bulletproofs. It is still a proof primitive rather than a full R1CS
//! Bulletproofs backend.

use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex, OnceLock},
};

use blake2b_simd::Params;
use golden_core::FieldElement;
use golden_pallas::{PallasPoint, PallasScalar};
use rayon::prelude::*;

use super::derive_pallas_generator;
use crate::ProofError;

const IPA_TRANSCRIPT_DOMAIN: &[u8] = b"GoldenRedPallas/PallasIpaTranscript/v1";
const IPA_SETUP_G_LABEL: &[u8] = b"ipa-g";
const IPA_SETUP_H_LABEL: &[u8] = b"ipa-h";
const IPA_SETUP_Q_LABEL: &[u8] = b"ipa-q";
const IPA_MAGIC: &[u8; 4] = b"GIPA";
const IPA_VERSION: u8 = 0;

/// Deterministic Pallas generator vectors for an inner-product argument.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PallasIpaSetup {
    g: Arc<[PallasPoint]>,
    h: Arc<[PallasPoint]>,
    product_generator: PallasPoint,
    transcript_digest: [u8; 32],
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct IpaSetupCacheKey {
    domain: Vec<u8>,
    log_len: u8,
}

static IPA_SETUP_CACHE: OnceLock<Mutex<BTreeMap<IpaSetupCacheKey, PallasIpaSetup>>> =
    OnceLock::new();

impl PallasIpaSetup {
    /// Build a deterministic test setup for `2^log_len` vector slots.
    ///
    /// # Panics
    ///
    /// Panics if `log_len` is too large to fit the vector length in `usize`.
    #[must_use]
    pub fn deterministic(domain: &[u8], log_len: u8) -> Self {
        let key = IpaSetupCacheKey {
            domain: domain.to_vec(),
            log_len,
        };
        let cache = IPA_SETUP_CACHE.get_or_init(|| Mutex::new(BTreeMap::new()));
        if let Some(setup) = cache
            .lock()
            .expect("IPA setup cache mutex is not poisoned")
            .get(&key)
            .cloned()
        {
            return setup;
        }

        let len = 1_usize
            .checked_shl(u32::from(log_len))
            .expect("Pallas IPA vector length fits in usize");
        let g = Arc::<[PallasPoint]>::from(
            (0..len)
                .into_par_iter()
                .map(|index| derive_setup_generator(domain, IPA_SETUP_G_LABEL, index))
                .collect::<Vec<_>>(),
        );
        let h = Arc::<[PallasPoint]>::from(
            (0..len)
                .into_par_iter()
                .map(|index| derive_setup_generator(domain, IPA_SETUP_H_LABEL, index))
                .collect::<Vec<_>>(),
        );
        let product_generator = derive_setup_generator(domain, IPA_SETUP_Q_LABEL, 0);
        let transcript_digest = setup_transcript_digest(&g, &h, product_generator);

        let setup = Self {
            g,
            h,
            product_generator,
            transcript_digest,
        };
        cache
            .lock()
            .expect("IPA setup cache mutex is not poisoned")
            .entry(key)
            .or_insert_with(|| setup.clone())
            .clone()
    }

    fn supports_len(&self, len: usize) -> bool {
        len != 0 && len.is_power_of_two() && self.g.len() >= len && self.h.len() >= len
    }

    /// Left-side IPA generators.
    #[must_use]
    pub fn g(&self) -> &[PallasPoint] {
        &self.g
    }

    /// Right-side IPA generators.
    #[must_use]
    pub fn h(&self) -> &[PallasPoint] {
        &self.h
    }

    /// Product-binding generator.
    #[must_use]
    pub const fn product_generator(&self) -> PallasPoint {
        self.product_generator
    }

    pub(super) const fn transcript_digest(&self) -> [u8; 32] {
        self.transcript_digest
    }
}

/// Public claim verified by a Pallas inner-product proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PallasIpaClaim {
    /// Commitment to the witness vectors.
    pub commitment: PallasPoint,
    /// Claimed inner product `<a, b>`.
    pub product: PallasScalar,
    /// Powers challenge used to weight the right generator vector.
    pub y: PallasScalar,
    /// Base-2 logarithm of the witness vector length.
    pub log_len: u8,
}

/// Private vector witness for a Pallas inner-product proof.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PallasIpaWitness {
    a: Vec<PallasScalar>,
    b: Vec<PallasScalar>,
}

impl PallasIpaWitness {
    /// Create a witness and its matching public claim.
    #[must_use]
    pub fn new_with_claim<I>(
        setup: &PallasIpaSetup,
        y: PallasScalar,
        elements: I,
    ) -> Option<(Self, PallasIpaClaim)>
    where
        I: IntoIterator<Item = (PallasScalar, PallasScalar)>,
    {
        let witness = Self::new(elements)?;
        let len = witness.a.len();
        if !setup.supports_len(len) {
            return None;
        }

        let h = weighted_h_generators(&setup.h[..len], y);
        let commitment = msm(&setup.g[..len], &witness.a) + msm(&h, &witness.b);
        let product = inner_product(&witness.a, &witness.b);
        let claim = PallasIpaClaim {
            commitment,
            product,
            y,
            log_len: log_len(len),
        };

        Some((witness, claim))
    }

    fn new<I>(elements: I) -> Option<Self>
    where
        I: IntoIterator<Item = (PallasScalar, PallasScalar)>,
    {
        let (a, b): (Vec<_>, Vec<_>) = elements.into_iter().unzip();
        let len = a.len();
        if len == 0 || !len.is_power_of_two() {
            return None;
        }

        Some(Self { a, b })
    }
}

/// Logarithmic Pallas inner-product proof.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PallasIpaProof {
    l_r: Vec<(PallasPoint, PallasPoint)>,
    a_final: PallasScalar,
    b_final: PallasScalar,
}

impl PallasIpaProof {
    /// Prove the supplied inner-product claim.
    pub fn prove(
        setup: &PallasIpaSetup,
        claim: &PallasIpaClaim,
        witness: PallasIpaWitness,
    ) -> Result<Self, ProofError> {
        let len = claim_len(claim)?;
        if !setup.supports_len(len) || witness.a.len() != len || witness.b.len() != len {
            return Err(ProofError::InvalidWitness);
        }
        if claim.product != inner_product(&witness.a, &witness.b) {
            return Err(ProofError::InvalidWitness);
        }

        let mut transcript = IpaTranscript::new();
        transcript.commit_setup(setup, len);
        transcript.commit_claim(claim);
        let product_challenge = transcript.challenge(b"product-binding");
        let product_generator = setup.product_generator.mul_scalar(product_challenge);

        let mut left_scalars = witness.a;
        let mut right_scalars = witness.b;
        let mut left_generators = setup.g[..len].to_vec();
        let mut right_generators = weighted_h_generators(&setup.h[..len], claim.y);
        let mut l_r = Vec::with_capacity(usize::from(claim.log_len));

        while left_scalars.len() > 1 {
            let half = left_scalars.len() / 2;
            let (a_lo, a_hi) = left_scalars.split_at(half);
            let (b_lo, b_hi) = right_scalars.split_at(half);
            let (g_lo, g_hi) = left_generators.split_at(half);
            let (h_lo, h_hi) = right_generators.split_at(half);

            let product_left = inner_product(a_lo, b_hi);
            let product_right = inner_product(a_hi, b_lo);
            let l_point =
                msm(g_hi, a_lo) + msm(h_lo, b_hi) + product_generator.mul_scalar(product_left);
            let r_point =
                msm(g_lo, a_hi) + msm(h_hi, b_lo) + product_generator.mul_scalar(product_right);

            transcript.commit_round(l_point, r_point);
            let round_challenge = transcript.challenge(b"round");
            let round_challenge_inv = round_challenge.invert().ok_or(ProofError::InvalidProof)?;

            left_scalars = fold_scalars(a_lo, a_hi, round_challenge, round_challenge_inv);
            right_scalars = fold_scalars(b_lo, b_hi, round_challenge_inv, round_challenge);
            left_generators = fold_points(g_lo, g_hi, round_challenge_inv, round_challenge);
            right_generators = fold_points(h_lo, h_hi, round_challenge, round_challenge_inv);
            l_r.push((l_point, r_point));
        }

        Ok(Self {
            l_r,
            a_final: left_scalars[0],
            b_final: right_scalars[0],
        })
    }

    /// Verify this proof against a public inner-product claim.
    pub fn verify(&self, setup: &PallasIpaSetup, claim: &PallasIpaClaim) -> Result<(), ProofError> {
        let len = claim_len(claim)?;
        if !setup.supports_len(len) || self.l_r.len() != usize::from(claim.log_len) {
            return Err(ProofError::InvalidProof);
        }

        let mut transcript = IpaTranscript::new();
        transcript.commit_setup(setup, len);
        transcript.commit_claim(claim);
        let product_challenge = transcript.challenge(b"product-binding");
        let product_generator = setup.product_generator.mul_scalar(product_challenge);

        let mut folded_commitment = claim.commitment + product_generator.mul_scalar(claim.product);
        let mut left_generators = setup.g[..len].to_vec();
        let mut right_generators = weighted_h_generators(&setup.h[..len], claim.y);

        for &(l_point, r_point) in &self.l_r {
            transcript.commit_round(l_point, r_point);
            let round_challenge = transcript.challenge(b"round");
            let round_challenge_inv = round_challenge.invert().ok_or(ProofError::InvalidProof)?;
            folded_commitment += l_point.mul_scalar(round_challenge * round_challenge)
                + r_point.mul_scalar(round_challenge_inv * round_challenge_inv);

            let half = left_generators.len() / 2;
            let (g_lo, g_hi) = left_generators.split_at(half);
            let (h_lo, h_hi) = right_generators.split_at(half);
            left_generators = fold_points(g_lo, g_hi, round_challenge_inv, round_challenge);
            right_generators = fold_points(h_lo, h_hi, round_challenge, round_challenge_inv);
        }

        let expected = left_generators[0].mul_scalar(self.a_final)
            + right_generators[0].mul_scalar(self.b_final)
            + product_generator.mul_scalar(self.a_final * self.b_final);
        if folded_commitment == expected {
            Ok(())
        } else {
            Err(ProofError::InvalidProof)
        }
    }

    /// Serialize this proof into a compact byte encoding.
    ///
    /// # Panics
    ///
    /// Panics if the proof has more than 255 IPA rounds. Proofs produced by
    /// this module cannot exceed that because claim lengths are encoded by a
    /// `u8` logarithm.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(6 + (64 * self.l_r.len()) + 64);
        bytes.extend_from_slice(IPA_MAGIC);
        bytes.push(IPA_VERSION);
        bytes.push(u8::try_from(self.l_r.len()).expect("IPA round count fits in u8"));
        for &(l, r) in &self.l_r {
            bytes.extend_from_slice(&l.to_bytes());
            bytes.extend_from_slice(&r.to_bytes());
        }
        bytes.extend_from_slice(&self.a_final.to_bytes());
        bytes.extend_from_slice(&self.b_final.to_bytes());
        bytes
    }

    /// Parse a proof produced by [`Self::to_bytes`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ProofError> {
        if bytes.len() < 70 || &bytes[..4] != IPA_MAGIC || bytes[4] != IPA_VERSION {
            return Err(ProofError::InvalidProof);
        }

        let rounds = usize::from(bytes[5]);
        let expected_len = 6 + (64 * rounds) + 64;
        if bytes.len() != expected_len {
            return Err(ProofError::InvalidProof);
        }

        let mut offset = 6;
        let mut l_r = Vec::with_capacity(rounds);
        for _ in 0..rounds {
            let l = read_point(bytes, &mut offset)?;
            let r = read_point(bytes, &mut offset)?;
            l_r.push((l, r));
        }
        let a_final = read_scalar(bytes, &mut offset)?;
        let b_final = read_scalar(bytes, &mut offset)?;

        Ok(Self {
            l_r,
            a_final,
            b_final,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct IpaTranscript {
    bytes: Vec<u8>,
}

impl IpaTranscript {
    fn new() -> Self {
        let mut transcript = Self { bytes: Vec::new() };
        transcript.commit_bytes(b"domain", IPA_TRANSCRIPT_DOMAIN);
        transcript
    }

    fn commit_setup(&mut self, setup: &PallasIpaSetup, len: usize) {
        self.commit_u64(b"len", len as u64);
        self.commit_bytes(b"setup-digest", &setup.transcript_digest);
    }

    fn commit_claim(&mut self, claim: &PallasIpaClaim) {
        self.commit_point(b"commitment", claim.commitment);
        self.commit_scalar(b"product", claim.product);
        self.commit_scalar(b"y", claim.y);
        self.commit_bytes(b"log-len", &[claim.log_len]);
    }

    fn commit_round(&mut self, l: PallasPoint, r: PallasPoint) {
        self.commit_point(b"L", l);
        self.commit_point(b"R", r);
    }

    fn challenge(&mut self, label: &[u8]) -> PallasScalar {
        for counter in 0_u64.. {
            let mut state = Params::new().hash_length(64).to_state();
            state.update(IPA_TRANSCRIPT_DOMAIN);
            update_len_prefixed(&mut state, &self.bytes);
            update_len_prefixed(&mut state, label);
            state.update(&counter.to_le_bytes());

            let hash = state.finalize();
            let mut uniform = [0_u8; 64];
            uniform.copy_from_slice(hash.as_bytes());
            let scalar = PallasScalar::from_uniform_bytes(&uniform);
            if !scalar.is_zero() {
                self.commit_bytes(b"challenge", label);
                self.commit_scalar(b"challenge-value", scalar);
                return scalar;
            }
        }
        unreachable!("u64 challenge counter space exhausted");
    }

    fn commit_point(&mut self, label: &[u8], point: PallasPoint) {
        self.commit_bytes(label, &point.to_bytes());
    }

    fn commit_scalar(&mut self, label: &[u8], scalar: PallasScalar) {
        self.commit_bytes(label, &scalar.to_bytes());
    }

    fn commit_u64(&mut self, label: &[u8], value: u64) {
        self.commit_bytes(label, &value.to_le_bytes());
    }

    fn commit_bytes(&mut self, label: &[u8], bytes: &[u8]) {
        self.bytes
            .extend_from_slice(&(label.len() as u64).to_le_bytes());
        self.bytes.extend_from_slice(label);
        self.bytes
            .extend_from_slice(&(bytes.len() as u64).to_le_bytes());
        self.bytes.extend_from_slice(bytes);
    }
}

fn derive_setup_generator(domain: &[u8], kind: &[u8], index: usize) -> PallasPoint {
    let mut label = Vec::with_capacity(domain.len() + kind.len() + 24);
    label.extend_from_slice(&(domain.len() as u64).to_le_bytes());
    label.extend_from_slice(domain);
    label.extend_from_slice(&(kind.len() as u64).to_le_bytes());
    label.extend_from_slice(kind);
    label.extend_from_slice(&(index as u64).to_le_bytes());
    derive_pallas_generator(&label)
}

fn setup_transcript_digest(
    g: &[PallasPoint],
    h: &[PallasPoint],
    product_generator: PallasPoint,
) -> [u8; 32] {
    let mut state = Params::new().hash_length(32).to_state();
    state.update(IPA_TRANSCRIPT_DOMAIN);
    state.update(b"setup-digest/v0");
    state.update(&(g.len() as u64).to_le_bytes());
    for generator in g {
        state.update(&generator.to_bytes());
    }
    state.update(&(h.len() as u64).to_le_bytes());
    for generator in h {
        state.update(&generator.to_bytes());
    }
    state.update(&product_generator.to_bytes());
    let digest = state.finalize();
    let mut bytes = [0_u8; 32];
    bytes.copy_from_slice(digest.as_bytes());
    bytes
}

fn claim_len(claim: &PallasIpaClaim) -> Result<usize, ProofError> {
    1_usize
        .checked_shl(u32::from(claim.log_len))
        .filter(|len| *len != 0)
        .ok_or(ProofError::InvalidProof)
}

fn log_len(len: usize) -> u8 {
    u8::try_from(len.trailing_zeros()).expect("power-of-two length log fits in u8")
}

fn weighted_h_generators(h: &[PallasPoint], y: PallasScalar) -> Vec<PallasPoint> {
    let powers = scalar_powers_from_one(y, h.len());
    h.par_iter()
        .zip(powers.par_iter())
        .map(|(&generator, &power)| generator.mul_scalar(power))
        .collect()
}

fn inner_product(a: &[PallasScalar], b: &[PallasScalar]) -> PallasScalar {
    a.par_iter()
        .zip(b.par_iter())
        .map(|(&lhs, &rhs)| lhs * rhs)
        .reduce(|| PallasScalar::ZERO, |acc, term| acc + term)
}

fn msm(points: &[PallasPoint], scalars: &[PallasScalar]) -> PallasPoint {
    points
        .par_iter()
        .zip(scalars.par_iter())
        .map(|(&point, &scalar)| point.mul_scalar(scalar))
        .reduce(PallasPoint::identity, |acc, point| acc + point)
}

fn fold_scalars(
    lo: &[PallasScalar],
    hi: &[PallasScalar],
    lo_weight: PallasScalar,
    hi_weight: PallasScalar,
) -> Vec<PallasScalar> {
    lo.par_iter()
        .zip(hi.par_iter())
        .map(|(&lhs, &rhs)| (lhs * lo_weight) + (rhs * hi_weight))
        .collect()
}

fn fold_points(
    lo: &[PallasPoint],
    hi: &[PallasPoint],
    lo_weight: PallasScalar,
    hi_weight: PallasScalar,
) -> Vec<PallasPoint> {
    lo.par_iter()
        .zip(hi.par_iter())
        .map(|(&lhs, &rhs)| lhs.mul_scalar(lo_weight) + rhs.mul_scalar(hi_weight))
        .collect()
}

fn scalar_powers_from_one(base: PallasScalar, len: usize) -> Vec<PallasScalar> {
    let mut powers = Vec::with_capacity(len);
    let mut current = PallasScalar::ONE;
    for _ in 0..len {
        powers.push(current);
        current *= base;
    }
    powers
}

fn update_len_prefixed(state: &mut blake2b_simd::State, bytes: &[u8]) {
    state.update(&(bytes.len() as u64).to_le_bytes());
    state.update(bytes);
}

fn read_point(bytes: &[u8], offset: &mut usize) -> Result<PallasPoint, ProofError> {
    let point =
        PallasPoint::from_bytes(read_array(bytes, offset)?).ok_or(ProofError::InvalidProof)?;
    Ok(point)
}

fn read_scalar(bytes: &[u8], offset: &mut usize) -> Result<PallasScalar, ProofError> {
    let scalar =
        PallasScalar::from_bytes(read_array(bytes, offset)?).ok_or(ProofError::InvalidProof)?;
    Ok(scalar)
}

fn read_array<const N: usize>(bytes: &[u8], offset: &mut usize) -> Result<[u8; N], ProofError> {
    let end = offset.checked_add(N).ok_or(ProofError::InvalidProof)?;
    let slice = bytes.get(*offset..end).ok_or(ProofError::InvalidProof)?;
    *offset = end;
    slice.try_into().map_err(|_| ProofError::InvalidProof)
}

#[cfg(test)]
mod tests {
    use golden_core::FieldElement;
    use golden_pallas::PallasScalar;

    use super::{IpaTranscript, PallasIpaClaim, PallasIpaProof, PallasIpaSetup, PallasIpaWitness};
    use crate::ProofError;

    fn valid_case() -> (PallasIpaSetup, PallasIpaClaim, PallasIpaWitness) {
        let setup = PallasIpaSetup::deterministic(b"ipa-test", 2);
        let elements = [
            (PallasScalar::from_u64(3), PallasScalar::from_u64(4)),
            (PallasScalar::from_u64(5), PallasScalar::from_u64(6)),
            (PallasScalar::from_u64(7), PallasScalar::from_u64(8)),
            (PallasScalar::from_u64(9), PallasScalar::from_u64(10)),
        ];
        let (witness, claim) =
            PallasIpaWitness::new_with_claim(&setup, PallasScalar::from_u64(11), elements)
                .expect("valid witness");
        (setup, claim, witness)
    }

    #[test]
    fn ipa_proof_verifies_valid_inner_product() {
        let (setup, claim, witness) = valid_case();
        let proof = PallasIpaProof::prove(&setup, &claim, witness).expect("proof");

        assert_eq!(proof.verify(&setup, &claim), Ok(()));
    }

    #[test]
    fn ipa_proof_roundtrips_through_bytes() {
        let (setup, claim, witness) = valid_case();
        let proof = PallasIpaProof::prove(&setup, &claim, witness).expect("proof");
        let decoded = PallasIpaProof::from_bytes(&proof.to_bytes()).expect("decode");

        assert_eq!(decoded, proof);
        assert_eq!(decoded.verify(&setup, &claim), Ok(()));
    }

    #[test]
    fn ipa_verifier_rejects_wrong_product() {
        let (setup, mut claim, witness) = valid_case();
        let proof = PallasIpaProof::prove(&setup, &claim, witness).expect("proof");
        claim.product += PallasScalar::ONE;

        assert_eq!(proof.verify(&setup, &claim), Err(ProofError::InvalidProof));
    }

    #[test]
    fn ipa_verifier_rejects_wrong_claim_length() {
        let (setup, mut claim, witness) = valid_case();
        let proof = PallasIpaProof::prove(&setup, &claim, witness).expect("proof");
        claim.log_len += 1;

        assert_eq!(proof.verify(&setup, &claim), Err(ProofError::InvalidProof));
    }

    #[test]
    fn deterministic_setup_reuses_cached_generator_vectors() {
        let first = PallasIpaSetup::deterministic(b"ipa-cache-test", 2);
        let second = PallasIpaSetup::deterministic(b"ipa-cache-test", 2);

        assert!(std::ptr::eq(first.g().as_ptr(), second.g().as_ptr()));
        assert!(std::ptr::eq(first.h().as_ptr(), second.h().as_ptr()));
    }

    #[test]
    fn ipa_transcript_commits_setup_by_digest() {
        let setup = PallasIpaSetup::deterministic(b"ipa-transcript-cache-test", 6);
        let mut transcript = IpaTranscript::new();
        transcript.commit_setup(&setup, 64);

        assert!(
            transcript.bytes.len() < 160,
            "transcript setup prefix should stay digest-sized, got {} bytes",
            transcript.bytes.len()
        );
    }
}
