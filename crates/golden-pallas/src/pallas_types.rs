//! Pallas scalar and group adapters.

use core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};

use golden_core::{FieldElement, MaskedShare, ParticipantId, Polynomial, PublicPolynomial};
use pasta_curves::{
    group::{
        Curve, Group, GroupEncoding,
        ff::{Field, PrimeField},
        prime::PrimeCurveAffine,
    },
    pallas,
};

/// Pallas scalar field element used by `RedPallas` and Golden shares.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PallasScalar(pallas::Scalar);

impl PallasScalar {
    /// Wrap a raw `pasta_curves` scalar.
    #[must_use]
    pub const fn from_inner(inner: pallas::Scalar) -> Self {
        Self(inner)
    }

    /// Return the wrapped `pasta_curves` scalar.
    #[must_use]
    pub const fn into_inner(self) -> pallas::Scalar {
        self.0
    }

    /// Return the canonical little-endian field encoding.
    #[must_use]
    pub fn to_bytes(self) -> [u8; 32] {
        self.0.to_repr()
    }

    /// Parse a canonical little-endian field encoding.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Option<Self> {
        Option::<pallas::Scalar>::from(pallas::Scalar::from_repr(bytes)).map(Self)
    }
}

impl FieldElement for PallasScalar {
    const ZERO: Self = Self(<pallas::Scalar as Field>::ZERO);
    const ONE: Self = Self(<pallas::Scalar as Field>::ONE);

    fn from_u64(value: u64) -> Self {
        Self(pallas::Scalar::from(value))
    }

    fn invert(self) -> Option<Self> {
        Option::<pallas::Scalar>::from(self.0.invert()).map(Self)
    }

    fn is_zero(self) -> bool {
        bool::from(self.0.is_zero())
    }
}

impl Add for PallasScalar {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0 + rhs.0)
    }
}

impl AddAssign for PallasScalar {
    fn add_assign(&mut self, rhs: Self) {
        self.0 += rhs.0;
    }
}

impl Sub for PallasScalar {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Self(self.0 - rhs.0)
    }
}

impl SubAssign for PallasScalar {
    fn sub_assign(&mut self, rhs: Self) {
        self.0 -= rhs.0;
    }
}

impl Mul for PallasScalar {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        Self(self.0 * rhs.0)
    }
}

impl MulAssign for PallasScalar {
    fn mul_assign(&mut self, rhs: Self) {
        self.0 *= rhs.0;
    }
}

impl Neg for PallasScalar {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self(-self.0)
    }
}

/// Pallas group element used for public keys and polynomial commitments.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PallasPoint(pallas::Point);

impl PallasPoint {
    /// Wrap a raw `pasta_curves` point.
    #[must_use]
    pub const fn from_inner(inner: pallas::Point) -> Self {
        Self(inner)
    }

    /// Return the wrapped `pasta_curves` point.
    #[must_use]
    pub const fn into_inner(self) -> pallas::Point {
        self.0
    }

    /// Additive identity.
    #[must_use]
    pub fn identity() -> Self {
        Self(pallas::Point::identity())
    }

    /// Standard Pallas generator.
    #[must_use]
    pub fn generator() -> Self {
        Self(pallas::Point::generator())
    }

    /// Multiply the standard generator by a scalar.
    #[must_use]
    pub fn generator_mul(scalar: PallasScalar) -> Self {
        Self(pallas::Point::generator() * scalar.0)
    }

    /// Multiply this point by a scalar.
    #[must_use]
    pub fn mul_scalar(self, scalar: PallasScalar) -> Self {
        Self(self.0 * scalar.0)
    }

    /// Return the canonical compressed encoding.
    #[must_use]
    pub fn to_bytes(self) -> [u8; 32] {
        self.0.to_affine().to_bytes()
    }

    /// Parse a canonical compressed encoding.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Option<Self> {
        Option::<pallas::Affine>::from(pallas::Affine::from_bytes(&bytes))
            .map(|point| Self(point.to_curve()))
    }
}

impl Add for PallasPoint {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0 + rhs.0)
    }
}

impl AddAssign for PallasPoint {
    fn add_assign(&mut self, rhs: Self) {
        self.0 += rhs.0;
    }
}

impl Sub for PallasPoint {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Self(self.0 - rhs.0)
    }
}

impl SubAssign for PallasPoint {
    fn sub_assign(&mut self, rhs: Self) {
        self.0 -= rhs.0;
    }
}

impl Neg for PallasPoint {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self(-self.0)
    }
}

/// Commit each scalar coefficient to the Pallas generator.
#[must_use]
pub fn commit_polynomial(polynomial: &Polynomial<PallasScalar>) -> PublicPolynomial<PallasPoint> {
    PublicPolynomial {
        coefficient_commitments: polynomial
            .coefficients()
            .iter()
            .copied()
            .map(PallasPoint::generator_mul)
            .collect(),
    }
}

/// Evaluate a public polynomial commitment at a participant identifier.
#[must_use]
pub fn evaluate_public_polynomial(
    public_polynomial: &PublicPolynomial<PallasPoint>,
    participant: ParticipantId,
) -> PallasPoint {
    let x = PallasScalar::from_u64(participant.get());
    public_polynomial
        .coefficient_commitments
        .iter()
        .rev()
        .copied()
        .fold(PallasPoint::identity(), |acc, coeff| {
            acc.mul_scalar(x) + coeff
        })
}

/// Verify Golden's public commitment equation for one masked share.
#[must_use]
pub fn verify_masked_share_commitment(
    masked_share: &MaskedShare<PallasScalar, PallasPoint>,
    public_polynomial: &PublicPolynomial<PallasPoint>,
) -> bool {
    let left = PallasPoint::generator_mul(masked_share.value);
    let right = evaluate_public_polynomial(public_polynomial, masked_share.participant)
        + masked_share.mask_commitment;
    left == right
}

#[cfg(test)]
mod tests {
    use super::{
        PallasPoint, PallasScalar, commit_polynomial, evaluate_public_polynomial,
        verify_masked_share_commitment,
    };
    use golden_core::{
        DealerConfig, DealerSecret, FieldElement, ParticipantId, Polynomial, ProofStatus,
        build_transcript, recover_share, verify_transcript,
    };

    fn id(value: u64) -> ParticipantId {
        ParticipantId::new(value).expect("non-zero id")
    }

    #[test]
    fn pallas_scalar_behaves_as_core_field_element() {
        let x = PallasScalar::from_u64(7);
        let y = PallasScalar::from_u64(11);

        assert_eq!((x + y) - y, x);
        assert_eq!(x * x.invert().expect("non-zero"), PallasScalar::ONE);
        assert!(PallasScalar::ZERO.is_zero());
    }

    #[test]
    fn pallas_point_encoding_round_trips() {
        let point = PallasPoint::generator_mul(PallasScalar::from_u64(42));
        let encoded = point.to_bytes();

        assert_eq!(PallasPoint::from_bytes(encoded), Some(point));
    }

    #[test]
    fn pallas_scalar_encoding_round_trips() {
        let scalar = PallasScalar::from_u64(42);
        let encoded = scalar.to_bytes();

        assert_eq!(PallasScalar::from_bytes(encoded), Some(scalar));
    }

    #[test]
    fn rejects_non_canonical_scalar_encoding() {
        assert_eq!(PallasScalar::from_bytes([0xff; 32]), None);
    }

    #[test]
    fn committed_polynomial_matches_scalar_evaluation() {
        let polynomial = Polynomial::new(vec![
            PallasScalar::from_u64(9),
            PallasScalar::from_u64(5),
            PallasScalar::from_u64(2),
        ]);
        let public = commit_polynomial(&polynomial);
        let participant = id(3);

        assert_eq!(
            evaluate_public_polynomial(&public, participant),
            PallasPoint::generator_mul(polynomial.evaluate(PallasScalar::from_u64(3)))
        );
    }

    #[test]
    fn verifies_masked_share_commitment_equation() {
        let participant = id(1);
        let polynomial =
            Polynomial::new(vec![PallasScalar::from_u64(5), PallasScalar::from_u64(7)]);
        let public_polynomial = commit_polynomial(&polynomial);
        let secret = DealerSecret { polynomial };
        let config = DealerConfig {
            dealer: id(10),
            participants: vec![participant],
            public_polynomial,
        };
        let mask = PallasScalar::from_u64(13);
        let mask_commitment = PallasPoint::generator_mul(mask);

        let mut transcript =
            build_transcript(config, &secret, |_| (mask, mask_commitment)).expect("transcript");
        transcript.proof_status = ProofStatus::Verified;

        let verified = verify_transcript(transcript, participant, verify_masked_share_commitment)
            .expect("verified");
        let masked = &verified.as_ref().masked_shares[0];

        assert_eq!(
            recover_share(masked.value, mask),
            secret.polynomial.evaluate(PallasScalar::from_u64(1))
        );
    }

    #[test]
    fn rejects_wrong_mask_commitment() {
        let participant = id(1);
        let polynomial =
            Polynomial::new(vec![PallasScalar::from_u64(5), PallasScalar::from_u64(7)]);
        let public_polynomial = commit_polynomial(&polynomial);
        let secret = DealerSecret { polynomial };
        let config = DealerConfig {
            dealer: id(10),
            participants: vec![participant],
            public_polynomial,
        };
        let mask = PallasScalar::from_u64(13);
        let wrong_mask_commitment = PallasPoint::generator_mul(PallasScalar::from_u64(14));
        let mut transcript = build_transcript(config, &secret, |_| (mask, wrong_mask_commitment))
            .expect("transcript");
        transcript.proof_status = ProofStatus::Verified;

        assert!(
            verify_transcript(transcript, participant, verify_masked_share_commitment,).is_err()
        );
    }
}
