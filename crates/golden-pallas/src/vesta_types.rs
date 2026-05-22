//! Vesta helper-curve adapters for the future Golden eVRF.

use core::ops::{Add, AddAssign, Neg, Sub, SubAssign};

use pasta_curves::{
    arithmetic::{Coordinates, CurveAffine},
    group::{
        Curve, Group, GroupEncoding,
        ff::{Field, PrimeField},
        prime::PrimeCurveAffine,
    },
    vesta,
};

use crate::PallasScalar;

/// Vesta scalar used for helper-curve group operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VestaScalar(vesta::Scalar);

impl VestaScalar {
    /// Wrap a raw `pasta_curves` scalar.
    #[must_use]
    pub const fn from_inner(inner: vesta::Scalar) -> Self {
        Self(inner)
    }

    /// Return the wrapped `pasta_curves` scalar.
    #[must_use]
    pub const fn into_inner(self) -> vesta::Scalar {
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
        Option::<vesta::Scalar>::from(vesta::Scalar::from_repr(bytes)).map(Self)
    }

    /// Construct from a small integer.
    #[must_use]
    pub fn from_u64(value: u64) -> Self {
        Self(vesta::Scalar::from(value))
    }

    /// Multiplicative identity.
    pub const ONE: Self = Self(<vesta::Scalar as Field>::ONE);
}

/// Vesta group element used by the helper-curve eVRF.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VestaPoint(vesta::Point);

impl VestaPoint {
    /// Wrap a raw `pasta_curves` point.
    #[must_use]
    pub const fn from_inner(inner: vesta::Point) -> Self {
        Self(inner)
    }

    /// Return the wrapped `pasta_curves` point.
    #[must_use]
    pub const fn into_inner(self) -> vesta::Point {
        self.0
    }

    /// Additive identity.
    #[must_use]
    pub fn identity() -> Self {
        Self(vesta::Point::identity())
    }

    /// Standard Vesta generator.
    #[must_use]
    pub fn generator() -> Self {
        Self(vesta::Point::generator())
    }

    /// Multiply the standard generator by a Vesta scalar.
    #[must_use]
    pub fn generator_mul(scalar: VestaScalar) -> Self {
        Self(vesta::Point::generator() * scalar.into_inner())
    }

    /// Multiply this point by a Vesta scalar.
    #[must_use]
    pub fn mul_scalar(self, scalar: VestaScalar) -> Self {
        Self(self.0 * scalar.into_inner())
    }

    /// Return the canonical compressed encoding.
    #[must_use]
    pub fn to_bytes(self) -> [u8; 32] {
        self.0.to_affine().to_bytes()
    }

    /// Return affine coordinates as Pallas scalar-field elements.
    #[must_use]
    pub fn affine_coordinates(self) -> Option<(PallasScalar, PallasScalar)> {
        let affine = self.0.to_affine();
        Option::<Coordinates<vesta::Affine>>::from(affine.coordinates()).map(|coords| {
            (
                PallasScalar::from_inner(*coords.x()),
                PallasScalar::from_inner(*coords.y()),
            )
        })
    }

    /// Parse a canonical compressed encoding.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Option<Self> {
        Option::<vesta::Affine>::from(vesta::Affine::from_bytes(&bytes))
            .map(|point| Self(point.to_curve()))
    }
}

impl Add for VestaPoint {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0 + rhs.0)
    }
}

impl AddAssign for VestaPoint {
    fn add_assign(&mut self, rhs: Self) {
        self.0 += rhs.0;
    }
}

impl Sub for VestaPoint {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Self(self.0 - rhs.0)
    }
}

impl SubAssign for VestaPoint {
    fn sub_assign(&mut self, rhs: Self) {
        self.0 -= rhs.0;
    }
}

impl Neg for VestaPoint {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self(-self.0)
    }
}

#[cfg(test)]
mod tests {
    use golden_core::FieldElement;

    use super::{VestaPoint, VestaScalar};

    #[test]
    fn vesta_point_encoding_round_trips() {
        let point = VestaPoint::generator_mul(VestaScalar::from_u64(42));
        let encoded = point.to_bytes();

        assert_eq!(VestaPoint::from_bytes(encoded), Some(point));
    }

    #[test]
    fn vesta_point_exposes_affine_coordinates() {
        let point = VestaPoint::generator_mul(VestaScalar::from_u64(42));
        let (x, y) = point.affine_coordinates().expect("non-identity point");
        let five = crate::PallasScalar::from_u64(5);

        assert_eq!(y * y, (x * x * x) + five);
    }

    #[test]
    fn vesta_scalar_encoding_round_trips() {
        let scalar = VestaScalar::from_u64(42);
        let encoded = scalar.to_bytes();

        assert_eq!(VestaScalar::from_bytes(encoded), Some(scalar));
    }
}
