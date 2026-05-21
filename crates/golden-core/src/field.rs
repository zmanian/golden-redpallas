//! Minimal finite-field interface required by the core DKG logic.

use core::fmt::Debug;

/// A scalar field element used for Shamir sharing.
pub trait FieldElement:
    Copy
    + Clone
    + Debug
    + Eq
    + PartialEq
    + core::ops::Add<Output = Self>
    + core::ops::AddAssign
    + core::ops::Sub<Output = Self>
    + core::ops::SubAssign
    + core::ops::Mul<Output = Self>
    + core::ops::MulAssign
    + core::ops::Neg<Output = Self>
{
    /// Additive identity.
    const ZERO: Self;

    /// Multiplicative identity.
    const ONE: Self;

    /// Construct from a small integer.
    fn from_u64(value: u64) -> Self;

    /// Multiplicative inverse, if the element is non-zero.
    fn invert(self) -> Option<Self>;

    /// Return true if the element is zero.
    #[must_use]
    fn is_zero(self) -> bool {
        self == Self::ZERO
    }
}

#[cfg(test)]
pub(crate) mod test_field {
    use super::FieldElement;

    const MODULUS: u64 = 97;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(crate) struct Fp(pub(crate) u64);

    impl Fp {
        fn reduce(value: u64) -> Self {
            Self(value % MODULUS)
        }
    }

    impl FieldElement for Fp {
        const ZERO: Self = Self(0);
        const ONE: Self = Self(1);

        fn from_u64(value: u64) -> Self {
            Self::reduce(value)
        }

        fn invert(self) -> Option<Self> {
            if self.is_zero() {
                return None;
            }

            let mut base = self;
            let mut exponent = MODULUS - 2;
            let mut acc = Self::ONE;
            while exponent > 0 {
                if exponent & 1 == 1 {
                    acc *= base;
                }
                base *= base;
                exponent >>= 1;
            }
            Some(acc)
        }
    }

    impl core::ops::Add for Fp {
        type Output = Self;

        fn add(self, rhs: Self) -> Self::Output {
            Self::reduce(self.0 + rhs.0)
        }
    }

    impl core::ops::AddAssign for Fp {
        fn add_assign(&mut self, rhs: Self) {
            *self = *self + rhs;
        }
    }

    impl core::ops::Sub for Fp {
        type Output = Self;

        fn sub(self, rhs: Self) -> Self::Output {
            Self::reduce((MODULUS + self.0 - rhs.0) % MODULUS)
        }
    }

    impl core::ops::SubAssign for Fp {
        fn sub_assign(&mut self, rhs: Self) {
            *self = *self - rhs;
        }
    }

    impl core::ops::Mul for Fp {
        type Output = Self;

        fn mul(self, rhs: Self) -> Self::Output {
            Self::reduce(self.0 * rhs.0)
        }
    }

    impl core::ops::MulAssign for Fp {
        fn mul_assign(&mut self, rhs: Self) {
            *self = *self * rhs;
        }
    }

    impl core::ops::Neg for Fp {
        type Output = Self;

        fn neg(self) -> Self::Output {
            if self.is_zero() {
                self
            } else {
                Self(MODULUS - self.0)
            }
        }
    }
}
