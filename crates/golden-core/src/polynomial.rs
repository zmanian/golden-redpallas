//! Shamir polynomial helpers.

use crate::FieldElement;

/// A polynomial with coefficients in ascending order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Polynomial<F> {
    coefficients: Vec<F>,
}

impl<F: FieldElement> Polynomial<F> {
    /// Create a polynomial from coefficients in ascending order.
    #[must_use]
    pub fn new(coefficients: Vec<F>) -> Self {
        Self { coefficients }
    }

    /// Return the constant term.
    #[must_use]
    pub fn constant(&self) -> Option<F> {
        self.coefficients.first().copied()
    }

    /// Return all coefficients.
    #[must_use]
    pub fn coefficients(&self) -> &[F] {
        &self.coefficients
    }

    /// Evaluate with Horner's method.
    #[must_use]
    pub fn evaluate(&self, x: F) -> F {
        self.coefficients
            .iter()
            .rev()
            .copied()
            .fold(F::ZERO, |acc, coeff| (acc * x) + coeff)
    }
}

/// Interpolation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InterpolationError {
    /// At least one duplicate x-coordinate was provided.
    DuplicateXCoordinate,
    /// No shares were provided.
    Empty,
}

/// Reconstruct the polynomial value at zero from `(x, y)` samples.
pub fn interpolate_at_zero<F: FieldElement>(samples: &[(F, F)]) -> Result<F, InterpolationError> {
    if samples.is_empty() {
        return Err(InterpolationError::Empty);
    }

    let mut secret = F::ZERO;
    for (j, (x_j, y_j)) in samples.iter().copied().enumerate() {
        let mut numerator = F::ONE;
        let mut denominator = F::ONE;

        for (m, (x_m, _)) in samples.iter().copied().enumerate() {
            if m == j {
                continue;
            }
            numerator *= -x_m;
            denominator *= x_j - x_m;
        }

        let Some(denominator_inverse) = denominator.invert() else {
            return Err(InterpolationError::DuplicateXCoordinate);
        };

        secret += y_j * numerator * denominator_inverse;
    }

    Ok(secret)
}

#[cfg(test)]
mod tests {
    use super::{Polynomial, interpolate_at_zero};
    use crate::field::test_field::Fp;

    #[test]
    fn evaluates_polynomial() {
        let polynomial = Polynomial::new(vec![Fp(3), Fp(2), Fp(5)]);

        assert_eq!(polynomial.evaluate(Fp(0)), Fp(3));
        assert_eq!(polynomial.evaluate(Fp(2)), Fp(27));
    }

    #[test]
    fn interpolates_constant_term() {
        let polynomial = Polynomial::new(vec![Fp(42), Fp(8), Fp(11)]);
        let samples = [
            (Fp(1), polynomial.evaluate(Fp(1))),
            (Fp(2), polynomial.evaluate(Fp(2))),
            (Fp(3), polynomial.evaluate(Fp(3))),
        ];

        assert_eq!(interpolate_at_zero(&samples), Ok(Fp(42)));
    }
}
