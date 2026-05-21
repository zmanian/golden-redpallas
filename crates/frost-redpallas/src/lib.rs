//! `RedPallas` FROST adapter boundary.
//!
//! Golden output shares must be normalized for Zcash `RedPallas` even-y public
//! keys and then mapped into a re-randomized FROST signing flow.

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
        "not implemented: bind Golden shares to a RedPallas FROST ciphersuite"
    }
}

#[cfg(test)]
mod tests {
    use super::{EvenYAction, YParity, even_y_action};

    #[test]
    fn maps_parity_to_normalization_action() {
        assert_eq!(even_y_action(YParity::Even), EvenYAction::Keep);
        assert_eq!(even_y_action(YParity::Odd), EvenYAction::Negate);
    }
}
