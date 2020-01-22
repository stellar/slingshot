//! Range-preserving arithmetic on signed integers with u64 absolute value.
use core::ops::Neg;
use curve25519_dalek::scalar::Scalar;
use serde::{Deserialize, Serialize};
use std::ops::{Add, Mul};
use subtle::{Choice, ConditionallySelectable};

/// Represents a signed integer with absolute value in the 64-bit range.
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Deserialize, Serialize)]
pub struct SignedInteger(i128);

impl SignedInteger {
    /// Returns Some(x) if self is non-negative
    /// Otherwise returns None.
    pub fn to_u64(&self) -> Option<u64> {
        if self.0 < 0 {
            None
        } else {
            Some(self.0 as u64)
        }
    }

    /// Converts the integer to Scalar.
    pub fn to_scalar(self) -> Scalar {
        self.into()
    }
}

impl From<u64> for SignedInteger {
    fn from(u: u64) -> SignedInteger {
        SignedInteger(u as i128)
    }
}

impl Into<Scalar> for SignedInteger {
    fn into(self) -> Scalar {
        if self.0 < 0 {
            Scalar::zero() - Scalar::from((-self.0) as u64)
        } else {
            Scalar::from(self.0 as u64)
        }
    }
}

impl Add for SignedInteger {
    type Output = Option<SignedInteger>;

    fn add(self, rhs: SignedInteger) -> Option<SignedInteger> {
        let max = u64::max_value() as i128;
        let s = self.0 + rhs.0;
        if s <= max && s >= -max {
            Some(SignedInteger(s))
        } else {
            None
        }
    }
}

impl Mul for SignedInteger {
    type Output = Option<SignedInteger>;

    fn mul(self, rhs: SignedInteger) -> Option<SignedInteger> {
        self.0.checked_mul(rhs.0).and_then(|p| {
            let max = u64::max_value() as i128;
            if p <= max && p >= -max {
                Some(SignedInteger(p))
            } else {
                None
            }
        })
    }
}

impl ConditionallySelectable for SignedInteger {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        SignedInteger(i128::conditional_select(&a.0, &b.0, choice))
    }
}

impl Neg for SignedInteger {
    type Output = SignedInteger;

    fn neg(self) -> SignedInteger {
        SignedInteger(-self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_overflow() {
        let a = SignedInteger::from(u64::max_value());
        let b = SignedInteger::from(0u64);
        assert_eq!((a + b).unwrap(), SignedInteger::from(u64::max_value()));

        let a = SignedInteger::from(u64::max_value());
        let b = SignedInteger::from(1u64);
        assert_eq!(a + b, None);
    }

    #[test]
    fn mul_overflow() {
        let a = SignedInteger::from(u64::max_value());
        let b = SignedInteger::from(1u64);
        assert_eq!((a * b).unwrap(), SignedInteger::from(u64::max_value()));

        let a = SignedInteger::from(u64::max_value());
        let b = -SignedInteger::from(1u64);
        assert_eq!((a * b).unwrap(), -SignedInteger::from(u64::max_value()));

        let a = SignedInteger::from(u64::max_value());
        let b = SignedInteger::from(2u64);
        assert_eq!(a * b, None);

        let a = SignedInteger::from(u64::max_value());
        let b = -SignedInteger::from(2u64);
        assert_eq!(a * b, None);

        let a = SignedInteger::from(u64::max_value());
        let b = SignedInteger::from(u64::max_value());
        assert_eq!(a * b, None);

        let a = SignedInteger::from(u64::max_value());
        let b = -SignedInteger::from(u64::max_value());
        assert_eq!(a * b, None);
    }
}
