//! Arithmetic and conversion API for ScalarWitness.

use curve25519_dalek::scalar::Scalar;
use serde::{Deserialize, Serialize};
use spacesuit::SignedInteger;

use crate::encoding::*;
use crate::errors::VMError;
use std::ops::{Add, Mul, Neg, Sub};
use std::u64;

/// Represents a concrete kind of a number represented by a scalar.
#[derive(Copy, Clone, Debug, PartialEq, Deserialize, Serialize)]
pub enum ScalarWitness {
    /// `ScalarKind::Integer` represents a signed integer with 64-bit absolute value (think "i65")
    Integer(SignedInteger),
    /// `ScalarKind::Scalar` represents a scalar modulo group order.
    Scalar(Scalar),
}

impl Encodable for ScalarWitness {
    /// Converts to a scalar and encodes it to a vec of bytes.
    fn encode(&self, w: &mut impl Writer) -> Result<(), WriteError> {
        w.write_scalar(b"scalar", &self.to_scalar())
    }
}
impl ExactSizeEncodable for ScalarWitness {
    fn encoded_size(&self) -> usize {
        32
    }
}

impl ScalarWitness {
    /// Converts the witness to an integer if it is an integer
    pub fn to_integer(self) -> Result<SignedInteger, VMError> {
        match self {
            ScalarWitness::Integer(i) => Ok(i),
            ScalarWitness::Scalar(_) => Err(VMError::TypeNotSignedInteger),
        }
    }

    /// Converts the witness to a scalar.
    pub fn to_scalar(self) -> Scalar {
        match self {
            ScalarWitness::Integer(i) => i.into(),
            ScalarWitness::Scalar(s) => s,
        }
    }

    /// Converts `Option<ScalarWitness>` into optional integer if it is one.
    pub fn option_to_integer(assignment: Option<Self>) -> Result<Option<SignedInteger>, VMError> {
        match assignment {
            None => Ok(None),
            Some(ScalarWitness::Integer(i)) => Ok(Some(i)),
            Some(ScalarWitness::Scalar(_)) => Err(VMError::TypeNotSignedInteger),
        }
    }

    /// Returns true if the scalar fits in u64.
    pub fn in_range(self) -> bool {
        let scalar_bytes = self.to_scalar().to_bytes();
        (&scalar_bytes[8..32]).iter().all(|v| v == &0)
    }
}

// Implementing arithmetic operatons for ScalarWitness

impl Neg for ScalarWitness {
    type Output = ScalarWitness;

    fn neg(self) -> ScalarWitness {
        match self {
            ScalarWitness::Integer(a) => ScalarWitness::Integer(-a),
            ScalarWitness::Scalar(a) => ScalarWitness::Scalar(-a),
        }
    }
}

impl Add for ScalarWitness {
    type Output = ScalarWitness;

    fn add(self, rhs: ScalarWitness) -> ScalarWitness {
        match (self, rhs) {
            (ScalarWitness::Integer(a), ScalarWitness::Integer(b)) => match a + b {
                Some(res) => ScalarWitness::Integer(res),
                None => ScalarWitness::Scalar(a.to_scalar() + b.to_scalar()),
            },
            (a, b) => ScalarWitness::Scalar(a.to_scalar() + b.to_scalar()),
        }
    }
}

impl Sub for ScalarWitness {
    type Output = ScalarWitness;

    fn sub(self, rhs: ScalarWitness) -> ScalarWitness {
        -self + rhs
    }
}

impl Mul for ScalarWitness {
    type Output = ScalarWitness;

    fn mul(self, rhs: ScalarWitness) -> ScalarWitness {
        match (self, rhs) {
            (ScalarWitness::Integer(a), ScalarWitness::Integer(b)) => match a * b {
                Some(res) => ScalarWitness::Integer(res),
                None => ScalarWitness::Scalar(a.to_scalar() * b.to_scalar()),
            },
            (a, b) => ScalarWitness::Scalar(a.to_scalar() * b.to_scalar()),
        }
    }
}

// Upcasting integers/scalars into ScalarWitness.

impl From<u64> for ScalarWitness {
    fn from(x: u64) -> Self {
        ScalarWitness::Integer(x.into())
    }
}

impl From<Scalar> for ScalarWitness {
    fn from(x: Scalar) -> Self {
        ScalarWitness::Scalar(x)
    }
}

// Converting scalar witness to an opaque Scalar.

impl Into<Scalar> for ScalarWitness {
    fn into(self) -> Scalar {
        self.to_scalar()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encoded_size() {
        assert_eq!(ScalarWitness::Integer(1.into()).encoded_size(), 32);
        assert_eq!(
            ScalarWitness::Scalar(Scalar::from(0xffu64)).encoded_size(),
            32
        );
    }

    #[test]
    fn to_integer() {
        // ok
        let x = ScalarWitness::Integer(24.into());
        assert_eq!(x.to_integer().unwrap().to_u64().unwrap(), 24);

        // ok negative
        let x = -ScalarWitness::Integer(24.into());
        assert_eq!((-x.to_integer().unwrap()).to_u64().unwrap(), 24);

        // err
        let x = ScalarWitness::Scalar(24u64.into());
        assert_eq!(x.to_integer().unwrap_err(), VMError::TypeNotSignedInteger);
    }

    #[test]
    fn to_scalar() {
        // +int
        assert_eq!(
            ScalarWitness::Integer(1.into()).to_scalar(),
            Scalar::from(1u64)
        );

        // -int
        assert_eq!(
            ScalarWitness::Integer(-SignedInteger::from(1u64)).to_scalar(),
            -Scalar::from(1u64)
        );

        // scalar
        assert_eq!(
            ScalarWitness::Scalar(Scalar::from(0xffu64)).to_scalar(),
            Scalar::from(0xffu64)
        );
    }

    #[test]
    fn option_to_integer() {
        assert_eq!(ScalarWitness::option_to_integer(None), Ok(None));
        assert_eq!(
            ScalarWitness::option_to_integer(Some(ScalarWitness::Integer(24.into()))),
            Ok(Some(SignedInteger::from(24u64)))
        );
        assert_eq!(
            ScalarWitness::option_to_integer(Some(-ScalarWitness::Integer(24.into()))),
            Ok(Some(-SignedInteger::from(24u64)))
        );
        assert_eq!(
            ScalarWitness::option_to_integer(Some(ScalarWitness::Scalar(24u64.into()))),
            Err(VMError::TypeNotSignedInteger)
        );
    }

    #[test]
    fn add() {
        assert_eq!(
            ScalarWitness::from(2u64) + ScalarWitness::from(5u64),
            ScalarWitness::from(7u64)
        );

        assert_eq!(
            -ScalarWitness::from(10u64) + ScalarWitness::from(5u64),
            -ScalarWitness::from(5u64)
        );

        assert_eq!(
            ScalarWitness::from(1000u64) + ScalarWitness::from(Scalar::from(0xffu64)),
            ScalarWitness::from(Scalar::from(1000u64) + Scalar::from(0xffu64))
        );

        assert_eq!(
            -ScalarWitness::from(Scalar::from(0xffu64))
                + ScalarWitness::from(Scalar::from(0xffu64)),
            ScalarWitness::from(Scalar::zero())
        );
    }

    #[test]
    fn mul() {
        assert_eq!(
            ScalarWitness::from(5u64) * ScalarWitness::from(6u64),
            ScalarWitness::from(30u64)
        );

        assert_eq!(
            -ScalarWitness::from(2u64) * ScalarWitness::from(7u64),
            -ScalarWitness::from(14u64)
        );

        assert_eq!(
            ScalarWitness::from(100u64) * ScalarWitness::from(Scalar::from(0xffu64)),
            ScalarWitness::from(Scalar::from(100u64) * Scalar::from(0xffu64))
        );

        assert_eq!(
            ScalarWitness::from(Scalar::from(0xffu64)) * ScalarWitness::from(Scalar::from(0xfeu64)),
            ScalarWitness::from(Scalar::from(0xffu64) * Scalar::from(0xfeu64))
        );
    }

    #[test]
    fn overflow() {
        assert_eq!(
            ScalarWitness::from(u64::MAX) * ScalarWitness::from(u64::MAX),
            ScalarWitness::from(Scalar::from(u64::MAX) * Scalar::from(u64::MAX))
        );

        assert_eq!(
            ScalarWitness::from(u64::MAX) + ScalarWitness::from(u64::MAX),
            ScalarWitness::from(Scalar::from(u64::MAX) + Scalar::from(u64::MAX))
        );

        assert_eq!(
            -ScalarWitness::from(u64::MAX) + (-ScalarWitness::from(u64::MAX)),
            ScalarWitness::from(-Scalar::from(u64::MAX) - Scalar::from(u64::MAX))
        );
    }
}
