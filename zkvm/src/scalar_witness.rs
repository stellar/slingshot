//! Arithmetic and conversion API for ScalarWitness.

use curve25519_dalek::scalar::Scalar;
use spacesuit::SignedInteger;

use crate::errors::VMError;
use std::ops::{Add, Mul, Neg};

/// Represents a concrete kind of a number represented by a scalar:
/// `ScalarKind::Integer` represents a signed integer with 64-bit absolute value (think "i65")
/// `ScalarKind::Scalar` represents a scalar modulo group order.
#[derive(Copy, Clone, Debug)]
pub enum ScalarWitness {
    Integer(SignedInteger),
    Scalar(Scalar),
}

impl ScalarWitness {
    /// Returns the number of bytes needed to serialize the ScalarWitness.
    pub fn serialized_length(&self) -> usize {
        32
    }

    /// Converts to a scalar and encodes it to a vec of bytes.
    pub(crate) fn encode(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.to_scalar().to_bytes())
    }

    /// Converts the witness to an integer if it is an integer
    pub fn to_integer(self) -> Result<SignedInteger, VMError> {
        match self {
            ScalarWitness::Integer(i) => Ok(i),
            ScalarWitness::Scalar(_) => Err(VMError::TypeNotSignedInteger),
        }
    }

    // Converts the witness to a scalar.
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
}

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

impl Into<Scalar> for ScalarWitness {
    fn into(self) -> Scalar {
        self.to_scalar()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialized_length() {
        assert_eq!(ScalarWitness::Integer(1.into()).serialized_length(), 32);
        assert_eq!(
            ScalarWitness::Scalar(Scalar::from(0xffu64)).serialized_length(),
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

    // TBD: arithmetic tests
    // TBD: also test int-to-scalar promotion on overflow
}
