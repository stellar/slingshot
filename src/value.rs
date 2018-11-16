use curve25519_dalek::scalar::Scalar;
use bulletproofs::r1cs::Variable;

/// TBD: rename to Value after Value is renamed to AllocatedValue.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct SecretValue {
    pub q: u64,   // quantity
    pub a: Scalar, // issuer
    pub t: Scalar, // tag
}

/// Helper struct for ease of working with
/// 3-tuples of variables and assignments
#[derive(Copy, Clone, Debug)]
pub struct AllocatedValue {
    pub q: Variable, // quantity
    pub a: Variable, // issuer
    pub t: Variable, // tag
    pub assignment: Option<SecretValue>
}

/// Represents a variable for quantity, along with its assignment.
#[derive(Copy, Clone, Debug)]
pub struct AllocatedQuantity {
    pub variable: Variable,
    pub assignment: Option<u64>
}

impl SecretValue {
    /// Returns a zero quantity with a zero flavor.
    pub fn zero() -> SecretValue {
        SecretValue {
            q: 0,
            a: Scalar::zero(),
            t: Scalar::zero(),
        }
    }
}

impl AllocatedValue {
    /// Returns a quantity variable with its assignment.
	pub fn quantity(&self) -> AllocatedQuantity {
		AllocatedQuantity {
			variable: self.q,
			assignment: self.assignment.map(|v| v.q)
		}
	}
}
