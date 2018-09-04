use bulletproofs::R1CSError;
use bulletproofs::circuit_proof::r1cs::Assignment;
use curve25519_dalek::scalar::Scalar;
use std::ops::{Add, Mul};

pub fn missing() -> Assignment {
    Err(R1CSError::MissingAssignment)
}

pub struct AssignmentHolder (Assignment);

impl Mul for AssignmentHolder {
	type Output = Self;

	fn mul(self, rhs: Self) -> Self {
	    if self.0.is_err() || rhs.0.is_err() {
	        return AssignmentHolder(missing());
	    }
	    AssignmentHolder(Ok(self.0.unwrap() * rhs.0.unwrap()))	
	}
}

impl Mul<Scalar> for AssignmentHolder {
	type Output = Self;

	fn mul(self, rhs: Scalar) -> Self {
		if self.0.is_err() {
			return AssignmentHolder(missing());
		}
		AssignmentHolder(Ok(self.0.unwrap() * rhs))
	}
}

impl Add for AssignmentHolder {
	type Output = Self;

	fn add(self, rhs: Self) -> Self {
	    if self.0.is_err() || rhs.0.is_err() {
	        return AssignmentHolder(missing());
	    }
	    AssignmentHolder(Ok(self.0.unwrap() + rhs.0.unwrap()))	
	}
}

impl Add<Scalar> for AssignmentHolder {
	type Output = Self;

	fn add(self, rhs: Scalar) -> Self {
		if self.0.is_err() {
			return AssignmentHolder(missing());
		}
		AssignmentHolder(Ok(self.0.unwrap() + rhs))
	}
}