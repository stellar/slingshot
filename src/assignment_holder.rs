use bulletproofs::circuit_proof::r1cs::Assignment;
use bulletproofs::R1CSError;
use curve25519_dalek::scalar::Scalar;
use std::ops::{Add, Mul, Sub};

pub fn missing() -> Assignment {
    Err(R1CSError::MissingAssignment)
}

pub struct AssignmentHolder(pub Assignment);

impl AssignmentHolder {
    pub fn new(val: Scalar) -> Self {
        AssignmentHolder(Ok(val))
    }

    pub fn err() -> Self {
        AssignmentHolder(Err(R1CSError::MissingAssignment))
    }
}

impl Mul for AssignmentHolder {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self {
        if self.0.is_err() || rhs.0.is_err() {
            return AssignmentHolder::err();
        }
        AssignmentHolder(Ok(self.0.unwrap() * rhs.0.unwrap()))
    }
}

impl Mul<Scalar> for AssignmentHolder {
    type Output = Self;

    fn mul(self, rhs: Scalar) -> Self {
        if self.0.is_err() {
            return AssignmentHolder::err();
        }
        AssignmentHolder(Ok(self.0.unwrap() * rhs))
    }
}

impl Add for AssignmentHolder {
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        if self.0.is_err() || rhs.0.is_err() {
            return AssignmentHolder::err();
        }
        AssignmentHolder(Ok(self.0.unwrap() + rhs.0.unwrap()))
    }
}

impl Add<Scalar> for AssignmentHolder {
    type Output = Self;

    fn add(self, rhs: Scalar) -> Self {
        if self.0.is_err() {
            return AssignmentHolder::err();
        }
        AssignmentHolder(Ok(self.0.unwrap() + rhs))
    }
}

impl Sub for AssignmentHolder {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self {
        if self.0.is_err() || rhs.0.is_err() {
            return AssignmentHolder::err();
        }
        AssignmentHolder(Ok(self.0.unwrap() - rhs.0.unwrap()))
    }
}

impl Sub<Scalar> for AssignmentHolder {
    type Output = Self;

    fn sub(self, rhs: Scalar) -> Self {
        if self.0.is_err() {
            return AssignmentHolder::err();
        }
        AssignmentHolder(Ok(self.0.unwrap() - rhs))
    }
}
