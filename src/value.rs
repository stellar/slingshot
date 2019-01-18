use bulletproofs::r1cs::{ConstraintSystem, Prover, R1CSError, Variable, Verifier};
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use rand::{CryptoRng, Rng};

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Value {
    pub q: u64,    // quantity
    pub f: Scalar, // flavor
}

pub struct CommittedValue {
    pub q: CompressedRistretto,
    pub f: CompressedRistretto,
}

/// Helper struct for ease of working with
/// 2-tuples of variables and assignments
#[derive(Copy, Clone, Debug)]
pub struct AllocatedValue {
    pub q: Variable, // quantity
    pub f: Variable, // flavor
    pub assignment: Option<Value>,
}

/// Represents a variable for quantity, along with its assignment.
#[derive(Copy, Clone, Debug)]
pub struct AllocatedQuantity {
    pub variable: Variable,
    pub assignment: Option<u64>,
}

impl Value {
    /// Returns a zero quantity with a zero flavor.
    pub fn zero() -> Value {
        Value {
            q: 0,
            f: Scalar::zero(),
        }
    }

    /// Creates variables for the fields in `Value`, and packages them in an `AllocatedValue`.
    pub fn allocate<CS: ConstraintSystem>(&self, cs: &mut CS) -> Result<AllocatedValue, R1CSError> {
        let q_u64 = self.q.into();
        let (q_var, f_var, _) = cs.allocate(|| Ok((q_u64, self.f, q_u64 * self.f)))?;

        Ok(AllocatedValue {
            q: q_var,
            f: f_var,
            assignment: Some(*self),
        })
    }

    pub fn allocate_unassigned<CS: ConstraintSystem>(
        cs: &mut CS,
    ) -> Result<AllocatedValue, R1CSError> {
        let (q_var, f_var, _) = cs.allocate(|| {
            Err(R1CSError::GadgetError {
                description: "Tried to allocate variables q_var and f_var from function"
                    .to_string(),
            })
        })?;

        Ok(AllocatedValue {
            q: q_var,
            f: f_var,
            assignment: None,
        })
    }
}

impl AllocatedValue {
    /// Returns a quantity variable with its assignment.
    pub fn quantity(&self) -> AllocatedQuantity {
        AllocatedQuantity {
            variable: self.q,
            assignment: self.assignment.map(|v| v.q),
        }
    }

    // /// Make another `AllocatedValue`, with the same assignment and newly allocated variables.
    pub fn reallocate<CS: ConstraintSystem>(
        &self,
        cs: &mut CS,
    ) -> Result<AllocatedValue, R1CSError> {
        match self.assignment {
            Some(value) => value.allocate(cs),
            None => Value::allocate_unassigned(cs),
        }
    }
}

pub trait ProverCommittable {
    type Output;

    fn commit<R: Rng + CryptoRng>(&self, prover: &mut Prover, rng: &mut R) -> Self::Output;
}

impl ProverCommittable for Value {
    type Output = (CommittedValue, AllocatedValue);

    fn commit<R: Rng + CryptoRng>(&self, prover: &mut Prover, rng: &mut R) -> Self::Output {
        let (q_commit, q_var) = prover.commit(self.q.into(), Scalar::random(rng));
        let (f_commit, f_var) = prover.commit(self.f, Scalar::random(rng));
        let commitments = CommittedValue {
            q: q_commit,
            f: f_commit,
        };
        let vars = AllocatedValue {
            q: q_var,
            f: f_var,
            assignment: Some(*self),
        };
        (commitments, vars)
    }
}

impl ProverCommittable for Vec<Value> {
    type Output = (Vec<CommittedValue>, Vec<AllocatedValue>);

    fn commit<R: Rng + CryptoRng>(&self, prover: &mut Prover, rng: &mut R) -> Self::Output {
        self.iter().map(|value| value.commit(prover, rng)).unzip()
    }
}

pub trait VerifierCommittable {
    type Output;
    fn commit(&self, verifier: &mut Verifier) -> Self::Output;
}

impl VerifierCommittable for CommittedValue {
    type Output = AllocatedValue;

    fn commit(&self, verifier: &mut Verifier) -> Self::Output {
        AllocatedValue {
            q: verifier.commit(self.q),
            f: verifier.commit(self.f),
            assignment: None,
        }
    }
}

impl VerifierCommittable for Vec<CommittedValue> {
    type Output = Vec<AllocatedValue>;

    fn commit(&self, verifier: &mut Verifier) -> Self::Output {
        self.iter().map(|value| value.commit(verifier)).collect()
    }
}
