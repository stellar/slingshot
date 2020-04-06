use bulletproofs::r1cs::{ConstraintSystem, Prover, R1CSError, Variable, Verifier};
use core::borrow::BorrowMut;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use rand::{CryptoRng, Rng};

use crate::signed_integer::SignedInteger;

/// A pair of a secret _quantity_ (64-bit integer)
/// and a secret _flavor_ (scalar).
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Value {
    /// Secret quantity
    pub q: SignedInteger,
    /// Secret flavor
    pub f: Scalar,
}

/// A pair of Pedersen commitments to a secret quantity and flavor.
pub struct CommittedValue {
    /// Pedersen commitment to a quantity
    pub q: CompressedRistretto,
    /// Pedersen commitment to a flavor
    pub f: CompressedRistretto,
}

/// Helper struct for ease of working with
/// 2-tuples of variables and assignments
#[derive(Copy, Clone, Debug)]
pub struct AllocatedValue {
    /// R1CS variable representing the quantity
    pub q: Variable,
    /// R1CS variable representing the flavor
    pub f: Variable,
    /// Secret assignment to the above variables
    pub assignment: Option<Value>,
}

impl Value {
    /// Returns a zero quantity with a zero flavor.
    pub fn zero() -> Value {
        Value {
            q: 0u64.into(),
            f: Scalar::zero(),
        }
    }

    /// Creates variables for the fields in `Value`, and packages them in an `AllocatedValue`.
    pub fn allocate<CS: ConstraintSystem>(&self, cs: &mut CS) -> Result<AllocatedValue, R1CSError> {
        let q_u64 = self.q.into();
        let (q_var, f_var, _) = cs.allocate_multiplier(Some((q_u64, self.f)))?;

        Ok(AllocatedValue {
            q: q_var,
            f: f_var,
            assignment: Some(*self),
        })
    }
}

impl AllocatedValue {
    /// Creates an unassigned allocated value.
    pub(crate) fn unassigned<CS: ConstraintSystem>(
        cs: &mut CS,
    ) -> Result<AllocatedValue, R1CSError> {
        let (q, f, _) = cs.allocate_multiplier(None)?;

        Ok(Self {
            q,
            f,
            assignment: None,
        })
    }

    /// Creates a list of unassigned allocated values.
    pub(crate) fn unassigned_vec<CS: ConstraintSystem>(
        cs: &mut CS,
        n: usize,
    ) -> Result<Vec<AllocatedValue>, R1CSError> {
        (0..n).map(|_| Self::unassigned(cs)).collect()
    }
}

/// Extension trait for committing Values to the Prover's constraint system.
/// TBD: make this private by refactoring the benchmarks.
pub trait ProverCommittable {
    /// Result of committing Self to a constraint system.
    type Output;

    /// Commits the type to a constraint system.
    fn commit<T: BorrowMut<Transcript>, R: Rng + CryptoRng>(
        &self,
        prover: &mut Prover<T>,
        rng: &mut R,
    ) -> Self::Output;
}

impl ProverCommittable for Value {
    type Output = (CommittedValue, AllocatedValue);

    fn commit<T: BorrowMut<Transcript>, R: Rng + CryptoRng>(
        &self,
        prover: &mut Prover<T>,
        rng: &mut R,
    ) -> Self::Output {
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

    fn commit<T: BorrowMut<Transcript>, R: Rng + CryptoRng>(
        &self,
        prover: &mut Prover<T>,
        rng: &mut R,
    ) -> Self::Output {
        self.iter().map(|value| value.commit(prover, rng)).unzip()
    }
}

/// Extension trait for committing Values to the Verifier's constraint system.
/// TBD: make this private by refactoring the benchmarks.
pub trait VerifierCommittable {
    /// Result of committing Self to a constraint system.
    type Output;

    /// Commits the type to a constraint system.
    fn commit<T: BorrowMut<Transcript>>(&self, verifier: &mut Verifier<T>) -> Self::Output;
}

impl VerifierCommittable for CommittedValue {
    type Output = AllocatedValue;

    fn commit<T: BorrowMut<Transcript>>(&self, verifier: &mut Verifier<T>) -> Self::Output {
        AllocatedValue {
            q: verifier.commit(self.q),
            f: verifier.commit(self.f),
            assignment: None,
        }
    }
}

impl VerifierCommittable for Vec<CommittedValue> {
    type Output = Vec<AllocatedValue>;

    fn commit<T: BorrowMut<Transcript>>(&self, verifier: &mut Verifier<T>) -> Self::Output {
        self.iter().map(|value| value.commit(verifier)).collect()
    }
}
