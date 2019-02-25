//! Constraint system-related types and operations:
//! Commitments, Variables, Expressions and Constraints.

use bulletproofs::{r1cs, PedersenGens};
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use std::ops::{Add, Neg};

use crate::scalar_witness::ScalarWitness;

#[derive(Copy, Clone, Debug)]
pub struct Variable {
    pub(crate) index: usize,
    // the witness is located indirectly in vm::VariableCommitment
}

pub type ExpressionTerm = (r1cs::Variable, Scalar);
#[derive(Clone, Debug)]
pub enum Expression {
    Constant(ScalarWitness),
    LinearCombination(Vec<ExpressionTerm>, Option<ScalarWitness>),
}

#[derive(Clone, Debug)]
pub enum Constraint {
    Eq(Expression, Expression),
    And(Vec<Constraint>),
    Or(Vec<Constraint>),
    // no witness needed as it's normally true/false and we derive it on the fly during processing.
    // this also allows us not to wrap this enum in a struct.
}

#[derive(Clone, Debug)]
pub enum Commitment {
    Closed(CompressedRistretto),
    Open(Box<CommitmentWitness>),
}

/// Prover's representation of the commitment secret: witness and blinding factor
#[derive(Clone, Debug)]
pub struct CommitmentWitness {
    value: ScalarWitness,
    blinding: Scalar,
}

impl Commitment {
    /// Returns the number of bytes needed to serialize the Commitment.
    pub fn serialized_length(&self) -> usize {
        32
    }

    /// Converts a Commitment to a compressed point.
    pub fn to_point(&self) -> CompressedRistretto {
        match self {
            Commitment::Closed(x) => *x,
            Commitment::Open(w) => w.to_point(),
        }
    }

    pub(crate) fn encode(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.to_point().to_bytes());
    }

    pub fn unblinded<T: Into<ScalarWitness>>(x: T) -> Self {
        Commitment::Open(Box::new(CommitmentWitness {
            blinding: Scalar::zero(),
            value: x.into(),
        }))
    }

    pub fn blinded<T: Into<ScalarWitness>>(x: T) -> Self {
        Commitment::Open(Box::new(CommitmentWitness {
            blinding: Scalar::random(&mut rand::thread_rng()),
            value: x.into(),
        }))
    }

    pub fn blinded_with_factor<T: Into<ScalarWitness>>(x: T, blinding: Scalar) -> Self {
        Commitment::Open(Box::new(CommitmentWitness {
            blinding,
            value: x.into(),
        }))
    }

    /// Returns a pair of secrets: the committed scalar or integer, and the blinding factor
    pub fn witness(&self) -> Option<(ScalarWitness, Scalar)> {
        match self {
            Commitment::Closed(_) => None,
            Commitment::Open(w) => Some((w.value, w.blinding)),
        }
    }
}

impl CommitmentWitness {
    fn to_point(&self) -> CompressedRistretto {
        let gens = PedersenGens::default();
        gens.commit(self.value.into(), self.blinding).compress()
    }
}

impl Expression {
    pub fn constant<S: Into<ScalarWitness>>(a: S) -> Self {
        Expression::Constant(a.into())
    }
}

impl Neg for Expression {
    type Output = Expression;

    fn neg(self) -> Expression {
        match self {
            Expression::Constant(a) => Expression::Constant(-a),
            Expression::LinearCombination(mut terms, assignment) => {
                for (_, n) in terms.iter_mut() {
                    *n = -*n;
                }
                Expression::LinearCombination(terms, assignment.map(|a| -a))
            }
        }
    }
}

impl Add for Expression {
    type Output = Expression;

    fn add(self, rhs: Expression) -> Expression {
        match (self, rhs) {
            (Expression::Constant(left), Expression::Constant(right)) => {
                Expression::Constant(left + right)
            }
            (
                Expression::Constant(l),
                Expression::LinearCombination(mut right_terms, right_assignment),
            ) => {
                // prepend constant term to `term vector` in non-constant expression
                right_terms.insert(0, (r1cs::Variable::One(), l.into()));
                Expression::LinearCombination(right_terms, right_assignment.map(|r| l + r))
            }
            (
                Expression::LinearCombination(mut left_terms, left_assignment),
                Expression::Constant(r),
            ) => {
                // append constant term to term vector in non-constant expression
                left_terms.push((r1cs::Variable::One(), r.into()));
                Expression::LinearCombination(left_terms, left_assignment.map(|l| l + r))
            }
            (
                Expression::LinearCombination(mut left_terms, left_assignment),
                Expression::LinearCombination(right_terms, right_assignment),
            ) => {
                // append right terms to left terms in non-constant expression
                left_terms.extend(right_terms);
                Expression::LinearCombination(
                    left_terms,
                    left_assignment.and_then(|l| right_assignment.map(|r| l + r)),
                )
            }
        }
    }
}

// Upcasting witness/points into Commitment

impl From<CommitmentWitness> for Commitment {
    fn from(x: CommitmentWitness) -> Self {
        Commitment::Open(Box::new(x))
    }
}

impl From<CompressedRistretto> for Commitment {
    fn from(x: CompressedRistretto) -> Self {
        Commitment::Closed(x)
    }
}

impl Into<CompressedRistretto> for Commitment {
    fn into(self) -> CompressedRistretto {
        self.to_point()
    }
}
