//! Constraint system-related types and operations:
//! Commitments, Variables, Expressions and Constraints.

use bulletproofs::{r1cs, r1cs::ConstraintSystem, PedersenGens};
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use std::iter::FromIterator;
use std::ops::{Add, Neg, Sub};

use crate::encoding;
use crate::errors::VMError;
use crate::scalar_witness::ScalarWitness;

#[derive(Copy, Clone, Debug)]
pub struct Variable {
    pub(crate) index: usize,
    // the witness is located indirectly in vm::VariableCommitment
}

#[derive(Clone, Debug)]
pub enum Expression {
    Constant(ScalarWitness),
    LinearCombination(Vec<(r1cs::Variable, Scalar)>, Option<ScalarWitness>),
}

#[derive(Clone, Debug)]
pub enum Constraint {
    Eq(Expression, Expression),
    And(Box<Constraint>, Box<Constraint>),
    Or(Box<Constraint>, Box<Constraint>),
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

impl Constraint {
    pub fn verify<CS: r1cs::ConstraintSystem>(self, cs: &mut CS) -> Result<(), VMError> {
        cs.specify_randomized_constraints(move |cs| {
            // Flatten the constraint into one expression
            // Note: cloning because we can't move out of captured variable in an `Fn` closure,
            // and `Box<FnOnce>` is not fully supported yet. (We can update when that happens).
            // Cf. https://github.com/dalek-cryptography/bulletproofs/issues/244
            let expr = self.clone().flatten(cs);

            // Add the resulting expression to the constraint system
            cs.constrain(expr);

            Ok(())
        })
        .map_err(|e| VMError::R1CSError(e))
    }

    fn flatten<CS: r1cs::RandomizedConstraintSystem>(self, cs: &mut CS) -> r1cs::LinearCombination {
        match self {
            Constraint::Eq(expr1, expr2) => expr1.to_r1cs_lc() - expr2.to_r1cs_lc(),
            Constraint::And(c1, c2) => {
                let a = c1.flatten(cs);
                let b = c2.flatten(cs);
                let z = cs.challenge_scalar(b"ZkVM.verify.and-challenge");
                a + z * b
            }
            Constraint::Or(c1, c2) => {
                let a = c1.flatten(cs);
                let b = c2.flatten(cs);
                // output expression: a * b
                let (_l, _r, o) = cs.multiply(a, b);
                r1cs::LinearCombination::from(o)
            }
        }
    }
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
        encoding::write_point(&self.to_point(), buf);
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

    // Note: we can't implement this as a `Mul` trait because we have to pass in a
    // ConstraintSystem, because the `LinearCombination * LinearCombination` case
    // requires the creation of a multiplier in the constraint system.
    pub fn multiply<CS: r1cs::ConstraintSystem>(self, rhs: Self, cs: &mut CS) -> Self {
        match (self, rhs) {
            // Constant * Constant
            (Expression::Constant(left), Expression::Constant(right)) => {
                Expression::Constant(left * right)
            }
            // Constant * LinearCombination
            (
                Expression::Constant(l),
                Expression::LinearCombination(mut right_terms, right_assignment),
            ) => {
                // Multiply coefficients in right_terms by l,
                // Multiply assignment in right_assignment by l
                for (_, n) in right_terms.iter_mut() {
                    *n = *n * l.to_scalar();
                }
                Expression::LinearCombination(right_terms, right_assignment.map(|r| r * l))
            }
            // LinearCombination * Constant
            (
                Expression::LinearCombination(mut left_terms, left_assignment),
                Expression::Constant(r),
            ) => {
                // Multiply coefficients in left_terms by r,
                // Multiply assignment in left_assignment by r
                for (_, n) in left_terms.iter_mut() {
                    *n = *n * r.to_scalar();
                }
                Expression::LinearCombination(left_terms, left_assignment.map(|l| l * r))
            }
            // LinearCombination * LinearCombination
            // Creates a multiplication gate in r1cs
            (
                Expression::LinearCombination(left_terms, left_assignment),
                Expression::LinearCombination(right_terms, right_assignment),
            ) => {
                let (_, _, output_var) = cs.multiply(
                    r1cs::LinearCombination::from_iter(left_terms),
                    r1cs::LinearCombination::from_iter(right_terms),
                );
                let output_assignment = match (left_assignment, right_assignment) {
                    (Some(l), Some(r)) => Some(l * r),
                    (_, _) => None,
                };
                Expression::LinearCombination(vec![(output_var, Scalar::one())], output_assignment)
            }
        }
    }

    fn to_r1cs_lc(&self) -> r1cs::LinearCombination {
        match self {
            Expression::Constant(a) => a.to_scalar().into(),
            Expression::LinearCombination(terms, _) => r1cs::LinearCombination::from_iter(terms),
        }
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
