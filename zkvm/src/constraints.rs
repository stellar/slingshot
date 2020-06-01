//! Constraint system-related types and operations:
//! Commitments, Variables, Expressions and Constraints.

use bulletproofs::{r1cs, r1cs::ConstraintSystem, PedersenGens};
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use serde::{Deserialize, Serialize};
use std::iter::FromIterator;
use std::ops::{Add, Neg};
use subtle::{ConditionallySelectable, ConstantTimeEq};

use crate::encoding::*;
use crate::errors::VMError;
use crate::scalar_witness::ScalarWitness;

/// Variable represents a high-level R1CS variable specified by its
/// Pedersen commitment. In ZkVM variables are actually indices to a list
/// of stored commitments to permit commitment reblinding (see `reblind` instruction).
#[derive(Clone, Debug)]
pub struct Variable {
    /// TBD: maybe do this as a subtype of the Expression
    pub(crate) commitment: Commitment,
}

/// Expression is a linear combination of high-level variables (`var`),
/// low-level variables (`alloc`) and constants.
#[derive(Clone, Debug, PartialEq)]
pub enum Expression {
    /// Represents a constant. Operations on constants produce constants.
    Constant(ScalarWitness),

    /// Linear combination of R1CS variables and constants.
    LinearCombination(Vec<(r1cs::Variable, Scalar)>, Option<ScalarWitness>),
}

/// Constraint is a boolean function of expressions and other constraints.
/// Constraints can be evaluated to true or false. The `verify` instruction
/// enforces that the final composition evaluates to `true` in zero knowledge.
///
/// Note: use dedicated functions `eq()`, `and()`, `or()` and `not()` to create
/// constraints since they apply guaranteed optimization for cleartext constraints.
#[derive(Clone, Debug, PartialEq)]
pub enum Constraint {
    /// Cleartext constraint: known to the verifier to be true or false.
    Cleartext(bool),

    /// Secret constraint: not known to the verifier whether it is true or false.
    Secret(SecretConstraint),
}

/// This is a subtype of `Constraint` that excludes `::Cleartext` case.
#[derive(Clone, Debug, PartialEq)]
pub enum SecretConstraint {
    /// Equality constraint between two expressions.
    /// Created by `eq` instruction.
    Eq(Expression, Expression),

    /// Conjunction of two constraints: each must evaluate to true.
    /// Created by `and` instruction.
    And(Box<SecretConstraint>, Box<SecretConstraint>),

    /// Disjunction of two constraints: at least one must evaluate to true.
    /// Created by `or` instruction.
    Or(Box<SecretConstraint>, Box<SecretConstraint>),

    /// Negation of a constraint: must be zero to evaluate to true.
    /// Created by 'not' instruction.
    Not(Box<SecretConstraint>),
    // no witness needed as it's normally true/false and we derive it on the fly during processing.
    // this also allows us not to wrap this enum in a struct.
}

/// Commitment is a represention of an _open_ or _closed_ Pedersen commitment.
#[derive(Clone, PartialEq, Deserialize, Serialize)]
pub enum Commitment {
    /// Hides a secret value and its blinding factor in the Ristretto point.
    Closed(CompressedRistretto),

    /// Contains the secret value and its blinding factor for the use in the prover’s VM.
    Open(Box<CommitmentWitness>),
}

/// Prover's representation of the commitment secret: witness and blinding factor
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub struct CommitmentWitness {
    value: ScalarWitness,
    blinding: Scalar,
}

impl Constraint {
    /// Generates and adds to R1CS constraints that enforce that the self evaluates to true.
    /// Implements the logic behind `verify` instruction.
    pub fn verify<CS: r1cs::RandomizableConstraintSystem>(
        self,
        cs: &mut CS,
    ) -> Result<(), VMError> {
        // Return early without updating CS if the constraint is cleartext.
        // Note: this makes the matching on ::Cleartext case inside `flatten` function unnecessary.
        let secret_constraint = match self {
            Constraint::Cleartext(true) => return Ok(()),
            Constraint::Cleartext(false) => return Err(VMError::CleartextConstraintFalse),
            Constraint::Secret(sc) => sc,
        };
        cs.specify_randomized_constraints(move |cs| {
            // Flatten the constraint into one expression
            // Note: cloning because we can't move out of captured variable in an `Fn` closure,
            // and `Box<FnOnce>` is not fully supported yet. (We can update when that happens).
            // Cf. https://github.com/dalek-cryptography/bulletproofs/issues/244
            let (expr, _) = secret_constraint.clone().flatten(cs)?;

            // Add the resulting expression to the constraint system
            cs.constrain(expr);

            Ok(())
        })
        .map_err(|e| VMError::R1CSError(e))
    }

    /// Creates an equality constraint.
    ///
    /// Applies _guaranteed optimization_:
    /// if both arguments are constant expressions, returns Constraint::Cleartext(bool).
    pub fn eq(e1: Expression, e2: Expression) -> Self {
        match (e1, e2) {
            (Expression::Constant(sw1), Expression::Constant(sw2)) => {
                Constraint::Cleartext(sw1 == sw2)
            }
            (e1, e2) => Constraint::Secret(SecretConstraint::Eq(e1, e2)),
        }
    }

    /// Creates a conjunction constraint.
    ///
    /// Applies _guaranteed optimization_:
    /// if one argument is a cleartext `false`, returns `false`, otherwise returns other argument.
    pub fn and(c1: Constraint, c2: Constraint) -> Self {
        match (c1, c2) {
            (Constraint::Cleartext(false), _) => Constraint::Cleartext(false),
            (Constraint::Cleartext(true), other) => other,
            (_, Constraint::Cleartext(false)) => Constraint::Cleartext(false),
            (other, Constraint::Cleartext(true)) => other,
            (Constraint::Secret(c1), Constraint::Secret(c2)) => {
                Constraint::Secret(SecretConstraint::And(Box::new(c1), Box::new(c2)))
            }
        }
    }

    /// Creates a disjunction constraint.
    ///
    /// Applies _guaranteed optimization_:
    /// if one argument is a cleartext `true`, returns `true`, otherwise returns other argument.
    pub fn or(c1: Constraint, c2: Constraint) -> Self {
        match (c1, c2) {
            (Constraint::Cleartext(false), other) => other,
            (Constraint::Cleartext(true), _) => Constraint::Cleartext(true),
            (other, Constraint::Cleartext(false)) => other,
            (_, Constraint::Cleartext(true)) => Constraint::Cleartext(true),
            (Constraint::Secret(c1), Constraint::Secret(c2)) => {
                Constraint::Secret(SecretConstraint::Or(Box::new(c1), Box::new(c2)))
            }
        }
    }

    /// Creates a logical inverse of the constraint.
    ///
    /// Applies _guaranteed optimization_:
    /// if the argument is a cleartext constraint `c`, inverts it.
    pub fn not(c: Constraint) -> Self {
        match c {
            Constraint::Cleartext(b) => Constraint::Cleartext(!b),
            Constraint::Secret(c) => Constraint::Secret(SecretConstraint::Not(Box::new(c))),
        }
    }

    /// Returns the secret assignment to this constraint (true or false),
    /// based on the assignments to the variables inside the underlying Expressions.
    /// Returns `None` if any underlying variable does not have an assignment.
    pub fn assignment(&self) -> Option<bool> {
        self.eval()
    }

    /// Evaluates the constraint using the optional scalar witness data in the underlying `Expression`s.
    /// Returns None if the witness is missing in any expression.
    fn eval(&self) -> Option<bool> {
        match self {
            Constraint::Cleartext(flag) => Some(*flag),
            Constraint::Secret(sc) => sc.eval(),
        }
    }
}

impl SecretConstraint {
    fn flatten<CS: r1cs::RandomizedConstraintSystem>(
        self,
        cs: &mut CS,
    ) -> Result<(r1cs::LinearCombination, Option<Scalar>), r1cs::R1CSError> {
        match self {
            SecretConstraint::Eq(expr1, expr2) => {
                let assignment = expr1
                    .eval()
                    .and_then(|x| expr2.eval().map(|y| (x - y).to_scalar()));
                Ok((expr1.to_r1cs_lc() - expr2.to_r1cs_lc(), assignment))
            }
            SecretConstraint::And(c1, c2) => {
                let (a, a_assg) = c1.flatten(cs)?;
                let (b, b_assg) = c2.flatten(cs)?;
                let z = cs.challenge_scalar(b"ZkVM.verify.and-challenge");
                let assignment = a_assg.and_then(|a| b_assg.map(|b| a + z * b));
                Ok((a + z * b, assignment))
            }
            SecretConstraint::Or(c1, c2) => {
                let (a, a_assg) = c1.flatten(cs)?;
                let (b, b_assg) = c2.flatten(cs)?;
                // output expression: a * b
                let (_l, _r, o) = cs.multiply(a, b);
                let assignment = a_assg.and_then(|a| b_assg.map(|b| a * b));
                Ok((r1cs::LinearCombination::from(o), assignment))
            }
            SecretConstraint::Not(c1) => {
                // Compute the input linear combination and its secret assignment
                let (x_lc, x_assg) = c1.flatten(cs)?;

                // Compute assignments for all the wires
                let (xy_assg, xw_assg, y_assg) = match x_assg {
                    Some(x) => {
                        let is_zero = x.ct_eq(&Scalar::zero());
                        let y = Scalar::conditional_select(
                            &Scalar::zero(),
                            &Scalar::one(),
                            is_zero.into(),
                        );
                        let w = Scalar::conditional_select(&x, &Scalar::one(), is_zero.into());
                        let w = w.invert();
                        (Some((x, y)), Some((x, w)), Some(y))
                    }
                    None => (None, None, None),
                };

                // Allocate two multipliers.
                let (l1, r1, o1) = cs.allocate_multiplier(xy_assg)?;
                let (l2, _r2, o2) = cs.allocate_multiplier(xw_assg)?;

                // Add 4 constraints.

                // (1) `x == l1`
                cs.constrain(l1 - x_lc);

                // (2) `l1 == l2` (== x)
                cs.constrain(l1 - l2);

                // (3) `x*y == 0` which implies that y == 0 if x != 0.
                cs.constrain(o1.into());

                // (4) `x*w == 1 - y` which implies that y == 1 if x == 0.
                cs.constrain(o2 - Scalar::one() + r1);

                // Note: w (r2) is left unconstrained — it is a free variable.

                Ok((r1cs::LinearCombination::from(r1), y_assg))
            }
        }
    }

    /// Evaluates the constraint using the optional scalar witness data in the underlying `Expression`s.
    /// Returns None if the witness is missing in any expression.
    fn eval(&self) -> Option<bool> {
        match self {
            SecretConstraint::Eq(e1, e2) => e1.eval().and_then(|x| e2.eval().map(|y| x == y)),
            SecretConstraint::And(c1, c2) => c1.eval().and_then(|x| c2.eval().map(|y| x && y)),
            SecretConstraint::Or(c1, c2) => c1.eval().and_then(|x| c2.eval().map(|y| x || y)),
            SecretConstraint::Not(c1) => c1.eval().map(|x| !x),
        }
    }
}

impl Encodable for Commitment {
    fn encode(&self, w: &mut impl Writer) -> Result<(), WriteError> {
        w.write_point(b"commitment", &self.to_point())
    }
}
impl ExactSizeEncodable for Commitment {
    fn encoded_size(&self) -> usize {
        32
    }
}
impl Commitment {
    /// Converts a Commitment to a compressed point.
    pub fn to_point(&self) -> CompressedRistretto {
        match self {
            Commitment::Closed(x) => *x,
            Commitment::Open(w) => w.to_point(),
        }
    }

    /// Creates an open commitment with a zero blinding factor.
    pub fn unblinded<T: Into<ScalarWitness>>(x: T) -> Self {
        Commitment::Open(Box::new(CommitmentWitness {
            blinding: Scalar::zero(),
            value: x.into(),
        }))
    }

    /// Creates an open commitment with a random blinding factor.
    pub fn blinded<T: Into<ScalarWitness>>(x: T) -> Self {
        Commitment::Open(Box::new(CommitmentWitness {
            blinding: Scalar::random(&mut rand::thread_rng()),
            value: x.into(),
        }))
    }

    /// Creates an open commitment with a specified blinding factor.
    pub fn blinded_with_factor<T: Into<ScalarWitness>>(x: T, blinding: Scalar) -> Self {
        Commitment::Open(Box::new(CommitmentWitness {
            blinding,
            value: x.into(),
        }))
    }

    /// Returns a pair of secrets: the committed scalar or integer, and the blinding factor
    /// TBD: rename to `to_option()`.
    pub fn witness(&self) -> Option<(ScalarWitness, Scalar)> {
        match self {
            Commitment::Closed(_) => None,
            Commitment::Open(w) => Some((w.value, w.blinding)),
        }
    }

    /// Returns the committed scalar or integer, without the blinding factor.
    /// If the witness is missing, returns None.
    pub fn assignment(&self) -> Option<ScalarWitness> {
        match self {
            Commitment::Closed(_) => None,
            Commitment::Open(w) => Some(w.value),
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
    /// Creates a constant expression for a given integer or scalar.
    pub fn constant<S: Into<ScalarWitness>>(a: S) -> Self {
        Expression::Constant(a.into())
    }

    /// Multiplies two expressions by constraining them to the left/right wires
    /// of a newly allocated R1CS multiplier, and returns
    /// the output wire wrapped in Expression type.
    ///
    /// Note: we can't implement this as a `Mul` trait because we have to pass in a
    /// ConstraintSystem, because the `LinearCombination * LinearCombination` case
    /// requires the creation of a multiplier in the constraint system.
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

    pub(crate) fn to_r1cs_lc(&self) -> r1cs::LinearCombination {
        match self {
            Expression::Constant(a) => a.to_scalar().into(),
            Expression::LinearCombination(terms, _) => r1cs::LinearCombination::from_iter(terms),
        }
    }

    /// Evaluates the expression using its optional scalar witness data.
    /// Returns None if there is no witness.
    fn eval(&self) -> Option<ScalarWitness> {
        match self {
            Expression::Constant(a) => Some(*a),
            Expression::LinearCombination(_, a) => match a {
                Some(a) => Some(*a),
                None => None,
            },
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

#[cfg(test)]
mod tests {
    use super::*;
    use merlin::Transcript;

    #[test]
    fn expression_arithmetic() {
        // const + const => const
        assert_eq!(
            Expression::Constant(1u64.into()) + Expression::Constant(2u64.into()),
            Expression::Constant(3u64.into())
        );
        // const + lincomb => prepend to lincomb
        assert_eq!(
            Expression::Constant(1u64.into())
                + Expression::LinearCombination(
                    vec![(r1cs::Variable::One(), 2u64.into())],
                    Some(2u64.into())
                ),
            Expression::LinearCombination(
                vec![
                    (r1cs::Variable::One(), 1u64.into()),
                    (r1cs::Variable::One(), 2u64.into())
                ],
                Some(3u64.into())
            )
        );
        // lincomb + const => append to lincomb
        assert_eq!(
            Expression::LinearCombination(
                vec![(r1cs::Variable::One(), 1u64.into())],
                Some(1u64.into())
            ) + Expression::Constant(2u64.into()),
            Expression::LinearCombination(
                vec![
                    (r1cs::Variable::One(), 1u64.into()),
                    (r1cs::Variable::One(), 2u64.into())
                ],
                Some(3u64.into())
            )
        );
        // lincomb + lincomb => concat
        assert_eq!(
            Expression::LinearCombination(
                vec![(r1cs::Variable::Committed(1), 11u64.into())],
                Some(100u64.into())
            ) + Expression::LinearCombination(
                vec![(r1cs::Variable::Committed(2), 22u64.into())],
                Some(42u64.into())
            ),
            Expression::LinearCombination(
                vec![
                    (r1cs::Variable::Committed(1), 11u64.into()),
                    (r1cs::Variable::Committed(2), 22u64.into())
                ],
                Some(142u64.into())
            )
        );
        // -expr => negate weights
        assert_eq!(
            -Expression::Constant(1u64.into()),
            Expression::Constant(-ScalarWitness::from(1))
        );
        assert_eq!(
            -Expression::LinearCombination(
                vec![(r1cs::Variable::One(), 1u64.into())],
                Some(1u64.into())
            ),
            Expression::LinearCombination(
                vec![(r1cs::Variable::One(), -Scalar::from(1u64))],
                Some(-ScalarWitness::from(1))
            )
        );

        let mut cs = MockMultiplierCS { num_multipliers: 0 };

        let e1 = Expression::Constant(10u64.into());
        let e2 = Expression::Constant(20u64.into());
        let e3 = Expression::LinearCombination(
            vec![(r1cs::Variable::Committed(0), 3u64.into())],
            Some(3u64.into()),
        );
        let e4 = Expression::LinearCombination(
            vec![(r1cs::Variable::Committed(1), 4u64.into())],
            Some(4u64.into()),
        );

        // const * const => mult consts
        assert_eq!(
            e1.clone().multiply(e2.clone(), &mut cs),
            Expression::Constant(200u64.into())
        );
        // const * expr => mult weights
        assert_eq!(
            e1.clone().multiply(e3.clone(), &mut cs),
            Expression::LinearCombination(
                vec![(r1cs::Variable::Committed(0), 30u64.into())],
                Some(30u64.into())
            )
        );
        // expr * const => mult weights
        assert_eq!(
            e3.clone().multiply(e1.clone(), &mut cs),
            Expression::LinearCombination(
                vec![(r1cs::Variable::Committed(0), 30u64.into())],
                Some(30u64.into())
            )
        );
        // expr * expr => allocate new multiplier
        assert_eq!(
            e3.clone().multiply(e4.clone(), &mut cs),
            Expression::LinearCombination(
                vec![(r1cs::Variable::MultiplierOutput(0), 1u64.into())],
                Some(12u64.into())
            )
        );
    }

    #[test]
    fn constraints_arithmetic() {
        // eq(const, const) => cleartext(true)
        assert_eq!(
            Constraint::eq(
                Expression::Constant(1u64.into()),
                Expression::Constant(1u64.into())
            ),
            Constraint::Cleartext(true)
        );
        // eq(const1, const2) => cleartext(false)
        assert_eq!(
            Constraint::eq(
                Expression::Constant(1u64.into()),
                Expression::Constant(2u64.into())
            ),
            Constraint::Cleartext(false)
        );
        // eq(const, nonconst) => ::Eq
        let e1 = Expression::Constant(1u64.into());
        let e2 = Expression::LinearCombination(
            vec![(r1cs::Variable::One(), 2u64.into())],
            Some(2u64.into()),
        );
        assert_eq!(
            Constraint::eq(e1.clone(), e2.clone()),
            Constraint::Secret(SecretConstraint::Eq(e1.clone(), e2.clone()))
        );
        assert_eq!(
            Constraint::eq(e2.clone(), e1.clone()),
            Constraint::Secret(SecretConstraint::Eq(e2.clone(), e1.clone()))
        );

        let s1 = SecretConstraint::Eq(e1.clone(), e2.clone());
        let s2 = SecretConstraint::Eq(e2.clone(), e2.clone());
        let c1 = Constraint::Secret(s1.clone());
        let c2 = Constraint::Secret(s2.clone());
        // and(cleartext(true), other) => other
        assert_eq!(
            Constraint::and(Constraint::Cleartext(true), c1.clone()),
            c1.clone()
        );
        // and(cleartext(false), other) => cleartext(false)
        assert_eq!(
            Constraint::and(Constraint::Cleartext(false), c1.clone()),
            Constraint::Cleartext(false)
        );
        // and(secret, secret) => ::Or(secret, secret)
        assert_eq!(
            Constraint::and(c1.clone(), c2.clone()),
            Constraint::Secret(SecretConstraint::And(
                Box::new(s1.clone()),
                Box::new(s2.clone())
            ))
        );

        // or(cleartext(true), other) => cleartext(true)
        assert_eq!(
            Constraint::or(Constraint::Cleartext(true), c1.clone()),
            Constraint::Cleartext(true)
        );
        // or(cleartext(false), other) => other
        assert_eq!(
            Constraint::or(Constraint::Cleartext(false), c1.clone()),
            c1.clone()
        );
        // or(secret, secret) => ::Or(secret, secret)
        assert_eq!(
            Constraint::or(c1.clone(), c2.clone()),
            Constraint::Secret(SecretConstraint::Or(
                Box::new(s1.clone()),
                Box::new(s2.clone())
            ))
        );

        // not(cleartext(flag)) => cleartext(!flag)
        assert_eq!(
            Constraint::not(Constraint::Cleartext(false)),
            Constraint::Cleartext(true)
        );
        assert_eq!(
            Constraint::not(Constraint::Cleartext(true)),
            Constraint::Cleartext(false)
        );
        // not(secret) => ::Not(secret)
        assert_eq!(
            Constraint::not(c1.clone()),
            Constraint::Secret(SecretConstraint::Not(Box::new(s1.clone()),))
        );
    }

    struct MockMultiplierCS {
        pub num_multipliers: usize,
    }

    impl r1cs::ConstraintSystem for MockMultiplierCS {
        fn transcript(&mut self) -> &mut Transcript {
            // not used in tests
            unimplemented!()
        }

        // simulates a multiplication gate, returning
        fn multiply(
            &mut self,
            _left: r1cs::LinearCombination,
            _right: r1cs::LinearCombination,
        ) -> (r1cs::Variable, r1cs::Variable, r1cs::Variable) {
            let var = self.num_multipliers;
            self.num_multipliers += 1;
            let l_var = r1cs::Variable::MultiplierLeft(var);
            let r_var = r1cs::Variable::MultiplierRight(var);
            let o_var = r1cs::Variable::MultiplierOutput(var);
            (l_var, r_var, o_var)
        }

        fn allocate(
            &mut self,
            _assignment: Option<Scalar>,
        ) -> Result<r1cs::Variable, r1cs::R1CSError> {
            Ok(self.allocate_multiplier(None)?.0)
        }

        fn allocate_multiplier(
            &mut self,
            _assignments: Option<(Scalar, Scalar)>,
        ) -> Result<(r1cs::Variable, r1cs::Variable, r1cs::Variable), r1cs::R1CSError> {
            let var = self.num_multipliers;
            self.num_multipliers += 1;

            // Create variables for l,r,o
            let l_var = r1cs::Variable::MultiplierLeft(var);
            let r_var = r1cs::Variable::MultiplierRight(var);
            let o_var = r1cs::Variable::MultiplierOutput(var);

            Ok((l_var, r_var, o_var))
        }

        fn constrain(&mut self, _lc: r1cs::LinearCombination) {}

        fn metrics(&self) -> r1cs::Metrics {
            r1cs::Metrics {
                multipliers: self.num_multipliers,
                constraints: 0,
                phase_one_constraints: 0,
                phase_two_constraints: 0,
            }
        }
    }
}
