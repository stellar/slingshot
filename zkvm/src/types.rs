//! Core ZkVM stack types: data, variables, values, contracts etc.

use bulletproofs::{r1cs, PedersenGens};
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use spacesuit::SignedInteger;

use crate::contract::{Contract, Input, PortableItem};
use crate::encoding::Subslice;
use crate::errors::VMError;
use crate::ops::Instruction;
use crate::predicate::Predicate;
use crate::transcript::TranscriptProtocol;

use std::ops::Add;
use std::ops::Neg;

#[derive(Debug)]
pub enum Item {
    Data(Data),
    Contract(Contract),
    Value(Value),
    WideValue(WideValue),
    Variable(Variable),
    Expression(Expression),
    Constraint(Constraint),
}

#[derive(Clone, Debug)]
pub enum Data {
    Opaque(Vec<u8>),
    Witness(DataWitness),
}

#[derive(Debug)]
pub struct Value {
    pub(crate) qty: Variable,
    pub(crate) flv: Variable,
}

#[derive(Debug)]
pub struct WideValue {
    pub(crate) r1cs_qty: r1cs::Variable,
    pub(crate) r1cs_flv: r1cs::Variable,
    pub(crate) witness: Option<(SignedInteger, Scalar)>,
}

#[derive(Copy, Clone, Debug)]
pub struct Variable {
    pub(crate) index: usize,
    // the witness is located indirectly in vm::VariableCommitment
}

pub type ExpressionTerm = (r1cs::Variable, Scalar);
#[derive(Clone, Debug)]
pub enum Expression {
    Constant(ScalarWitness),
    Terms(Vec<ExpressionTerm>, Option<ScalarWitness>),
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

/// Prover's representation of the witness.
#[derive(Clone, Debug)]
pub enum DataWitness {
    Program(Vec<Instruction>),
    Predicate(Box<Predicate>),
    Commitment(Box<Commitment>),
    Scalar(Box<ScalarWitness>),
    Input(Box<Input>),
}

/// Prover's representation of the commitment secret: witness and blinding factor
#[derive(Clone, Debug)]
pub struct CommitmentWitness {
    pub value: ScalarWitness,
    pub blinding: Scalar,
}

/// Represents a concrete kind of a number represented by a scalar:
/// `ScalarKind::Integer` represents a signed integer with 64-bit absolute value (aka i65)
/// `ScalarKind::Scalar` represents a scalar modulo group order.
#[derive(Copy, Clone, Debug)]
pub enum ScalarWitness {
    Integer(SignedInteger),
    Scalar(Scalar),
}

impl Commitment {
    pub fn to_point(&self) -> CompressedRistretto {
        match self {
            Commitment::Closed(x) => *x,
            Commitment::Open(w) => w.to_point(),
        }
    }

    pub(crate) fn encode(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.to_point().to_bytes());
    }
}

impl CommitmentWitness {
    pub fn to_point(&self) -> CompressedRistretto {
        let gens = PedersenGens::default();
        gens.commit(self.value.into(), self.blinding).compress()
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
            (ScalarWitness::Integer(a), ScalarWitness::Integer(b)) => {
                let res = a + b;

                let max = spacesuit::SignedInteger::from(std::u64::MAX);
                let min = -max;
                if res > max || res < min {
                    ScalarWitness::Scalar(res.into())
                } else {
                    ScalarWitness::Integer(res)
                }
            }
            (ScalarWitness::Scalar(a), ScalarWitness::Scalar(b)) => ScalarWitness::Scalar(a + b),
            (ScalarWitness::Integer(a), ScalarWitness::Scalar(b)) => {
                let x: Scalar = a.into();
                ScalarWitness::Scalar(x + b)
            }
            (ScalarWitness::Scalar(a), ScalarWitness::Integer(b)) => {
                let x: Scalar = b.into();
                ScalarWitness::Scalar(x + a)
            }
        }
    }
}

impl Into<Scalar> for ScalarWitness {
    fn into(self) -> Scalar {
        match self {
            ScalarWitness::Integer(i) => i.into(),
            ScalarWitness::Scalar(s) => s,
        }
    }
}

impl Item {
    // Downcasts to Data type
    pub fn to_data(self) -> Result<Data, VMError> {
        match self {
            Item::Data(x) => Ok(x),
            _ => Err(VMError::TypeNotData),
        }
    }

    // Downcasts to a portable type
    pub fn to_portable(self) -> Result<PortableItem, VMError> {
        match self {
            Item::Data(x) => Ok(PortableItem::Data(x)),
            Item::Value(x) => Ok(PortableItem::Value(x)),
            _ => Err(VMError::TypeNotPortable),
        }
    }

    // Downcasts to Variable type
    pub fn to_variable(self) -> Result<Variable, VMError> {
        match self {
            Item::Variable(v) => Ok(v),
            _ => Err(VMError::TypeNotVariable),
        }
    }

    // Downcasts to Expression type (Variable is NOT casted to Expression)
    pub fn to_expression(self) -> Result<Expression, VMError> {
        match self {
            Item::Expression(expr) => Ok(expr),
            _ => Err(VMError::TypeNotExpression),
        }
    }

    // Downcasts to Value type
    pub fn to_value(self) -> Result<Value, VMError> {
        match self {
            Item::Value(v) => Ok(v),
            _ => Err(VMError::TypeNotValue),
        }
    }

    // Downcasts to WideValue type (Value is NOT casted to WideValue)
    pub fn to_wide_value(self) -> Result<WideValue, VMError> {
        match self {
            Item::WideValue(w) => Ok(w),
            _ => Err(VMError::TypeNotWideValue),
        }
    }

    // Downcasts to Contract type
    pub fn to_contract(self) -> Result<Contract, VMError> {
        match self {
            Item::Contract(c) => Ok(c),
            _ => Err(VMError::TypeNotContract),
        }
    }
}

impl Data {
    /// Returns a guaranteed lower bound on the number of bytes
    /// needed to serialize the Data.
    pub fn min_serialized_length(&self) -> usize {
        match self {
            Data::Opaque(data) => data.len(),
            Data::Witness(_) => 0,
        }
    }

    /// Converts the Data into a vector of bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Data::Opaque(data) => data.clone(),
            Data::Witness(w) => {
                let mut bytes: Vec<u8> = Vec::with_capacity(self.min_serialized_length());
                w.encode(&mut bytes);
                bytes.clone()
            }
        }
    }

    /// Downcast to a Predicate type.
    pub fn to_predicate(self) -> Result<Predicate, VMError> {
        match self {
            Data::Opaque(data) => {
                let point = Subslice::new(&data).read_point()?;
                Ok(Predicate::opaque(point))
            }
            Data::Witness(witness) => match witness {
                DataWitness::Predicate(boxed_pred) => Ok(*boxed_pred),
                _ => Err(VMError::TypeNotPredicate),
            },
        }
    }

    pub fn to_commitment(self) -> Result<Commitment, VMError> {
        match self {
            Data::Opaque(data) => {
                let point = Subslice::new(&data).read_point()?;
                Ok(Commitment::Closed(point))
            }
            Data::Witness(witness) => match witness {
                DataWitness::Commitment(w) => Ok(*w),
                _ => Err(VMError::TypeNotCommitment),
            },
        }
    }

    pub fn to_input(self) -> Result<Input, VMError> {
        match self {
            Data::Opaque(data) => Input::from_bytes(data),
            Data::Witness(witness) => match witness {
                DataWitness::Input(i) => Ok(*i),
                _ => Err(VMError::TypeNotInput),
            },
        }
    }

    /// Encodes blinded Data values.
    pub fn encode(&self, buf: &mut Vec<u8>) {
        match self {
            Data::Opaque(x) => {
                buf.extend_from_slice(x);
                return;
            }
            Data::Witness(w) => w.encode(buf),
        };
    }
}

impl DataWitness {
    fn encode(&self, buf: &mut Vec<u8>) {
        match self {
            DataWitness::Program(instr) => Instruction::encode_program(instr.iter(), buf),
            DataWitness::Predicate(pw) => pw.encode(buf),
            DataWitness::Commitment(c) => c.encode(buf),
            DataWitness::Scalar(s) => {
                let s: Scalar = (*s.clone()).into();
                buf.extend_from_slice(&s.to_bytes())
            }
            DataWitness::Input(b) => b.encode(buf),
        }
    }
}

impl Value {
    /// Computes a flavor as defined by the `issue` instruction from a predicate.
    pub fn issue_flavor(predicate: &Predicate) -> Scalar {
        let mut t = Transcript::new(b"ZkVM.issue");
        t.commit_bytes(b"predicate", predicate.point().as_bytes());
        t.challenge_scalar(b"flavor")
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
            Expression::Terms(mut terms, assignment) => {
                for (_, n) in terms.iter_mut() {
                    *n = -*n;
                }

                let x = match assignment {
                    Some(a) => Some(-a),
                    None => None,
                };
                Expression::Terms(terms, x)
            }
        }
    }
}

impl Add for Expression {
    type Output = Expression;

    fn add(self, rhs: Expression) -> Expression {
        match (self, rhs) {
            (Expression::Constant(a), Expression::Constant(b)) => Expression::Constant(a + b),
            (Expression::Constant(left), Expression::Terms(mut right_terms, right_assignment)) => {
                // concatenate constant term to term vector in non-constant expression
                terms.push((r1cs::Variable::One(), a.into()));

                // Add assignments
                let ass = match assignment {
                    Some(b) => Some(a + b),
                    _ => None,
                };
                Expression::Terms(terms, ass)
            }
            (Expression::Terms(mut terms, assignment), Expression::Constant(b)) => {
                // concatenate constant term to term vector in non-constant expression
                terms.push((r1cs::Variable::One(), b.into()));

                // Add assignments
                let ass = match assignment {
                    Some(a) => Some(a + b),
                    _ => None,
                };

                Expression::Terms(terms, ass)
            }
            (Expression::Terms(t1, a1), Expression::Terms(t2, a2)) => {
                // concatenate terms from both non-constant expressions
                let mut terms: Vec<ExpressionTerm> = Vec::new();
                terms.extend(t1);
                terms.extend(t2);

                // Add assignments
                let ass = match (a1, a2) {
                    (Some(a), Some(b)) => Some(a + b),
                    _ => None,
                };
                Expression::Terms(terms, ass)
            }
        }
    }
}

// Upcasting integers/scalars into ScalarWitness

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

// Upcasting all witness data types to Data and DataWitness

// Anything convertible to DataWitness is also convertible to Data
impl<T> From<T> for Data
where
    T: Into<DataWitness>,
{
    fn from(w: T) -> Self {
        Data::Witness(w.into())
    }
}

impl<T> From<T> for DataWitness
where
    T: Into<ScalarWitness>,
{
    fn from(x: T) -> Self {
        DataWitness::Scalar(Box::new(x.into()))
    }
}

impl From<Predicate> for DataWitness {
    fn from(x: Predicate) -> Self {
        DataWitness::Predicate(Box::new(x))
    }
}

impl From<Commitment> for DataWitness {
    fn from(x: Commitment) -> Self {
        DataWitness::Commitment(Box::new(x))
    }
}

impl From<Input> for DataWitness {
    fn from(x: Input) -> Self {
        DataWitness::Input(Box::new(x))
    }
}

// Upcasting all types to Item

impl From<Data> for Item {
    fn from(x: Data) -> Self {
        Item::Data(x)
    }
}

impl From<Value> for Item {
    fn from(x: Value) -> Self {
        Item::Value(x)
    }
}

impl From<WideValue> for Item {
    fn from(x: WideValue) -> Self {
        Item::WideValue(x)
    }
}

impl From<Contract> for Item {
    fn from(x: Contract) -> Self {
        Item::Contract(x)
    }
}

impl From<Variable> for Item {
    fn from(x: Variable) -> Self {
        Item::Variable(x)
    }
}

impl From<Expression> for Item {
    fn from(x: Expression) -> Self {
        Item::Expression(x)
    }
}

impl From<Constraint> for Item {
    fn from(x: Constraint) -> Self {
        Item::Constraint(x)
    }
}

// Upcast a portable item to any item
impl From<PortableItem> for Item {
    fn from(portable: PortableItem) -> Self {
        match portable {
            PortableItem::Data(x) => Item::Data(x),
            PortableItem::Value(x) => Item::Value(x),
        }
    }
}
