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

#[derive(Clone, Debug)]
pub struct Expression {
    /// Terms of the expression
    pub(crate) terms: Vec<(r1cs::Variable, Scalar)>,
    pub(crate) assignment: Option<ScalarWitness>,
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
    Commitment(Box<CommitmentWitness>),
    Scalar(Box<Scalar>),
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

    pub fn ensure_closed(&self) -> Result<CompressedRistretto, VMError> {
        match self {
            Commitment::Open(_) => Err(VMError::DataNotOpaque),
            Commitment::Closed(x) => Ok(*x),
        }
    }
}

impl CommitmentWitness {
    pub fn to_point(&self) -> CompressedRistretto {
        let gens = PedersenGens::default();
        gens.commit(self.value.into(), self.blinding).compress()
    }

    pub(crate) fn encode(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.to_point().to_bytes());
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
                DataWitness::Commitment(w) => Ok(Commitment::Open(w)),
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
            DataWitness::Commitment(cw) => cw.encode(buf),
            DataWitness::Scalar(s) => buf.extend_from_slice(&s.to_bytes()),
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
    pub fn constant<S: Into<Scalar>>(a: S) -> Self {
        let a: Scalar = a.into();

        Expression {
            terms: vec![(r1cs::Variable::One(), a)],
            assignment: Some(ScalarWitness::Scalar(a)),
        }
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
