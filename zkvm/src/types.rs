//! Core ZkVM stack types: data, variables, values, contracts etc.

use bulletproofs::r1cs;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use spacesuit::SignedInteger;

use crate::constraints::{Commitment, Constraint, Expression, Variable};
use crate::contract::{Contract, Input, PortableItem};
use crate::encoding::SliceReader;
use crate::errors::VMError;
use crate::ops::Instruction;
use crate::predicate::Predicate;
use crate::scalar_witness::ScalarWitness;
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
    Program(Vec<Instruction>),
    Predicate(Box<Predicate>),
    Commitment(Box<Commitment>),
    Scalar(Box<ScalarWitness>),
    Input(Box<Input>),
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

impl Item {
    // Downcasts to Data type
    pub fn to_data(self) -> Result<Data, VMError> {
        match self {
            Item::Data(x) => Ok(x),
            _ => Err(VMError::TypeNotData),
        }
    }

    // Downcasts to Contract type
    pub fn to_contract(self) -> Result<Contract, VMError> {
        match self {
            Item::Contract(c) => Ok(c),
            _ => Err(VMError::TypeNotContract),
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

    // Downcasts to Constraint type
    pub fn to_constraint(self) -> Result<Constraint, VMError> {
        match self {
            Item::Constraint(c) => Ok(c),
            _ => Err(VMError::TypeNotConstraint),
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
}

impl Data {
    /// Returns the number of bytes needed to serialize the Data.
    pub fn serialized_length(&self) -> usize {
        match self {
            Data::Opaque(data) => data.len(),
            Data::Program(program) => program.iter().map(|p| p.serialized_length()).sum(),
            Data::Predicate(predicate) => predicate.serialized_length(),
            Data::Commitment(commitment) => commitment.serialized_length(),
            Data::Scalar(scalar) => scalar.serialized_length(),
            Data::Input(input) => input.serialized_length(),
        }
    }

    /// Converts the Data into a vector of bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.serialized_length());
        self.encode(&mut buf);
        buf
    }

    /// Downcast to a Predicate type.
    pub fn to_predicate(self) -> Result<Predicate, VMError> {
        match self {
            Data::Opaque(data) => {
                let point = SliceReader::parse(&data, |r| r.read_point())?;
                Ok(Predicate::Opaque(point))
            }
            Data::Predicate(p) => Ok(*p),
            _ => Err(VMError::TypeNotPredicate),
        }
    }

    pub fn to_commitment(self) -> Result<Commitment, VMError> {
        match self {
            Data::Opaque(data) => {
                let point = SliceReader::parse(&data, |r| r.read_point())?;
                Ok(Commitment::Closed(point))
            }
            Data::Commitment(c) => Ok(*c),
            _ => Err(VMError::TypeNotCommitment),
        }
    }

    pub fn to_input(self) -> Result<Input, VMError> {
        match self {
            Data::Opaque(data) => Input::from_bytes(data),
            Data::Input(i) => Ok(*i),
            _ => Err(VMError::TypeNotInput),
        }
    }

    /// Encodes blinded Data values.
    pub fn encode(&self, buf: &mut Vec<u8>) {
        match self {
            Data::Opaque(x) => buf.extend_from_slice(x),
            Data::Program(program) => Instruction::encode_program(program.iter(), buf),
            Data::Predicate(predicate) => predicate.encode(buf),
            Data::Commitment(commitment) => commitment.encode(buf),
            Data::Scalar(scalar) => scalar.encode(buf),
            Data::Input(input) => input.encode(buf),
        };
    }
}

impl Value {
    /// Computes a flavor as defined by the `issue` instruction from a predicate.
    pub fn issue_flavor(predicate: &Predicate) -> Scalar {
        let mut t = Transcript::new(b"ZkVM.issue");
        t.commit_bytes(b"predicate", predicate.to_point().as_bytes());
        t.challenge_scalar(b"flavor")
    }
}

// Upcasting all witness data types to Data

impl<T> From<T> for Data
where
    T: Into<ScalarWitness>,
{
    fn from(x: T) -> Self {
        Data::Scalar(Box::new(x.into()))
    }
}

impl From<Predicate> for Data {
    fn from(x: Predicate) -> Self {
        Data::Predicate(Box::new(x))
    }
}

impl From<Commitment> for Data {
    fn from(x: Commitment) -> Self {
        Data::Commitment(Box::new(x))
    }
}

impl From<Input> for Data {
    fn from(x: Input) -> Self {
        Data::Input(Box::new(x))
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
