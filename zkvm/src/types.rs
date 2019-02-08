//! Core ZkVM stack types: data, variables, values, contracts etc.

use bulletproofs::{r1cs, PedersenGens};
use byteorder::{ByteOrder, LittleEndian};
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;

use crate::encoding::Subslice;
use crate::errors::VMError;
use crate::ops::Instruction;
use crate::transcript::TranscriptProtocol;
use crate::txlog::UTXO;

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

#[derive(Debug)]
pub enum PortableItem {
    Data(Data),
    Value(Value),
}

#[derive(Debug)]
pub enum Data {
    Opaque(Vec<u8>),
    Witness(DataWitness),
}

impl Data {
    pub fn to_bytes(self) -> Vec<u8> {
        match self {
            Data::Opaque(data) => data,
            Data::Witness(_) => unimplemented!(),
        }
    }
}

#[derive(Debug)]
pub struct Contract {
    pub(crate) payload: Vec<PortableItem>,
    pub(crate) predicate: Predicate,
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
    pub(crate) witness: Option<(Scalar, Scalar)>,
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
    pub(crate) assignment: Option<u64>,
}

#[derive(Clone, Debug)]
pub enum Constraint {
    Eq(Expression, Expression),
    And(Vec<Constraint>),
    Or(Vec<Constraint>),
    // no witness needed as it's normally true/false and we derive it on the fly during processing.
    // this also allows us not to wrap this enum in a struct.
}

#[derive(Debug)]
pub enum Predicate {
    Opaque(CompressedRistretto),
    Witness(Box<PredicateWitness>),
}

#[derive(Clone, Debug)]
pub enum Commitment {
    Closed(CompressedRistretto),
    Open(Box<CommitmentWitness>),
}

#[derive(Debug)]
pub enum Input {
    Opaque(Vec<u8>),
    Witness(Box<(Contract, UTXO)>),
}

/// Prover's representation of the witness.
#[derive(Debug)]
pub enum DataWitness {
    Program(Vec<Instruction>),
    Predicate(Box<PredicateWitness>), // maybe having Predicate and one more indirection would be cleaner - lets see how it plays out
    Commitment(Box<CommitmentWitness>),
    Scalar(Box<Scalar>),
    Input(Box<(Contract, UTXO)>),
}

/// Prover's representation of the predicate tree with all the secrets
#[derive(Debug)]
pub enum PredicateWitness {
    Key(Scalar),
    Program(Vec<Instruction>),
    Or(Box<(PredicateWitness, PredicateWitness)>),
}

/// Prover's representation of the commitment secret: witness and blinding factor
#[derive(Clone, Debug)]
pub struct CommitmentWitness {
    pub value: ScalarKind,
    pub blinding: Scalar,
}

#[derive(Copy,Clone,Debug)]
pub enum ScalarKind {
    Integer(u64),
    Scalar(Scalar),
}

impl Commitment {
    pub fn to_point(&self) -> CompressedRistretto {
        match self {
            Commitment::Closed(x) => *x,
            Commitment::Open(w) => w.to_point(),
        }
    }
}

impl CommitmentWitness {
    pub fn to_point(&self) -> CompressedRistretto {
        let gens = PedersenGens::default();
        gens.commit(self.value.into(), self.blinding).compress()
    }
}

impl Into<Scalar> for ScalarKind {
    fn into(self) -> Scalar {
        match self {
            ScalarKind::Integer(i) => i.into(),
            ScalarKind::Scalar(s) => s
        }
    }
}

impl Predicate {
    pub fn to_point(&self) -> CompressedRistretto {
        match self {
            Predicate::Opaque(point) => *point,
            Predicate::Witness(witness) => witness.to_point(),
        }
    }
}

impl PredicateWitness {
    pub fn to_point(&self) -> CompressedRistretto {
        unimplemented!()
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
    // len returns the length of the data for purposes of
    // allocating output.
    pub fn exact_output_size(&self) -> usize {
        match self {
            Data::Opaque(data) => data.len(),
            Data::Witness(_) => unimplemented!(),
        }
    }

    // TBD: make frozen types that are clonable
    pub fn tbd_clone(&self) -> Result<Data, VMError> {
        match self {
            Data::Opaque(data) => Ok(Data::Opaque(data.to_vec())),
            Data::Witness(_) => unimplemented!(),
        }
    }

    /// Downcast to a Predicate type.
    pub fn to_predicate(self) -> Result<Predicate, VMError> {
        match self {
            Data::Opaque(data) => {
                let point = Subslice::new(&data).read_point()?;
                Ok(Predicate::Opaque(point))
            }
            Data::Witness(witness) => match witness {
                DataWitness::Predicate(w) => Ok(Predicate::Witness(w)),
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
            Data::Opaque(data) => Ok(Input::Opaque(data)),
            Data::Witness(witness) => match witness {
                DataWitness::Input(w) => Ok(Input::Witness(w)),
                _ => Err(VMError::TypeNotInput),
            },
        }
    }
}

impl Contract {
    pub fn exact_output_size(&self) -> usize {
        let mut size = 32 + 4;
        for item in self.payload.iter() {
            match item {
                PortableItem::Data(d) => size += 1 + 4 + d.exact_output_size(),
                PortableItem::Value(_) => size += 1 + 64,
            }
        }
        size
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
