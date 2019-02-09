//! Core ZkVM stack types: data, variables, values, contracts etc.

use bulletproofs::{r1cs, PedersenGens};
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use spacesuit::SignedInteger;

use crate::encoding;
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

#[derive(Clone, Debug)]
pub enum Data {
    Opaque(Vec<u8>),
    Witness(DataWitness),
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
pub enum Predicate {
    Opaque(CompressedRistretto),
    Witness(Box<PredicateWitness>),
}

#[derive(Clone, Debug)]
pub enum Commitment {
    Closed(CompressedRistretto),
    Open(Box<CommitmentWitness>),
}

#[derive(Clone, Debug)]
pub enum Input {
    Opaque(Vec<u8>),
    Witness(Box<(FrozenContract, UTXO)>),
}

/// Prover's representation of the witness.
#[derive(Clone, Debug)]
pub enum DataWitness {
    Program(Vec<Instruction>),
    Predicate(Box<PredicateWitness>), // maybe having Predicate and one more indirection would be cleaner - lets see how it plays out
    Commitment(Box<CommitmentWitness>),
    Scalar(Box<Scalar>),
    Input(Box<(FrozenContract, UTXO)>),
}

/// Prover's representation of the predicate tree with all the secrets
#[derive(Clone, Debug)]
pub enum PredicateWitness {
    Key(Scalar),
    Program(Vec<Instruction>),
    Or(Box<(PredicateWitness, PredicateWitness)>),
}

/// Prover's representation of the commitment secret: witness and blinding factor
#[derive(Clone, Debug)]
pub struct CommitmentWitness {
    pub value: ScalarWitness,
    pub blinding: Scalar,
}

/// Representation of a Contract inside an Input that can be cloned.
#[derive(Clone, Debug)]
pub struct FrozenContract {
    pub(crate) payload: Vec<FrozenItem>,
    pub(crate) predicate: Predicate,
}

/// Representation of a PortableItem inside an Input that can be cloned.
#[derive(Clone, Debug)]
pub enum FrozenItem {
    Data(Data),
    Value(FrozenValue),
}

/// Representation of a Value inside an Input that can be cloned.
/// Note: values do not necessarily have open commitments. Some can be reblinded,
/// others can be passed-through to an output without going through `cloak` and the constraint system.
#[derive(Clone, Debug)]
pub struct FrozenValue {
    pub(crate) qty: Commitment,
    pub(crate) flv: Commitment,
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

    fn encode(&self, program: &mut Vec<u8>) {
        match self {
            Commitment::Closed(x) => program.extend_from_slice(&x.to_bytes()),
            Commitment::Open(w) => w.encode(program),
        }
    }
}

impl CommitmentWitness {
    pub fn to_point(&self) -> CompressedRistretto {
        let gens = PedersenGens::default();
        gens.commit(self.value.into(), self.blinding).compress()
    }

    fn encode(&self, program: &mut Vec<u8>) {
        program.extend_from_slice(&self.to_point().to_bytes());
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
        self.to_commitment().compress()
    }

    fn to_commitment(&self) -> RistrettoPoint {
        let gens = PedersenGens::default();
        match self {
            PredicateWitness::Key(s) => s * gens.B,
            PredicateWitness::Or(b) => {
                let mut t = Transcript::new(b"ZkVM.predicate");
                let (left, right) = (&b.0.to_commitment(), &b.1.to_commitment());
                t.commit_point(b"L", &left.compress());
                t.commit_point(b"R", &right.compress());
                let f = t.challenge_scalar(b"f");
                left + f * gens.B
            }
            PredicateWitness::Program(prog) => {
                let mut t = Transcript::new(b"ZkVM.predicate");
                let mut bytecode = Vec::new();
                Instruction::encode_program(prog.iter(), &mut bytecode);
                t.commit_bytes(b"prog", &bytecode);
                let h = t.challenge_scalar(b"h");
                h * gens.B_blinding
            }
        }
    }

    fn encode(&self, program: &mut Vec<u8>) {
        program.extend_from_slice(&self.to_point().to_bytes());
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
    /// Returns the length of the underlying vector of bytes.
    pub fn len(&self) -> usize {
        match self {
            Data::Opaque(data) => data.len(),
            Data::Witness(_) => unimplemented!(),
        }
    }

    /// Converts the Data into a vector of bytes
    pub fn to_bytes(self) -> Vec<u8> {
        match self {
            Data::Opaque(data) => data,
            Data::Witness(w) => {
                let mut bytes: Vec<u8> = Vec::new();
                w.encode(&mut bytes);
                bytes
            }
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

    /// Encodes blinded Data values for txprogram bytecode.
    pub fn encode(&self, program: &mut Vec<u8>) {
        match self {
            Data::Opaque(x) => {
                program.append(&mut x.clone());
                return;
            }
            Data::Witness(w) => w.encode(program),
        };
    }
}

impl DataWitness {
    fn encode(&self, program: &mut Vec<u8>) {
        match self {
            DataWitness::Program(instr) => Instruction::encode_program(instr.iter(), program),
            DataWitness::Predicate(pw) => pw.encode(program),
            DataWitness::Commitment(cw) => cw.encode(program),
            DataWitness::Scalar(s) => program.extend_from_slice(&s.to_bytes()),
            DataWitness::Input(b) => {
                // Input = PreviousTxID || PreviousOutput
                let (contract, _) = (&b.0, b.1);
                // TBD: get prev_txid
                let prev_txid: [u8; 32];
                program.extend_from_slice(&prev_txid);
                contract.encode(program);
            }
        }
    }
}

impl Contract {
    pub fn exact_output_size(&self) -> usize {
        let mut size = 32 + 4;
        for item in self.payload.iter() {
            match item {
                PortableItem::Data(d) => size += 1 + 4 + d.len(),
                PortableItem::Value(_) => size += 1 + 64,
            }
        }
        size
    }
}

impl FrozenContract {
    fn encode(&self, program: &mut Vec<u8>) {
        program.extend_from_slice(&self.predicate.to_point().to_bytes());
        for p in self.payload.iter() {
            match p {
                // Data = 0x00 || LE32(len) || <bytes>
                FrozenItem::Data(d) => {
                    program.push(0u8);
                    encoding::write_u32(d.len() as u32, program);
                    d.encode(program);
                }
                // Value = 0x01 || <32 bytes> || <32 bytes>
                FrozenItem::Value(v) => {
                    program.push(1u8);
                    program.extend_from_slice(&v.qty.to_point().to_bytes());
                    program.extend_from_slice(&v.qty.to_point().to_bytes());
                }
            }
        }
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
