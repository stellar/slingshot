use crate::encoding::*;
use crate::errors::VMError;
use crate::merkle::MerkleItem;
use crate::ops::Instruction;
use crate::predicate::PredicateTree;
use crate::scalar_witness::ScalarWitness;
use crate::types::String;

use alloc::vec;
use core::borrow::Borrow;
use merlin::Transcript;
use serde::{Deserialize, Serialize};

/// A builder type for assembling a sequence of `Instruction`s with chained method calls.
///
/// Example:
/// ```ascii
/// let prog = Program::new()
///            .push(...)
///            .input()
///            .push(...)
///            .output(1)
///            .to_vec()
/// ```
#[derive(Clone, PartialEq, Deserialize, Serialize)]
pub struct Program(Vec<Instruction>);

/// Represents a view of a program.
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub enum ProgramItem {
    /// `ProgramItem::Bytecode` represents the verifier's view - a Vector of bytecode-as-is.
    Bytecode(Vec<u8>),
    /// `ProgramItem::Program` represents the prover's view - a Program struct.
    Program(Program),
}

macro_rules! doc_expr {
    ($opname:expr, $op:ident) => {
        concat!(
            "Adds [`",
            $opname,
            "`](crate::ops::Instruction::",
            stringify!($op),
            ") instruction."
        )
    };
}

macro_rules! def_op {
    ($func_name:ident, $op:ident, $opname:expr) => {
        def_op_inner!($func_name, $op, doc_expr!($opname, $op));
    };
    ($func_name:ident, $op:ident, $arg_type:ty, $opname:expr) => {
        def_op_inner!($func_name, $op, $arg_type, doc_expr!($opname, $op));
    };
    ($func_name:ident, $op:ident, $arg_type1:ty, $arg_type2:ty, $opname:expr) => {
        def_op_inner!(
            $func_name,
            $op,
            $arg_type1,
            $arg_type2,
            doc_expr!($opname, $op)
        );
    };
}

macro_rules! def_op_inner {
    ($func_name:ident, $op:ident, $doc_expr:expr) => {
        #[doc = $doc_expr]
        pub fn $func_name(&mut self) -> &mut Program {
            self.0.push(Instruction::$op);
            self
        }
    };
    ($func_name:ident, $op:ident, $arg_type:ty, $doc_expr:expr) => {
        #[doc = $doc_expr]
        pub fn $func_name(&mut self, arg: $arg_type) -> &mut Program {
            self.0.push(Instruction::$op(arg));
            self
        }
    };
    ($func_name:ident, $op:ident, $arg_type1:ty, $arg_type2:ty, $doc_expr:expr) => {
        #[doc = $doc_expr]
        pub fn $func_name(&mut self, arg1: $arg_type1, arg2: $arg_type2) -> &mut Program {
            self.0.push(Instruction::$op(arg1, arg2));
            self
        }
    };
}

impl Encodable for Program {
    fn encode(&self, w: &mut impl Writer) -> Result<(), WriteError> {
        for i in self.0.iter() {
            i.borrow().encode(w)?;
        }
        Ok(())
    }
}

impl ExactSizeEncodable for Program {
    fn encoded_size(&self) -> usize {
        self.0.iter().map(|p| p.encoded_size()).sum()
    }
}

impl core::ops::Deref for Program {
    type Target = [Instruction];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Program {
    /// Creates an empty `Program`.
    pub fn new() -> Self {
        Program(vec![])
    }

    /// Creates a new program from a vector of instructions.
    pub fn from_vec(v: Vec<Instruction>) -> Self {
        Program(v)
    }

    /// Creates an empty `Program` and passes its &mut to the closure to let it add the instructions.
    /// Returns the resulting program.
    pub fn build<F>(builder: F) -> Self
    where
        F: FnOnce(&mut Self) -> (),
    {
        let mut program = Self::new();
        builder(&mut program);
        program
    }

    /// Creates a program by parsing a bytecode slice.
    pub fn parse(mut data: &[u8]) -> Result<Self, VMError> {
        data.read_all(|r| {
            let mut program = Self::new();
            while r.remaining_bytes() > 0 {
                program.0.push(Instruction::parse(r)?);
            }
            Ok(program)
        })
    }

    /// Adds a [`push:n:x`](crate::ops::Instruction::Push) instruction.
    pub fn push<T: Into<String>>(&mut self, data: T) -> &mut Program {
        self.0.push(Instruction::Push(data.into()));
        self
    }

    /// Adds a [`program:n:x`](crate::ops::Instruction::Program) instruction.
    pub fn program<T: Into<ProgramItem>>(&mut self, prog: T) -> &mut Program {
        self.0.push(Instruction::Program(prog.into()));
        self
    }

    def_op!(drop, Drop, "drop");
    def_op!(dup, Dup, usize, "dup:k");
    def_op!(roll, Roll, usize, "roll:k");
    def_op!(scalar, Scalar, "scalar");
    def_op!(commit, Commit, "commit");
    def_op!(alloc, Alloc, Option::<ScalarWitness>, "alloc");
    def_op!(mintime, Mintime, "mintime");
    def_op!(maxtime, Maxtime, "maxtime");
    def_op!(expr, Expr, "expr");
    def_op!(neg, Neg, "neg");
    def_op!(add, Add, "add");
    def_op!(mul, Mul, "mul");
    def_op!(eq, Eq, "eq");
    def_op!(range, Range, "range");
    def_op!(and, And, "and");
    def_op!(or, Or, "or");
    def_op!(not, Not, "not");
    def_op!(verify, Verify, "verify");

    def_op!(unblind, Unblind, "unblind");

    def_op!(issue, Issue, "issue");
    def_op!(borrow, Borrow, "borrow");
    def_op!(retire, Retire, "retire");

    def_op!(cloak, Cloak, usize, usize, "cloak:m:n");
    def_op!(fee, Fee, "fee");
    def_op!(input, Input, "input");
    def_op!(output, Output, usize, "output:k");
    def_op!(contract, Contract, usize, "contract:k");

    def_op!(log, Log, "log");
    def_op!(eval, Eval, "eval");
    def_op!(call, Call, "call");
    def_op!(signtx, Signtx, "signtx");
    def_op!(signid, Signid, "signid");
    def_op!(signtag, Signtag, "signtag");

    /// Takes predicate tree and index of program in Merkle tree to verify
    /// the program's membership in that Merkle tree and call the program.
    pub fn choose_call(
        &mut self,
        pred_tree: PredicateTree,
        prog_index: usize,
    ) -> Result<&mut Program, VMError> {
        let (call_proof, program) = pred_tree.create_callproof(prog_index)?;
        self.push(String::Opaque(call_proof.to_bytes()))
            .program(program)
            .call();
        Ok(self)
    }

    /// Serializes a Program into a byte array.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.encode_to_vec()
    }

    /// Converts the program to a plain vector of instructions.
    pub fn to_vec(self) -> Vec<Instruction> {
        self.0
    }
}

impl Encodable for ProgramItem {
    fn encode(&self, w: &mut impl Writer) -> Result<(), WriteError> {
        match self {
            ProgramItem::Program(prog) => w.write(b"program", &prog.encode_to_vec()),
            ProgramItem::Bytecode(bytes) => w.write(b"program", &bytes),
        }
    }
}
impl ExactSizeEncodable for ProgramItem {
    fn encoded_size(&self) -> usize {
        match self {
            ProgramItem::Program(prog) => prog.encoded_size(),
            ProgramItem::Bytecode(vec) => vec.len(),
        }
    }
}

impl ProgramItem {
    /// Encodes the program item into a bytecode array.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.encode_to_vec()
    }

    /// Downcasts a program item into a program.
    pub fn to_program(self) -> Result<Program, VMError> {
        match self {
            ProgramItem::Program(prog) => Ok(prog),
            ProgramItem::Bytecode(_) => return Err(VMError::TypeNotProgram),
        }
    }

    /// Downcasts a program item into a vector of bytes.
    /// Fails if called on a non-opaque `ProgramItem::Program`.
    /// Use `encode` method to serialize both opaque/nonopaque programs.
    pub fn to_bytecode(self) -> Result<Vec<u8>, VMError> {
        match self {
            ProgramItem::Program(_) => return Err(VMError::TypeNotProgram),
            ProgramItem::Bytecode(bytes) => Ok(bytes),
        }
    }
}

impl From<Program> for ProgramItem {
    fn from(x: Program) -> Self {
        ProgramItem::Program(x)
    }
}

impl MerkleItem for ProgramItem {
    fn commit(&self, t: &mut Transcript) {
        match self {
            ProgramItem::Program(prog) => prog.commit(t),
            ProgramItem::Bytecode(bytes) => t.append_message(b"program", &bytes),
        }
    }
}

impl MerkleItem for Program {
    fn commit(&self, t: &mut Transcript) {
        t.append_message(b"program", &self.to_bytes());
    }
}

impl core::iter::Extend<Instruction> for Program {
    fn extend<T>(&mut self, iter: T)
    where
        T: IntoIterator<Item = Instruction>,
    {
        self.0.extend(iter)
    }
}

impl core::iter::IntoIterator for Program {
    type Item = Instruction;
    type IntoIter = vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}
