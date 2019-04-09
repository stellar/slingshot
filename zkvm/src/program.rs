use crate::encoding::SliceReader;
use crate::errors::VMError;
use crate::merkle::{MerkleNeighbor, MerkleTree};
use crate::ops::Instruction;
use crate::predicate::{CallProof, PredicateTree};
use crate::scalar_witness::ScalarWitness;
use crate::types::Data;

use core::borrow::Borrow;
use spacesuit::BitRange;

/// A builder type for assembling a sequence of `Instruction`s with chained method calls.
/// E.g. `let prog = Program::new().push(...).input().push(...).output(1).to_vec()`.
#[derive(Clone, Debug)]
pub struct Program(Vec<Instruction>);

macro_rules! def_op {
    ($func_name:ident, $op:ident) => (
           /// Adds a `$func_name` instruction.
           pub fn $func_name(&mut self) -> &mut Program{
             self.0.push(Instruction::$op);
             self
        }
    );
    ($func_name:ident, $op:ident, $type:ty) => (
           /// Adds a `$func_name` instruction.
           pub fn $func_name(&mut self, arg :$type) -> &mut Program{
             self.0.push(Instruction::$op(arg));
             self
        }
    );
    ($func_name:ident, $op:ident, $type1:ty, $type2:ty) => (
           /// Adds a `$func_name` instruction.
           pub fn $func_name(&mut self, arg1: $type1, arg2: $type2) -> &mut Program{
             self.0.push(Instruction::$op(arg1, arg2));
             self
        }
    );
}

impl Program {
    def_op!(add, Add);
    def_op!(alloc, Alloc, Option<ScalarWitness>);
    def_op!(and, And);
    def_op!(borrow, Borrow);
    def_op!(call, Call);
    def_op!(cloak, Cloak, usize, usize);
    def_op!(r#const, Const);
    def_op!(contract, Contract, usize);
    def_op!(delegate, Delegate);
    def_op!(drop, Drop);
    def_op!(dup, Dup, usize);
    def_op!(eq, Eq);
    def_op!(export, Export);
    def_op!(expr, Expr);
    def_op!(import, Import);
    def_op!(input, Input);
    def_op!(issue, Issue);
    def_op!(log, Log);
    def_op!(maxtime, Maxtime);
    def_op!(mintime, Mintime);
    def_op!(mul, Mul);
    def_op!(neg, Neg);
    def_op!(nonce, Nonce);
    def_op!(or, Or);
    def_op!(output, Output, usize);
    def_op!(range, Range, BitRange);
    def_op!(retire, Retire);
    def_op!(roll, Roll, usize);
    def_op!(sign_tx, Signtx);
    def_op!(unblind, Unblind);
    def_op!(var, Var);
    def_op!(verify, Verify);

    /// Creates an empty `Program`.
    pub fn new() -> Self {
        Program(vec![])
    }

    /// Creates an empty `Program` and passes its &mut to the closure to let it add the instructions.
    /// Returns the resulting program.
    pub fn build<F>(builder: F) -> Self
    where
        F: FnOnce(&mut Self) -> &mut Self,
    {
        let mut program = Self::new();
        builder(&mut program);
        program
    }

    /// Creates a program from parsing the opaque data slice of encoded instructions.
    pub(crate) fn parse(data: &[u8]) -> Result<Self, VMError> {
        SliceReader::parse(data, |r| {
            let mut program = Self::new();
            while r.len() > 0 {
                program.0.push(Instruction::parse(r)?);
            }
            Ok(program)
        })
    }

    /// Converts the program to a plain vector of instructions.
    pub fn to_vec(self) -> Vec<Instruction> {
        self.0
    }

    /// Returns the serialized length of the program.
    pub(crate) fn serialized_length(&self) -> usize {
        self.0.iter().map(|p| p.serialized_length()).sum()
    }

    /// Encodes a program into a buffer.
    pub(crate) fn encode(&self, buf: &mut Vec<u8>) {
        for i in self.0.iter() {
            i.borrow().encode(buf);
        }
    }

    /// Adds a `push` instruction with an immediate data type that can be converted into `Data`.
    pub fn push<T: Into<Data>>(&mut self, data: T) -> &mut Program {
        self.0.push(Instruction::Push(data.into()));
        self
    }

    /// Takes predicate tree and index of program in Merkle tree to verify the program's membership in
    /// that Merkle tree and call the program.
    // PRTODO: Would the index of the program in the tree be passed? If not, how does this work?
    pub fn choose_call(
        &mut self,
        pred_tree: PredicateTree,
        index: usize,
    ) -> Result<&mut Program, VMError> {
        let tree = MerkleTree::build(b"ZkVM.taproot", &pred_tree.leaves);
        let neighbors = tree.create_path(index).unwrap();
        let mut positions: u32 = 0;
        for i in 0..neighbors.len() {
            match neighbors[i] {
                MerkleNeighbor::Right(_) => positions = positions | 1 << i,
                _ => {}
            }
        }
        let call_proof = CallProof {
            verification_key: pred_tree.key,
            neighbors: neighbors,
        };

        // PRTODO: I want to push both the program and the contract on the stack here,
        // but I'm unsure how to do that in a way that differentiates the two.
        self.push(Data::CallProof(call_proof)).call();
        self.push(self.clone()).call();
        Ok(self)
    }
}
