//! Definition of all instructions in ZkVM,
//! their codes and decoding/encoding utility functions.

use crate::encoding;
use crate::encoding::SliceReader;
use crate::errors::VMError;
use crate::predicate::Predicate;
use crate::scalar_witness::ScalarWitness;
use crate::types::Data;
use core::borrow::Borrow;
use core::mem;
use spacesuit::BitRange;

/// A builder type for assembling a sequence of `Instruction`s with chained method calls.
/// E.g. `let prog = Program::new().push(...).input().push(...).output(1).to_vec()`.
#[derive(Clone, Debug)]
pub struct Program(Vec<Instruction>);

/// A decoded instruction.
#[derive(Clone, Debug)]
#[allow(missing_docs)]
pub enum Instruction {
    Push(Data), // size of the string
    Drop,
    Dup(usize),  // index of the item
    Roll(usize), // index of the item
    Const,
    Var,
    Alloc(Option<ScalarWitness>),
    Mintime,
    Maxtime,
    Expr,
    Neg,
    Add,
    Mul,
    Eq,
    Range(BitRange), // bitwidth (0...64)
    And,
    Or,
    Verify,
    Unblind,
    Issue,
    Borrow,
    Retire,
    Cloak(usize, usize), // M inputs, N outputs
    Import,
    Export,
    Input,
    Output(usize),   // payload count
    Contract(usize), // payload count
    Nonce,
    Log,
    Signtx,
    Call,
    Left,
    Right,
    Delegate,
    Ext(u8),
}

/// A bytecode representation of the instruction.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
#[allow(missing_docs)]
pub enum Opcode {
    Push = 0x00,
    Drop = 0x01,
    Dup = 0x02,
    Roll = 0x03,
    Const = 0x04,
    Var = 0x05,
    Alloc = 0x06,
    Mintime = 0x07,
    Maxtime = 0x08,
    Expr = 0x09,
    Neg = 0x0a,
    Add = 0x0b,
    Mul = 0x0c,
    Eq = 0x0d,
    Range = 0x0e,
    And = 0x0f,
    Or = 0x10,
    Verify = 0x11,
    Unblind = 0x12,
    Issue = 0x13,
    Borrow = 0x14,
    Retire = 0x15,
    Cloak = 0x16,
    Import = 0x17,
    Export = 0x18,
    Input = 0x19,
    Output = 0x1a,
    Contract = 0x1b,
    Nonce = 0x1c,
    Log = 0x1d,
    Signtx = 0x1e,
    Call = 0x1f,
    Left = 0x20,
    Right = 0x21,
    Delegate = MAX_OPCODE,
}

const MAX_OPCODE: u8 = 0x22;

impl Opcode {
    /// Converts the opcode to `u8`.
    pub fn to_u8(self) -> u8 {
        unsafe { mem::transmute(self) }
    }

    /// Instantiates the opcode from `u8`.
    /// Unassigned code is mapped to `None`.
    pub fn from_u8(code: u8) -> Option<Opcode> {
        if code > MAX_OPCODE {
            None
        } else {
            unsafe { mem::transmute(code) }
        }
    }
}

impl Instruction {
    /// Returns the number of bytes required to serialize this instruction.
    pub fn serialized_length(&self) -> usize {
        match self {
            Instruction::Push(data) => 1 + 4 + data.serialized_length(),
            Instruction::Dup(_) => 1 + 4,
            Instruction::Roll(_) => 1 + 4,
            Instruction::Range(_) => 1 + 1,
            Instruction::Cloak(_, _) => 1 + 4 + 4,
            Instruction::Output(_) => 1 + 4,
            Instruction::Contract(_) => 1 + 4,
            _ => 1,
        }
    }

    /// Returns a parsed instruction from a subslice of the program string, modifying
    /// the subslice according to the bytes the instruction occupies
    /// E.g. a push instruction with 5-byte string occupies 1+4+5=10 bytes,
    /// (4 for the LE32 length prefix), advancing the program subslice by 10 bytes.
    ///
    /// Return `VMError::FormatError` if there are not enough bytes to parse an
    /// instruction.
    pub fn parse(program: &mut SliceReader) -> Result<Self, VMError> {
        let byte = program.read_u8()?;

        // Interpret the opcode. Unknown opcodes are extension opcodes.
        let opcode = match Opcode::from_u8(byte) {
            None => {
                return Ok(Instruction::Ext(byte));
            }
            Some(op) => op,
        };

        match opcode {
            Opcode::Push => {
                let strlen = program.read_size()?;
                let data_slice = program.read_bytes(strlen)?;
                Ok(Instruction::Push(Data::Opaque(data_slice.to_vec())))
            }
            Opcode::Drop => Ok(Instruction::Drop),
            Opcode::Dup => {
                let idx = program.read_size()?;
                Ok(Instruction::Dup(idx))
            }
            Opcode::Roll => {
                let idx = program.read_size()?;
                Ok(Instruction::Roll(idx))
            }
            Opcode::Const => Ok(Instruction::Const),
            Opcode::Var => Ok(Instruction::Var),
            Opcode::Alloc => Ok(Instruction::Alloc(None)),
            Opcode::Mintime => Ok(Instruction::Mintime),
            Opcode::Maxtime => Ok(Instruction::Maxtime),
            Opcode::Expr => Ok(Instruction::Expr),
            Opcode::Neg => Ok(Instruction::Neg),
            Opcode::Add => Ok(Instruction::Add),
            Opcode::Mul => Ok(Instruction::Mul),
            Opcode::Eq => Ok(Instruction::Eq),
            Opcode::Range => {
                let bit_width =
                    BitRange::new(program.read_u8()? as usize).ok_or(VMError::FormatError)?;
                Ok(Instruction::Range(bit_width))
            }
            Opcode::And => Ok(Instruction::And),
            Opcode::Or => Ok(Instruction::Or),
            Opcode::Verify => Ok(Instruction::Verify),
            Opcode::Unblind => Ok(Instruction::Unblind),
            Opcode::Issue => Ok(Instruction::Issue),
            Opcode::Borrow => Ok(Instruction::Borrow),
            Opcode::Retire => Ok(Instruction::Retire),
            Opcode::Cloak => {
                let m = program.read_size()?;
                let n = program.read_size()?;
                Ok(Instruction::Cloak(m, n))
            }
            Opcode::Import => Ok(Instruction::Import),
            Opcode::Export => Ok(Instruction::Export),
            Opcode::Input => Ok(Instruction::Input),
            Opcode::Output => {
                let k = program.read_size()?;
                Ok(Instruction::Output(k))
            }
            Opcode::Contract => {
                let k = program.read_size()?;
                Ok(Instruction::Contract(k))
            }
            Opcode::Nonce => Ok(Instruction::Nonce),
            Opcode::Log => Ok(Instruction::Log),
            Opcode::Signtx => Ok(Instruction::Signtx),
            Opcode::Call => Ok(Instruction::Call),
            Opcode::Left => Ok(Instruction::Left),
            Opcode::Right => Ok(Instruction::Right),
            Opcode::Delegate => Ok(Instruction::Delegate),
        }
    }

    /// Appends the bytecode representation of an Instruction
    /// to the program.
    pub fn encode(&self, program: &mut Vec<u8>) {
        let mut write = |op: Opcode| program.push(op.to_u8());
        match self {
            Instruction::Push(data) => {
                write(Opcode::Push);
                encoding::write_u32(data.serialized_length() as u32, program);
                data.encode(program);
            }
            Instruction::Drop => write(Opcode::Drop),
            Instruction::Dup(idx) => {
                write(Opcode::Dup);
                encoding::write_u32(*idx as u32, program);
            }
            Instruction::Roll(idx) => {
                write(Opcode::Roll);
                encoding::write_u32(*idx as u32, program);
            }
            Instruction::Const => write(Opcode::Const),
            Instruction::Var => write(Opcode::Var),
            Instruction::Alloc(_) => write(Opcode::Alloc),
            Instruction::Mintime => write(Opcode::Mintime),
            Instruction::Maxtime => write(Opcode::Maxtime),
            Instruction::Expr => write(Opcode::Expr),
            Instruction::Neg => write(Opcode::Neg),
            Instruction::Add => write(Opcode::Add),
            Instruction::Mul => write(Opcode::Mul),
            Instruction::Eq => write(Opcode::Eq),
            Instruction::Range(n) => {
                write(Opcode::Range);
                let bit_width: BitRange = *n;
                program.push(bit_width.into());
            }
            Instruction::And => write(Opcode::And),
            Instruction::Or => write(Opcode::Or),
            Instruction::Verify => write(Opcode::Verify),
            Instruction::Unblind => write(Opcode::Unblind),
            Instruction::Issue => write(Opcode::Issue),
            Instruction::Borrow => write(Opcode::Borrow),
            Instruction::Retire => write(Opcode::Retire),
            Instruction::Cloak(m, n) => {
                write(Opcode::Cloak);
                encoding::write_u32(*m as u32, program);
                encoding::write_u32(*n as u32, program);
            }
            Instruction::Import => write(Opcode::Import),
            Instruction::Export => write(Opcode::Export),
            Instruction::Input => write(Opcode::Input),
            Instruction::Output(k) => {
                write(Opcode::Output);
                encoding::write_u32(*k as u32, program);
            }
            Instruction::Contract(k) => {
                write(Opcode::Contract);
                encoding::write_u32(*k as u32, program);
            }
            Instruction::Nonce => write(Opcode::Nonce),
            Instruction::Log => write(Opcode::Log),
            Instruction::Signtx => write(Opcode::Signtx),
            Instruction::Call => write(Opcode::Call),
            Instruction::Left => write(Opcode::Left),
            Instruction::Right => write(Opcode::Right),
            Instruction::Delegate => write(Opcode::Delegate),
            Instruction::Ext(x) => program.push(*x),
        };
    }
}

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
}

impl Program {
    def_op!(add, Add);
    def_op!(alloc, Alloc, Option<ScalarWitness>);
    def_op!(and, And);
    def_op!(borrow, Borrow);
    def_op!(call, Call);
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
    def_op!(left, Left);
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
    def_op!(right, Right);
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
    pub fn parse(data: &[u8]) -> Result<Self, VMError> {
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
    pub fn serialized_length(&self) -> usize {
        self.0.iter().map(|p| p.serialized_length()).sum()
    }

    /// Encodes a program into a buffer.
    pub fn encode(&self, buf: &mut Vec<u8>) {
        for i in self.0.iter() {
            i.borrow().encode(buf);
        }
    }

    /// Adds a `push` instruction with an immediate data type that can be converted into `Data`.
    pub fn push<T: Into<Data>>(&mut self, data: T) -> &mut Program {
        self.0.push(Instruction::Push(data.into()));
        self
    }

    /// Adds a `cloak` instruction for `m` inputs and `n` outputs.
    pub fn cloak(&mut self, m: usize, n: usize) -> &mut Program {
        self.0.push(Instruction::Cloak(m, n));
        self
    }

    /// Takes predicate and closure to add choose operations for
    /// predicate tree traversal.
    pub fn choose_predicate<F, T>(
        &mut self,
        pred: Predicate,
        choose_fn: F,
    ) -> Result<&mut Program, VMError>
    where
        F: FnOnce(PredicateTree) -> Result<T, VMError>,
    {
        choose_fn(PredicateTree {
            prog: self,
            pred: pred,
        })?;
        Ok(self)
    }
}

/// Adds data and instructions to traverse a predicate tree.
pub struct PredicateTree<'a> {
    prog: &'a mut Program,
    pred: Predicate,
}

impl<'a> PredicateTree<'a> {
    /// Left Predicate branch
    pub fn left(self) -> Result<Self, VMError> {
        let (l, r) = self.pred.to_disjunction()?;
        let prog = self.prog;
        prog.push(l.as_opaque()).push(r.as_opaque()).left();

        Ok(Self { pred: l, prog })
    }

    /// Right Predicate branch
    pub fn right(self) -> Result<Self, VMError> {
        let (l, r) = self.pred.to_disjunction()?;
        let prog = self.prog;
        prog.push(l.as_opaque()).push(r.as_opaque()).right();

        Ok(Self { pred: r, prog })
    }

    /// Pushes program to the stack and calls the contract protected
    /// by the program predicate.
    pub fn call(self) -> Result<(), VMError> {
        let (subprog, salt) = self.pred.to_program()?;
        self.prog.push(Data::Opaque(salt)).call();
        self.prog.push(subprog).call();
        Ok(())
    }
}
