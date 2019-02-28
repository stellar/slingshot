//! Definition of all instructions in ZkVM,
//! their codes and decoding/encoding utility functions.

use core::borrow::Borrow;
use core::mem;

use crate::encoding;
use crate::encoding::SliceReader;
use crate::errors::VMError;
use crate::types::Data;

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
    Alloc,
    Mintime,
    Maxtime,
    Expr,
    Neg,
    Add,
    Mul,
    Eq,
    Range(u8), // bitwidth (1..64)
    And,
    Or,
    Verify,
    Blind,
    Reblind,
    Unblind,
    Issue,
    Borrow,
    Retire,
    Qty,
    Flavor,
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
    Blind = 0x12,
    Reblind = 0x13,
    Unblind = 0x14,
    Issue = 0x15,
    Borrow = 0x16,
    Retire = 0x17,
    Qty = 0x18,
    Flavor = 0x19,
    Cloak = 0x1a,
    Import = 0x1b,
    Export = 0x1c,
    Input = 0x1d,
    Output = 0x1e,
    Contract = 0x1f,
    Nonce = 0x20,
    Log = 0x21,
    Signtx = 0x22,
    Call = 0x23,
    Left = 0x24,
    Right = 0x25,
    Delegate = MAX_OPCODE,
}

const MAX_OPCODE: u8 = 0x26;

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
            Opcode::Alloc => Ok(Instruction::Alloc),
            Opcode::Mintime => Ok(Instruction::Mintime),
            Opcode::Maxtime => Ok(Instruction::Maxtime),
            Opcode::Expr => Ok(Instruction::Expr),
            Opcode::Neg => Ok(Instruction::Neg),
            Opcode::Add => Ok(Instruction::Add),
            Opcode::Mul => Ok(Instruction::Mul),
            Opcode::Eq => Ok(Instruction::Eq),
            Opcode::Range => {
                let bit_width = program.read_u8()?;
                Ok(Instruction::Range(bit_width))
            }
            Opcode::And => Ok(Instruction::And),
            Opcode::Or => Ok(Instruction::Or),
            Opcode::Verify => Ok(Instruction::Verify),
            Opcode::Blind => Ok(Instruction::Blind),
            Opcode::Reblind => Ok(Instruction::Reblind),
            Opcode::Unblind => Ok(Instruction::Unblind),
            Opcode::Issue => Ok(Instruction::Issue),
            Opcode::Borrow => Ok(Instruction::Borrow),
            Opcode::Retire => Ok(Instruction::Retire),
            Opcode::Qty => Ok(Instruction::Qty),
            Opcode::Flavor => Ok(Instruction::Flavor),
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
            Instruction::Alloc => write(Opcode::Alloc),
            Instruction::Mintime => write(Opcode::Mintime),
            Instruction::Maxtime => write(Opcode::Maxtime),
            Instruction::Expr => write(Opcode::Expr),
            Instruction::Neg => write(Opcode::Neg),
            Instruction::Add => write(Opcode::Add),
            Instruction::Mul => write(Opcode::Mul),
            Instruction::Eq => write(Opcode::Eq),
            Instruction::Range(bit_width) => {
                write(Opcode::Range);
                program.push(*bit_width);
            }
            Instruction::And => write(Opcode::And),
            Instruction::Or => write(Opcode::Or),
            Instruction::Verify => write(Opcode::Verify),
            Instruction::Blind => write(Opcode::Blind),
            Instruction::Reblind => write(Opcode::Reblind),
            Instruction::Unblind => write(Opcode::Unblind),
            Instruction::Issue => write(Opcode::Issue),
            Instruction::Borrow => write(Opcode::Borrow),
            Instruction::Retire => write(Opcode::Retire),
            Instruction::Qty => write(Opcode::Qty),
            Instruction::Flavor => write(Opcode::Flavor),
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

    /// Encodes the iterator of instructions into a buffer.
    pub fn encode_program<I>(iterator: I, program: &mut Vec<u8>)
    where
        I: IntoIterator,
        I::Item: Borrow<Self>,
    {
        for i in iterator.into_iter() {
            i.borrow().encode(program);
        }
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
    def_op!(alloc, Alloc);
    def_op!(and, And);
    def_op!(blind, Blind);
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
    def_op!(flavor, Flavor);
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
    def_op!(qty, Qty);
    def_op!(range, Range, u8);
    def_op!(reblind, Reblind);
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

    /// Converts the program to a plain vector of instructions.
    pub fn to_vec(self) -> Vec<Instruction> {
        self.0
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
}
