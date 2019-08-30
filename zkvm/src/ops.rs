//! Definition of all instructions in ZkVM,
//! their codes and decoding/encoding utility functions.

use crate::encoding;
use crate::encoding::Encodable;
use crate::encoding::SliceReader;
use crate::errors::VMError;
use crate::program::ProgramItem;
use crate::scalar_witness::ScalarWitness;
use crate::types::String;
use core::mem;

/// A decoded instruction.
#[derive(Clone, PartialEq)]
#[allow(missing_docs)]
pub enum Instruction {
    Push(String),
    Program(ProgramItem),
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
    Range,
    And,
    Or,
    Not,
    Verify,
    Unblind,
    Issue,
    Borrow,
    Retire,
    Cloak(usize, usize), // M inputs, N outputs
    Input,
    Output(usize),   // payload count
    Contract(usize), // payload count
    Log,
    Call,
    Signtx,
    Signid,
    Signtag,
    Ext(u8),
}

/// A bytecode representation of the instruction.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
#[allow(missing_docs)]
pub enum Opcode {
    Push = 0x00,
    Program = 0x01,
    Drop = 0x02,
    Dup = 0x03,
    Roll = 0x04,
    Const = 0x05,
    Var = 0x06,
    Alloc = 0x07,
    Mintime = 0x08,
    Maxtime = 0x09,
    Expr = 0x0a,
    Neg = 0x0b,
    Add = 0x0c,
    Mul = 0x0d,
    Eq = 0x0e,
    Range = 0x0f,
    And = 0x10,
    Or = 0x11,
    Not = 0x12,
    Verify = 0x13,
    Unblind = 0x14,
    Issue = 0x15,
    Borrow = 0x16,
    Retire = 0x17,
    Cloak = 0x18,
    Input = 0x19,
    Output = 0x1a,
    Contract = 0x1b,
    Log = 0x1c,
    Call = 0x1d,
    Signtx = 0x1e,
    Signid = 0x1f,
    Signtag = MAX_OPCODE,
}

const MAX_OPCODE: u8 = 0x20;

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

impl Encodable for Instruction {
    /// Appends the bytecode representation of an Instruction
    /// to the program.
    fn encode(&self, program: &mut Vec<u8>) {
        let mut write = |op: Opcode| program.push(op.to_u8());
        match self {
            Instruction::Push(data) => {
                write(Opcode::Push);
                encoding::write_u32(data.serialized_length() as u32, program);
                data.encode(program);
            }
            Instruction::Program(subprog) => {
                write(Opcode::Program);
                encoding::write_u32(subprog.serialized_length() as u32, program);
                subprog.encode(program);
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
            Instruction::Range => write(Opcode::Range),
            Instruction::And => write(Opcode::And),
            Instruction::Or => write(Opcode::Or),
            Instruction::Not => write(Opcode::Not),
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
            Instruction::Input => write(Opcode::Input),
            Instruction::Output(k) => {
                write(Opcode::Output);
                encoding::write_u32(*k as u32, program);
            }
            Instruction::Contract(k) => {
                write(Opcode::Contract);
                encoding::write_u32(*k as u32, program);
            }
            Instruction::Log => write(Opcode::Log),
            Instruction::Call => write(Opcode::Call),
            Instruction::Signtx => write(Opcode::Signtx),
            Instruction::Signid => write(Opcode::Signid),
            Instruction::Signtag => write(Opcode::Signtag),
            Instruction::Ext(x) => program.push(*x),
        };
    }

    /// Returns the number of bytes required to serialize this instruction.
    fn serialized_length(&self) -> usize {
        match self {
            Instruction::Push(data) => 1 + 4 + data.serialized_length(),
            Instruction::Program(progitem) => 1 + 4 + progitem.serialized_length(),
            Instruction::Dup(_) => 1 + 4,
            Instruction::Roll(_) => 1 + 4,
            Instruction::Range => 1,
            Instruction::Cloak(_, _) => 1 + 4 + 4,
            Instruction::Output(_) => 1 + 4,
            Instruction::Contract(_) => 1 + 4,
            _ => 1,
        }
    }
}

impl Instruction {
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
                Ok(Instruction::Push(String::Opaque(data_slice.to_vec())))
            }
            Opcode::Program => {
                let strlen = program.read_size()?;
                let data_slice = program.read_bytes(strlen)?;
                Ok(Instruction::Program(ProgramItem::Bytecode(
                    data_slice.to_vec(),
                )))
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
            Opcode::Range => Ok(Instruction::Range),
            Opcode::And => Ok(Instruction::And),
            Opcode::Or => Ok(Instruction::Or),
            Opcode::Not => Ok(Instruction::Not),
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
            Opcode::Input => Ok(Instruction::Input),
            Opcode::Output => {
                let k = program.read_size()?;
                Ok(Instruction::Output(k))
            }
            Opcode::Contract => {
                let k = program.read_size()?;
                Ok(Instruction::Contract(k))
            }
            Opcode::Log => Ok(Instruction::Log),
            Opcode::Call => Ok(Instruction::Call),
            Opcode::Signtx => Ok(Instruction::Signtx),
            Opcode::Signid => Ok(Instruction::Signid),
            Opcode::Signtag => Ok(Instruction::Signtag),
        }
    }
}
