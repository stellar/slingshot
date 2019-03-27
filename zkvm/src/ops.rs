//! Definition of all instructions in ZkVM,
//! their codes and decoding/encoding utility functions.

use crate::encoding;
use crate::encoding::SliceReader;
use crate::errors::VMError;
use crate::scalar_witness::ScalarWitness;
use crate::types::Data;
use core::mem;
use spacesuit::BitRange;

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
    Not,
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
    Not = 0x11,
    Verify = 0x12,
    Unblind = 0x13,
    Issue = 0x14,
    Borrow = 0x15,
    Retire = 0x16,
    Cloak = 0x17,
    Import = 0x18,
    Export = 0x19,
    Input = 0x1a,
    Output = 0x1b,
    Contract = 0x1c,
    Nonce = 0x1d,
    Log = 0x1e,
    Signtx = 0x1f,
    Delegate = MAX_OPCODE,
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
            Instruction::Delegate => write(Opcode::Delegate),
            Instruction::Ext(x) => program.push(*x),
        };
    }
}
