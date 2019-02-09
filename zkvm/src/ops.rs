use core::borrow::Borrow;
use core::mem;

use crate::encoding;
use crate::encoding::Subslice;
use crate::errors::VMError;
use crate::types::Data;

#[derive(Clone, Debug)]
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

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
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
    Neg = 0x09,
    Add = 0x0a,
    Mul = 0x0b,
    Eq = 0x0c,
    Range = 0x0d,
    And = 0x0e,
    Or = 0x0f,
    Verify = 0x10,
    Blind = 0x11,
    Reblind = 0x12,
    Unblind = 0x13,
    Issue = 0x14,
    Borrow = 0x15,
    Retire = 0x16,
    Qty = 0x17,
    Flavor = 0x18,
    Cloak = 0x19,
    Import = 0x1a,
    Export = 0x1b,
    Input = 0x1c,
    Output = 0x1d,
    Contract = 0x1e,
    Nonce = 0x1f,
    Log = 0x20,
    Signtx = 0x21,
    Call = 0x22,
    Left = 0x23,
    Right = 0x24,
    Delegate = MAX_OPCODE,
}

const MAX_OPCODE: u8 = 0x25;

impl Opcode {
    pub fn to_u8(self) -> u8 {
        unsafe { mem::transmute(self) }
    }

    pub fn from_u8(code: u8) -> Option<Opcode> {
        if code > MAX_OPCODE {
            None
        } else {
            unsafe { mem::transmute(code) }
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
    pub fn parse(program: &mut Subslice) -> Result<Self, VMError> {
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
        match self {
            Instruction::Push(data) => {
                program.push(Opcode::Push.to_u8());
                data.encode(program);
            }
            Instruction::Drop => program.push(Opcode::Drop.to_u8()),
            Instruction::Dup(idx) => {
                program.push(Opcode::Dup.to_u8());
                encoding::write_u32(*idx as u32, program);
            }
            Instruction::Roll(idx) => {
                program.push(Opcode::Roll.to_u8());
                encoding::write_u32(*idx as u32, program);
            }
            Instruction::Const => program.push(Opcode::Const.to_u8()),
            Instruction::Var => program.push(Opcode::Var.to_u8()),
            Instruction::Alloc => program.push(Opcode::Alloc.to_u8()),
            Instruction::Mintime => program.push(Opcode::Mintime.to_u8()),
            Instruction::Maxtime => program.push(Opcode::Maxtime.to_u8()),
            Instruction::Neg => program.push(Opcode::Neg.to_u8()),
            Instruction::Add => program.push(Opcode::Add.to_u8()),
            Instruction::Mul => program.push(Opcode::Mul.to_u8()),
            Instruction::Eq => program.push(Opcode::Eq.to_u8()),
            Instruction::Range(bit_width) => {
                program.push(Opcode::Range.to_u8());
                program.push(*bit_width);
            }
            Instruction::And => program.push(Opcode::And.to_u8()),
            Instruction::Or => program.push(Opcode::Or.to_u8()),
            Instruction::Verify => program.push(Opcode::Verify.to_u8()),
            Instruction::Blind => program.push(Opcode::Blind.to_u8()),
            Instruction::Reblind => program.push(Opcode::Reblind.to_u8()),
            Instruction::Unblind => program.push(Opcode::Unblind.to_u8()),
            Instruction::Issue => program.push(Opcode::Issue.to_u8()),
            Instruction::Borrow => program.push(Opcode::Borrow.to_u8()),
            Instruction::Retire => program.push(Opcode::Retire.to_u8()),
            Instruction::Qty => program.push(Opcode::Qty.to_u8()),
            Instruction::Flavor => program.push(Opcode::Flavor.to_u8()),
            Instruction::Cloak(m, n) => {
                program.push(Opcode::Cloak.to_u8());
                encoding::write_u32(*m as u32, program);
                encoding::write_u32(*n as u32, program);
            }
            Instruction::Import => program.push(Opcode::Import.to_u8()),
            Instruction::Export => program.push(Opcode::Export.to_u8()),
            Instruction::Input => program.push(Opcode::Input.to_u8()),
            Instruction::Output(k) => {
                program.push(Opcode::Output.to_u8());
                encoding::write_u32(*k as u32, program);
            }
            Instruction::Contract(k) => {
                program.push(Opcode::Contract.to_u8());
                encoding::write_u32(*k as u32, program);
            }
            Instruction::Nonce => program.push(Opcode::Nonce.to_u8()),
            Instruction::Log => program.push(Opcode::Log.to_u8()),
            Instruction::Signtx => program.push(Opcode::Signtx.to_u8()),
            Instruction::Call => program.push(Opcode::Call.to_u8()),
            Instruction::Left => program.push(Opcode::Left.to_u8()),
            Instruction::Right => program.push(Opcode::Right.to_u8()),
            Instruction::Delegate => program.push(Opcode::Delegate.to_u8()),
            Instruction::Ext(x) => program.push(*x),
        };
    }

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
