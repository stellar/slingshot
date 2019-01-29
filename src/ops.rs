use byteorder::{ByteOrder, LittleEndian};
use core::mem;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Instruction {
    Push(usize), // size of the string
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
    /// Returns a parsed instruction with a size that it occupies in the program string.
    /// E.g. a push instruction with 5-byte string occupies 1+4+5=10 bytes
    /// (4 for the LE32 length prefix).
    ///
    /// Return `None` if there is not enough bytes to parse an instruction.
    pub fn parse(program: &[u8]) -> Option<(Instruction, usize)> {
        if program.len() == 0 {
            return None;
        }

        let byte = program[0];
        let immdata = &program[1..];

        // Interpret the opcode. Unknown opcodes are extension opcodes.
        let opcode = match Opcode::from_u8(byte) {
            None => {
                return Some((Instruction::Ext(byte), 1));
            }
            Some(op) => op,
        };

        match opcode {
            Opcode::Push => {
                if immdata.len() < 4 {
                    return None;
                }
                let strlen = LittleEndian::read_u32(immdata) as usize;
                Some((Instruction::Push(strlen), 1 + 4 + strlen))
            }
            Opcode::Drop => Some((Instruction::Drop, 1)),
            Opcode::Dup => {
                if immdata.len() < 4 {
                    return None;
                }
                let idx = LittleEndian::read_u32(immdata) as usize;
                Some((Instruction::Dup(idx), 1 + 4))
            }
            Opcode::Roll => {
                if immdata.len() < 4 {
                    return None;
                }
                let idx = LittleEndian::read_u32(immdata) as usize;
                Some((Instruction::Roll(idx), 1 + 4))
            }
            Opcode::Const => Some((Instruction::Const, 1)),
            Opcode::Var => Some((Instruction::Var, 1)),
            Opcode::Alloc => Some((Instruction::Alloc, 1)),
            Opcode::Mintime => Some((Instruction::Mintime, 1)),
            Opcode::Maxtime => Some((Instruction::Maxtime, 1)),
            Opcode::Neg => Some((Instruction::Neg, 1)),
            Opcode::Add => Some((Instruction::Add, 1)),
            Opcode::Mul => Some((Instruction::Mul, 1)),
            Opcode::Eq => Some((Instruction::Eq, 1)),
            Opcode::Range => {
                if immdata.len() < 1 {
                    return None;
                }
                Some((Instruction::Range(immdata[0]), 1 + 1))
            }
            Opcode::And => Some((Instruction::And, 1)),
            Opcode::Or => Some((Instruction::Or, 1)),
            Opcode::Verify => Some((Instruction::Verify, 1)),
            Opcode::Blind => Some((Instruction::Blind, 1)),
            Opcode::Reblind => Some((Instruction::Reblind, 1)),
            Opcode::Unblind => Some((Instruction::Unblind, 1)),
            Opcode::Issue => Some((Instruction::Issue, 1)),
            Opcode::Borrow => Some((Instruction::Borrow, 1)),
            Opcode::Retire => Some((Instruction::Retire, 1)),
            Opcode::Qty => Some((Instruction::Qty, 1)),
            Opcode::Flavor => Some((Instruction::Flavor, 1)),
            Opcode::Cloak => {
                if immdata.len() < 8 {
                    return None;
                }
                let m = LittleEndian::read_u32(immdata) as usize;
                let n = LittleEndian::read_u32(&immdata[4..]) as usize;
                Some((Instruction::Cloak(m, n), 1 + 8))
            }
            Opcode::Import => Some((Instruction::Import, 1)),
            Opcode::Export => Some((Instruction::Export, 1)),
            Opcode::Input => Some((Instruction::Input, 1)),
            Opcode::Output => {
                if immdata.len() < 4 {
                    return None;
                }
                let k = LittleEndian::read_u32(immdata) as usize;
                Some((Instruction::Output(k), 1 + 4))
            }
            Opcode::Contract => {
                if immdata.len() < 4 {
                    return None;
                }
                let k = LittleEndian::read_u32(immdata) as usize;
                Some((Instruction::Contract(k), 1 + 4))
            }
            Opcode::Nonce => Some((Instruction::Nonce, 1)),
            Opcode::Log => Some((Instruction::Log, 1)),
            Opcode::Signtx => Some((Instruction::Signtx, 1)),
            Opcode::Call => Some((Instruction::Call, 1)),
            Opcode::Left => Some((Instruction::Left, 1)),
            Opcode::Right => Some((Instruction::Right, 1)),
            Opcode::Delegate => Some((Instruction::Delegate, 1)),
        }
    }
}
