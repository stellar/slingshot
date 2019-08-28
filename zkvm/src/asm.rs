//! API for human-readable encoding of programs.
//! Syntax:
//! * Words (such as `input`, `output` and `cloak`) are operation names.
//! * `0x...` is a hex-encoded `push` operation. 
//! * `[...]` is a sub-program.
//! * `{...}` is a contract.

use crate::program::Program;
use crate::ops::{Instruction};
use crate::contract::Contract;
use crate::encoding::SliceReader;

impl Program {
    /// Encodes program into a human-readable string.
    pub fn to_human_readable(&self) -> String {
        let mut s = String::new();
        self.encode_human_readable(&mut s);
        s
    }
    
    pub(crate) fn encode_human_readable(&self, buf: &mut String) {
        let progslice: &[Instruction] = &self;
        for i in 0..progslice.len() {
            let instr = progslice[i];
            let lookahead = &progslice[(i+1)..];
            instr.encode_human_readable(lookahead, buf);
        }
    }
}

impl Instruction {

    pub(crate) fn encode_human_readable(&self, lookahead: &[Instruction], buf: &mut String) {
        match self {
            Instruction::Push(data) => {
                // Use lookahead to guess a kind of data.
                // 1. `{contract} input`
                // 2. `[program] call`
                // 3. `[program] "sig" signid`
                // 4. `[program] "sig" signtag`
                // 5. else: encode as 0x<hex...>
                match lookahead.get(0) {
                    Some(Instruction::Input) => {
                        match SliceReader::parse(&data, |r| Contract::decode(r)) {
                            Ok(contract) => {
                                contract.encode_human_readable(buf);
                                return;
                            },
                            Err(_) => {}
                        }
                    }
                    _ => {}
                }
            }
            // Instruction::Program(subprog) => {
            //     write(Opcode::Program);
            //     encoding::write_u32(subprog.serialized_length() as u32, program);
            //     subprog.encode(program);
            // }
            // Instruction::Drop => write(Opcode::Drop),
            // Instruction::Dup(idx) => {
            //     write(Opcode::Dup);
            //     encoding::write_u32(*idx as u32, program);
            // }
            // Instruction::Roll(idx) => {
            //     write(Opcode::Roll);
            //     encoding::write_u32(*idx as u32, program);
            // }
            // Instruction::Const => write(Opcode::Const),
            // Instruction::Var => write(Opcode::Var),
            // Instruction::Alloc(_) => write(Opcode::Alloc),
            // Instruction::Mintime => write(Opcode::Mintime),
            // Instruction::Maxtime => write(Opcode::Maxtime),
            // Instruction::Expr => write(Opcode::Expr),
            // Instruction::Neg => write(Opcode::Neg),
            // Instruction::Add => write(Opcode::Add),
            // Instruction::Mul => write(Opcode::Mul),
            // Instruction::Eq => write(Opcode::Eq),
            // Instruction::Range => write(Opcode::Range),
            // Instruction::And => write(Opcode::And),
            // Instruction::Or => write(Opcode::Or),
            // Instruction::Not => write(Opcode::Not),
            // Instruction::Verify => write(Opcode::Verify),
            // Instruction::Unblind => write(Opcode::Unblind),
            // Instruction::Issue => write(Opcode::Issue),
            // Instruction::Borrow => write(Opcode::Borrow),
            // Instruction::Retire => write(Opcode::Retire),
            // Instruction::Cloak(m, n) => {
            //     write(Opcode::Cloak);
            //     encoding::write_u32(*m as u32, program);
            //     encoding::write_u32(*n as u32, program);
            // }
            // Instruction::Input => write(Opcode::Input),
            // Instruction::Output(k) => {
            //     write(Opcode::Output);
            //     encoding::write_u32(*k as u32, program);
            // }
            // Instruction::Contract(k) => {
            //     write(Opcode::Contract);
            //     encoding::write_u32(*k as u32, program);
            // }
            // Instruction::Log => write(Opcode::Log),
            // Instruction::Call => write(Opcode::Call),
            // Instruction::Signtx => write(Opcode::Signtx),
            // Instruction::Signid => write(Opcode::Signid),
            // Instruction::Signtag => write(Opcode::Signtag),
            // Instruction::Ext(x) => program.push(*x),
            _ => unimplemented!()
        };
    }
}

impl Contract {

    pub(crate) fn encode_human_readable(&self, buf: &mut String) {

    }
}