//! API for human-readable encoding of programs.
//! Syntax:
//! * Words (such as `input`, `output` and `cloak`) are operation names.
//! * `0x...` is a hex-encoded `push` operation.
//! * `[...]` is a sub-program.
//! * `{...}` is a contract.

use std;
use std::fmt;

use crate::constraints::Commitment;
use crate::contract::{Anchor, Contract, PortableItem};
use crate::encoding::*;
use crate::ops::Instruction;
use crate::predicate::Predicate;
use crate::program::Program;
use crate::tx::{Tx, TxID, VerifiedTx};
use crate::types::{String, Value};

impl fmt::Debug for Program {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let progslice: &[Instruction] = &self;
        for i in 0..progslice.len() {
            let instr = &progslice[i];
            let lookahead = &progslice[(i + 1)..];
            instr.fmt_with_lookahead(f, lookahead)?;
        }
        Ok(())
    }
}

impl fmt::Debug for Instruction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.fmt_with_lookahead(f, &[])
    }
}

impl String {
    pub(crate) fn fmt_as_pushdata(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            String::Opaque(bytes) => {
                // short strings are usually human-readable, so let's try decode them as utf-8.
                if bytes.len() < 32 {
                    match std::string::String::from_utf8(bytes.clone()) {
                        Ok(s) => write!(f, "push:\"{}\"", s),
                        Err(_) => write!(f, "push:0x{}", hex::encode(&bytes)),
                    }
                } else {
                    write!(f, "push:0x{}", hex::encode(&bytes))
                }
            }
            String::Predicate(predicate) => write!(f, "push:{:?}", predicate),
            String::Commitment(commitment) => write!(f, "push:{:?}", commitment),
            String::Scalar(scalar_witness) => write!(f, "push:{:?}", scalar_witness),
            String::Output(contract) => write!(f, "push:{:?}", contract),
            String::U64(n) => write!(f, "push:{:?}", n),
            String::U32(n) => write!(f, "push:{:?}", n),
        }
    }
}

impl fmt::Debug for Contract {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Contract{{predicate:{:?},anchor:{:?},payload:{:?}}}",
            self.predicate, self.anchor, self.payload
        )
    }
}

impl Value {
    pub(crate) fn fmt_as_pushdata(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Value{{{:?},{:?}}}", self.qty, self.flv)
    }
}

impl Instruction {
    pub(crate) fn fmt_with_lookahead(
        &self,
        f: &mut fmt::Formatter<'_>,
        lookahead: &[Instruction],
    ) -> fmt::Result {
        match self {
            Instruction::Push(string) => {
                // Use lookahead to guess a kind of data.
                // 1. `{contract} input`
                // 2. else opaque: encode as 0x<hex...>
                // 3. else non-opaque: use Debug
                match (string, lookahead.get(0)) {
                    (String::Opaque(bytes), Some(&Instruction::Input)) => {
                        (&bytes[..])
                            .read_all(|r| Contract::decode(r))
                            .map(|c| String::Output(Box::new(c)).fmt_as_pushdata(f))
                            .unwrap_or_else(|_| string.fmt_as_pushdata(f)) // bad encoding -> keep opaque
                    }
                    (string, _) => string.fmt_as_pushdata(f),
                }
            }
            Instruction::Program(subprog) => write!(f, "[{:?}]", subprog),
            Instruction::Drop => write!(f, "drop"),
            Instruction::Dup(i) => write!(f, "dup:{}", i),
            Instruction::Roll(i) => write!(f, "roll:{}", i),
            Instruction::Scalar => write!(f, "scalar"),
            Instruction::Commit => write!(f, "commit"),
            Instruction::Alloc(_) => write!(f, "alloc"),
            Instruction::Mintime => write!(f, "mintime"),
            Instruction::Maxtime => write!(f, "maxtime"),
            Instruction::Expr => write!(f, "expr"),
            Instruction::Neg => write!(f, "neg"),
            Instruction::Add => write!(f, "add"),
            Instruction::Mul => write!(f, "mul"),
            Instruction::Eq => write!(f, "eq"),
            Instruction::Range => write!(f, "range"),
            Instruction::And => write!(f, "and"),
            Instruction::Or => write!(f, "or"),
            Instruction::Not => write!(f, "not"),
            Instruction::Verify => write!(f, "verify"),
            Instruction::Unblind => write!(f, "unblind"),
            Instruction::Issue => write!(f, "issue"),
            Instruction::Borrow => write!(f, "borrow"),
            Instruction::Retire => write!(f, "retire"),
            Instruction::Cloak(m, n) => write!(f, "cloak:{}:{}", m, n),
            Instruction::Fee => write!(f, "fee"),
            Instruction::Input => write!(f, "input"),
            Instruction::Output(k) => write!(f, "output:{}", k),
            Instruction::Contract(k) => write!(f, "contract:{}", k),
            Instruction::Log => write!(f, "log"),
            Instruction::Eval => write!(f, "eval"),
            Instruction::Call => write!(f, "call"),
            Instruction::Signtx => write!(f, "signtx"),
            Instruction::Signid => write!(f, "signid"),
            Instruction::Signtag => write!(f, "signtag"),
            Instruction::Ext(byte) => write!(f, "ext:{:x}", byte),
        }?;

        // If we know that there are more instructions in the program,
        // add a separating space character.
        if lookahead.len() > 0 {
            write!(f, " ")?
        }

        Ok(())
    }
}

impl fmt::Debug for Predicate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{}", hex::encode(&self.verification_key().as_bytes()))
    }
}

impl fmt::Debug for Anchor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{}", hex::encode(&self.0))
    }
}

impl fmt::Debug for PortableItem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PortableItem::String(s) => s.fmt_as_pushdata(f),
            PortableItem::Program(p) => write!(f, "[{:?}]", p),
            PortableItem::Value(v) => v.fmt_as_pushdata(f),
        }
    }
}

impl fmt::Debug for Commitment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Commitment::Closed(point) => write!(f, "0x{}", hex::encode(&point.as_bytes())),
            Commitment::Open(cw) => write!(f, "{:?}", cw),
        }
    }
}

impl fmt::Debug for TxID {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TxID({})", hex::encode(&self))
    }
}

impl fmt::Debug for Tx {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Tx(v{}, [{:x},{:x}]) {{\n",
            self.header.version, self.header.mintime_ms, self.header.maxtime_ms
        )?;
        match Program::parse(&self.program) {
            Ok(p) => write!(f, "    Program({:?})\n", p)?,
            Err(e) => write!(
                f,
                "    InvalidProgram({})->{:?}\n",
                hex::encode(&self.program),
                e
            )?,
        }
        write!(
            f,
            "    {:?}\n    R1CSProof({})\n",
            &self.signature,
            hex::encode(self.proof.to_bytes())
        )?;
        write!(f, "}}")
    }
}

impl fmt::Debug for VerifiedTx {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "VerifiedTx(v{}, [{:x},{:x}]) {{\n",
            self.header.version, self.header.mintime_ms, self.header.maxtime_ms
        )?;
        write!(f, "    {:?}\n", &self.id)?;
        write!(f, "    Fee rate: {:?}\n", &self.feerate)?;
        for entry in self.log.iter() {
            write!(f, "    {:?}\n", entry)?;
        }
        write!(f, "}}")
    }
}
