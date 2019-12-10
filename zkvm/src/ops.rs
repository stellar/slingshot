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
    /// **push:n:x** → _data_
    ///
    /// Pushes a binary string `x` containing `n` bytes. 
    /// Immediate data `n` is encoded as LE-32
    /// followed by `x` encoded as a sequence of `n` bytes.
    Push(String),

    /// **program:n:x** → _program_
    ///
    /// Pushes a program string `x` containing `n` bytes. 
    /// Immediate data `n` is encoded as LE-32
    /// followed by `x` encoded as a sequence of `n` bytes.
    Program(ProgramItem),

    /// _x_ **drop** → ø
    ///
    /// Drops top item from the stack.
    /// Fails if the item is not a copyable type.
    Drop,

    /// _x(k) … x(0)_ **dup:_k_** → _x(k) ... x(0) x(k)_
    ///
    /// Copies k’th item from the top of the stack.
    /// Immediate data `k` is encoded as LE-32.
    ///
    /// Fails if `x(k)` is not a _copyable type_.
    Dup(usize),  // index of the item

    /// _x(k) x(k-1) ... x(0)_ **roll:_k_** → _x(k-1) ... x(0) x(k)_
    ///
    /// Looks past `k` items from the top, and moves the next item to the top of the stack.
    /// Immediate data `k` is encoded as LE32.
    ///
    /// Note: `roll:0` is a no-op, `roll:1` swaps the top two items.
    Roll(usize), // index of the item

    /// _a_ **const** → _expr_
    /// 
    /// 1. Pops a _scalar_ `a` from the stack.
    /// 2. Creates an _expression_ `expr` with weight `a` assigned to an R1CS constant `1`.
    /// 3. Pushes `expr` to the stack.
    /// 
    /// Fails if `a` is not a valid _scalar_.
    Const,

    /// _P_ **var** → _v_
    /// 
    /// 1. Pops a _point_ `P` from the stack.
    /// 2. Creates a _variable_ `v` from a _Pedersen commitment_ `P`.
    /// 3. Pushes `v` to the stack.
    /// 
    /// Fails if `P` is not a valid _point_.
    Var,

    /// **alloc** → _expr_
    /// 
    /// 1. Allocates a low-level variable in the constraint system and wraps it in the _expression_ with weight 1.
    /// 2. Pushes the resulting expression to the stack.
    /// 
    /// This is different from [`var`](Instruction::Var): the variable created by `alloc` is _not_
    /// represented by an individual Pedersen commitment and therefore can be chosen freely when the transaction is constructed.
    Alloc(Option<ScalarWitness>),

    /// **mintime** → _expr_
    /// 
    /// Pushes an _expression_ `expr` corresponding to the _minimum time bound_ of the transaction.
    /// 
    /// The one-term expression represents time bound as a weight on the R1CS constant `1` (see [`const`](Instruction::Const)).
    Mintime,
    
    /// **maxtime** → _expr_
    /// 
    /// Pushes an _expression_ `expr` corresponding to the _maximum time bound_ of the transaction.
    /// 
    /// The one-term expression represents time bound as a weight on the R1CS constant `1` (see [`const`](Instruction::Const)).
    Maxtime,

    /// _var_ **expr** → _ex_
    /// 
    /// 1. Pops a _variable_ `var`.
    /// 2. Allocates a high-level variable in the constraint system using its Pedersen commitment.
    /// 3. Pushes a single-term _expression_ with weight=1 to the stack: `expr = { (1, var) }`.
    /// 
    /// Fails if `var` is not a _variable type_.
    Expr,

    /// _ex1_ **neg** → _ex2_
    /// 
    /// 1. Pops an _expression_ `ex1`.
    /// 2. Negates the weights in the `ex1` producing new expression `ex2`.
    /// 3. Pushes `ex2` to the stack.
    /// 
    /// Fails if `ex1` is not an _expression type_.
    Neg,

    /// _ex1 ex2_ **add** → ex3_
    /// 
    /// 1. Pops two _expressions_ `ex2`, then `ex1`.
    /// 2. If both expressions are _constant expressions_:
    ///     1. Creates a new _constant expression_ `ex3` with the weight equal to the sum of weights in `ex1` and `ex2`.
    /// 3. Otherwise, creates a new expression `ex3` by concatenating terms in `ex1` and `ex2`.
    /// 4. Pushes `ex3` to the stack.
    /// 
    /// Fails if `ex1` and `ex2` are not both _expression types_.
    Add,

    /// _ex1 ex2_ **mul** → _ex3_
    /// 
    /// Multiplies two _expressions_ producing another _expression_ representing the result of multiplication.
    /// 
    /// This performs a _guaranteed optimization_: if one of the expressions `ex1` or `ex2` contains
    /// only one term and this term is for the variable representing the R1CS constant `1`
    /// (in other words, the statement is a cleartext constant),
    /// then the other expression is multiplied by that constant in-place without allocating a multiplier in the _constraint system_.
    /// 
    /// This optimization is _guaranteed_ because it affects the state of the constraint system:
    /// not performing it would make the existing proofs invalid.
    /// 
    /// 1. Pops two _expressions_ `ex2`, then `ex1`.
    /// 2. If either `ex1` or `ex2` is a _constant expression_:
    ///     1. The other expression is multiplied in place by the scalar from that expression.
    ///     2. The resulting expression is pushed to the stack.
    /// 3. Otherwise:
    ///     1. Creates a multiplier in the constraint system.
    ///     2. Constrains the left wire to `ex1`, and the right wire to `ex2`.
    ///     3. Creates an _expression_ `ex3` with the output wire in its single term.
    ///     4. Pushes `ex3` to the stack.
    /// 
    /// Fails if `ex1` and `ex2` are not both _expression types_.
    /// 
    /// Note: if both `ex1` and `ex2` are _constant expressions_,
    /// the result does not depend on which one treated as a constant,
    /// and the resulting expression is also a constant expression.
    Mul,

    /// _ex1 ex2_ **eq** → _constraint_
    /// 
    /// 1. Pops two _expressions_ `ex2`, then `ex1`.
    /// 2. If both `ex1` or `ex2` are _constant expressions_:
    ///     1. Creates a _cleartext constraint_ with a boolean `true` if the weights are equal, `false` otherwise.
    /// 3. Otherwise:
    ///     1. Creates a _constraint_ that represents statement `ex1 - ex2 = 0`.
    /// 4. Pushes the constraint to the stack.
    /// 
    /// Fails if `ex1` and `ex2` are not both _expression types_.
    Eq,

    /// _expr_ **range** → _expr_
    /// 
    /// 1. Pops an _expression_ `expr`.
    /// 2. Adds an 64-bit range proof for `expr` to the constraint system. (See [Cloak protocol](https://github.com/stellar/slingshot/blob/main/spacesuit/spec.md) for the range proof definition).
    /// 3. Pushes `expr` back to the stack.
    /// 
    /// Fails if `expr` is not an _expression type_.
    Range,

    /// _c1 c2_ **and** → _c3_
    /// 
    /// 1. Pops _constraints_ `c2`, then `c1`.
    /// 2. If either `c1` or `c2` is a _cleartext constraint_:
    ///     1. If the cleartext constraint is `false`, returns it; otherwise returns the other constraint.
    /// 3. Otherwise:
    ///     1. Creates a _conjunction constraint_ `c3` containing `c1` and `c2`.
    /// 3. Pushes `c3` to the stack.
    /// 
    /// No changes to the _constraint system_ are made until [`verify`](Instruction::Verify) is executed.
    /// 
    /// Fails if `c1` and `c2` are not _constraints_.
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
pub enum Opcode {
    /// A code for [Instruction::Push].
    Push = 0x00,
    /// A code for [Instruction::Program].
    Program = 0x01,
    /// A code for [Instruction::Drop].
    Drop = 0x02,
    /// A code for [Instruction::Dup].
    Dup = 0x03,
    /// A code for [Instruction::Roll].
    Roll = 0x04,
    /// A code for [Instruction::Const].
    Const = 0x05,
    /// A code for [Instruction::Var]
    Var = 0x06,
    /// A code for [Instruction::Alloc]
    Alloc = 0x07,
    /// A code for [Instruction::Mintime]
    Mintime = 0x08,
    /// A code for [Instruction::Maxtime]
    Maxtime = 0x09,
    /// A code for [Instruction::Expr]
    Expr = 0x0a,
    /// A code for [Instruction::Neg]
    Neg = 0x0b,
    /// A code for [Instruction::Add]
    Add = 0x0c,
    /// A code for [Instruction::Mul]
    Mul = 0x0d,
    /// A code for [Instruction::Eq]
    Eq = 0x0e,
    /// A code for [Instruction::Range]
    Range = 0x0f,
    /// A code for [Instruction::And]
    And = 0x10,
    /// A code for [Instruction::Or]
    Or = 0x11,
    /// A code for [Instruction::Not]
    Not = 0x12,
    /// A code for [Instruction::Verify]
    Verify = 0x13,
    /// A code for [Instruction::Unblind]
    Unblind = 0x14,
    /// A code for [Instruction::Issue]
    Issue = 0x15,
    /// A code for [Instruction::Borrow]
    Borrow = 0x16,
    /// A code for [Instruction::Retire]
    Retire = 0x17,
    /// A code for [Instruction::Cloak]
    Cloak = 0x18,
    /// A code for [Instruction::Input]
    Input = 0x19,
    /// A code for [Instruction::Output]
    Output = 0x1a,
    /// A code for [Instruction::Contract]
    Contract = 0x1b,
    /// A code for [Instruction::Log]
    Log = 0x1c,
    /// A code for [Instruction::Call]
    Call = 0x1d,
    /// A code for [Instruction::Signtx]
    Signtx = 0x1e,
    /// A code for [Instruction::Signid]
    Signid = 0x1f,
    /// A code for [Instruction::Signtag]
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
