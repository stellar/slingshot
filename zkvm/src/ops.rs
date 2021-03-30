//! Definition of all instructions in ZkVM,
//! their codes and decoding/encoding utility functions.
use core::mem;
use serde::{Deserialize, Serialize};

use crate::encoding::*;
use crate::errors::VMError;
use crate::program::ProgramItem;
use crate::scalar_witness::ScalarWitness;
use crate::types::String;

/// A decoded instruction.
#[derive(Clone, PartialEq, Deserialize, Serialize)]
pub enum Instruction {
    /// **push:_n_:_x_** → _data_
    ///
    /// Pushes a _string_ `x` containing `n` bytes.
    /// Immediate data `n` is encoded as _LE32_
    /// followed by `x` encoded as a sequence of `n` bytes.
    Push(String),

    /// **program:_n_:_x_** → _program_
    ///
    /// Pushes a _program_ `x` containing `n` bytes.
    /// Immediate data `n` is encoded as _LE32_
    /// followed by `x`, as a sequence of `n` bytes.
    Program(ProgramItem),

    /// _x_ **drop** → ø
    ///
    /// Drops `x` from the stack.
    ///
    /// Fails if `x` is not a _droppable type_.
    Drop,

    /// _x(k) … x(0)_ **dup:_k_** → _x(k) ... x(0) x(k)_
    ///
    /// Copies k’th item from the top of the stack.
    /// Immediate data `k` is encoded as _LE32_.
    ///
    /// Fails if `x(k)` is not a _copyable type_.
    Dup(usize),

    /// _x(k) x(k-1) ... x(0)_ **roll:_k_** → _x(k-1) ... x(0) x(k)_
    ///
    /// Looks past `k` items from the top, and moves the next item to the top of the stack.
    /// Immediate data `k` is encoded as _LE32_.
    ///
    /// Note: `roll:0` is a no-op, `roll:1` swaps the top two items.
    Roll(usize),

    /// _a_ **scalar** → _expr_
    ///
    /// 1. Pops a _scalar_ `a` from the stack.
    /// 2. Creates an _expression_ `expr` with weight `a` assigned to an R1CS constant `1`.
    /// 3. Pushes `expr` to the stack.
    ///
    /// Fails if `a` is not a valid _scalar_.
    Scalar,

    /// _P_ **commit** → _v_
    ///
    /// 1. Pops a _point_ `P` from the stack.
    /// 2. Creates a _variable_ `v` from a _Pedersen commitment_ `P`.
    /// 3. Pushes `v` to the stack.
    ///
    /// Fails if `P` is not a valid _point_.
    Commit,

    /// **alloc** → _expr_
    ///
    /// 1. Allocates a low-level variable in the _constraint system_ and wraps it in the _expression_ with weight 1.
    /// 2. Pushes the resulting expression to the stack.
    ///
    /// This is different from `commit`: the variable created by `alloc` is _not_ represented by an individual Pedersen commitment and therefore can be chosen freely when the transaction is constructed.
    Alloc(Option<ScalarWitness>),

    /// **mintime** → _expr_
    ///
    /// Pushes an _expression_ `expr` corresponding to the _minimum time bound_ of the transaction.
    ///
    /// The one-term expression represents time bound as a weight on the R1CS constant `1` (see `scalar`).
    Mintime,

    /// **maxtime** → _expr_
    ///
    /// Pushes an _expression_ `expr` corresponding to the _maximum time bound_ of the transaction.
    ///
    /// The one-term expression represents time bound as a weight on the R1CS constant `1` (see `scalar`).
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
    /// 2. Adds an 64-bit range proof for `expr` to the _constraint system_ (see _Cloak protocol_ for the range proof definition).
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
    /// No changes to the _constraint system_ are made until `verify` is executed.
    ///
    /// Fails if `c1` and `c2` are not _constraints_.
    And,

    /// _constraint1 constraint2_ **or** → _constraint3_
    ///
    /// 1. Pops _constraints_ `c2`, then `c1`.
    /// 2. If either `c1` or `c2` is a _cleartext constraint_:
    ///     1. If the cleartext constraint is `true`, returns it; otherwise returns the other constraint.
    /// 3. Otherwise:
    ///     1. Creates a _disjunction constraint_ `c3` containing `c1` and `c2`.
    /// 3. Pushes `c3` to the stack.
    ///
    /// No changes to the _constraint system_ are made until `verify` is executed.
    ///
    /// Fails if `c1` and `c2` are not _constraints_.
    Or,

    /// _constr1_ **not** → _constr2_
    ///
    /// 1. Pops _constraint_ `c1`.
    /// 2. If `c1` is a _cleartext constraint_, returns its negation.
    /// 3. Otherwise:
    ///     1. Create two constraints:
    ///        ```ascii
    ///        x * y = 0
    ///        x * w = 1-y
    ///        ```
    ///        where `w` is a free variable and `x` is the evaluation of constraint `c1`.
    ///     2. Wrap the output `y` in a constraint `c2`.
    ///     3. Push `c2` to the stack.
    ///
    /// This implements the boolean `not` trick from _Setty, Vu, Panpalia, Braun, Ali, Blumberg, Walfish (2012)_ and implemented in _libsnark_.
    Not,

    /// _constr_ **verify** → ø
    ///
    /// 1. Pops _constraint_ `constr`.
    /// 2. If `constr` is a _cleartext constraint_:
    ///     1. If it is `true`, returns immediately.
    ///     2. If it is `false`, fails execution.
    /// 3. Otherwise, transforms the constraint `constr` recursively using the following rules:
    ///     1. Replace conjunction of two _linear constraints_ `a` and `b` with a linear constraint `c` by combining both constraints with a random challenge `z`:
    ///         ```ascii
    ///         z = transcript.challenge_scalar(b"ZkVM.verify.and-challenge");
    ///         c = a + z·b
    ///         ```
    ///     2. Replace disjunction of two _linear constraints_ `a` and `b` by constrainting an output `o` of a newly allocated multiplier `{r,l,o}` to zero, while adding constraints `r == a` and `l == b` to the constraint system.
    ///         ```ascii
    ///         r == a # added to CS
    ///         l == b # added to CS
    ///         o == 0 # replaces OR(a,b)
    ///         ```
    ///     3. Conjunctions and disjunctions of non-linear constraints are transformed via rules (1) and (2) using depth-first recursion.
    /// 3. The resulting single linear constraint is added to the constraint system.
    ///
    /// Fails if `constr` is not a _constraint_.
    Verify,

    /// _V v_ **unblind** → _V_
    ///
    /// 1. Pops _scalar_ `v`.
    /// 2. Pops _point_ `V`.
    /// 3. Verifies the _unblinding proof_ for the commitment `V` and scalar `v`, _deferring all point operations_).
    /// 4. Pushes _point_ `V`.
    ///
    /// Fails if:
    /// * `v` is not a valid _scalar_, or
    /// * `V` is not a valid _point_, or
    Unblind,

    /// _qty flv metadata pred_ **issue** → _contract_
    ///
    /// 1. Pops _point_ `pred`.
    /// 2. Pops _string_ `metadata`.
    /// 3. Pops _variable_ `flv` and commits it to the constraint system.
    /// 4. Pops _variable_ `qty` and commits it to the constraint system.
    /// 5. Creates a _value_ with variables `qty` and `flv` for quantity and flavor, respectively.
    /// 6. Computes the _flavor_ scalar defined by the _predicate_ `pred` using the following _transcript-based_ protocol:
    ///     ```ascii
    ///     T = Transcript("ZkVM.issue")
    ///     T.append("predicate", pred)
    ///     T.append("metadata", metadata)
    ///     flavor = T.challenge_scalar("flavor")
    ///     ```
    /// 6. Checks that the `flv` has unblinded commitment to `flavor`
    ///    by _deferring the point operation_:
    ///     ```ascii
    ///     flv == flavor·B
    ///     ```
    /// 7. Adds a 64-bit range proof for the `qty` to the _constraint system_
    ///    (see _Cloak protocol_ for the range proof definition).
    /// 8. Adds an _issue entry_ to the _transaction log_.
    /// 9. Creates a _contract_ with the value as the only _payload_,
    ///    protected by the predicate `pred`, consuming _VM’s last anchor_
    ///    and replacing it with this contract’s _ID_.
    ///
    /// The value is now issued into the contract that must be unlocked
    /// using one of the contract instructions: `signtx`, `signid`, `signtag` or `call`.
    ///
    /// Fails if:
    /// * `pred` is not a valid _point_,
    /// * `flv` or `qty` are not _variable types_,
    /// * VM’s _last anchor_ is not set.
    Issue,

    /// _qty flv_ **borrow** → _–V +V_
    ///
    /// 1. Pops _variable_ `flv` and commits it to the constraint system.
    /// 2. Pops _variable_ `qty` and commits it to the constraint system.
    /// 3. Creates a _value_ `+V` with variables `qty` and `flv` for quantity and flavor, respectively.
    /// 4. Adds a 64-bit range proof for `qty` variable to the _constraint system_ (see _Cloak protocol_ for the range proof definition).
    /// 5. Creates _wide value_ `–V`, allocating a low-level variable `qty2` for the negated quantity and reusing the flavor variable `flv`.
    /// 6. Adds a constraint `qty2 == -qty` to the constraint system.
    /// 7. Pushes `–V`, then `+V` to the stack.
    ///
    /// The wide value `–V` is not a _portable type_, and can only be consumed by a `cloak` instruction
    /// (where it is merged with appropriate positive quantity of the same flavor).
    ///
    /// Fails if `qty` and `flv` are not _variable types_.
    Borrow,

    /// _value_ **retire** → ø
    ///
    /// 1. Pops a _value_ from the stack.
    /// 2. Adds a _retirement_ entry to the _transaction log_.
    ///
    /// Fails if the value is not a _non-negative value type_.
    Retire,

    /// _widevalues commitments_ **cloak:_m_:_n_** → _values_
    ///
    /// Merges and splits `m` _wide values_ into `n` _values_.
    ///
    /// 1. Pops `2·n` _points_ as pairs of _flavor_ and _quantity_ for each output value, flavor is popped first in each pair.
    /// 2. Pops `m` _wide values_ as input values.
    /// 3. Creates constraints and 64-bit range proofs for quantities per _Cloak protocol_.
    /// 4. Pushes `n` _values_ to the stack, placing them in the **reverse** order as their corresponding commitments:
    ///    ```ascii
    ///    A B C → cloak → C B A
    ///    ```
    ///
    /// Immediate data `m` and `n` are encoded as two _LE32_s.
    Cloak(usize, usize),

    /// _qty_ **fee** → _widevalue_
    ///
    /// 1. Pops an 4-byte _string_ `qty` from the stack and decodes it as _LE32_ integer.
    /// 2. Checks that `qty`  and accumulated fee is less or equal to `2^24`.
    /// 3. Pushes _wide value_ `–V`, with quantity variable constrained to `-qty` and with flavor constrained to 0.
    ///    Both variables are allocated from a single multiplier.
    /// 4. Adds a _fee entry_ to the _transaction log_ with the quantity `qty`.
    ///
    /// Fails if the resulting amount of fees is exceeding `2^24`.
    Fee,

    /// _prevoutput_ **input** → _contract_
    ///
    /// 1. Pops a _string_ `prevoutput` representing the _unspent output structure_ from the stack.
    /// 2. Constructs a _contract_ based on `prevoutput` and pushes it to the stack.
    /// 3. Adds _input entry_ to the _transaction log_.
    /// 4. Sets the _VM’s last anchor_ to the ratcheted _contract ID_:
    ///     ```ascii
    ///     T = Transcript("ZkVM.ratchet-anchor")
    ///     T.append("old", contract_id)
    ///     new_anchor = T.challenge_bytes("new")
    ///     ```
    ///
    /// Fails if the `prevoutput` is not a _string_ with exact encoding of an _output structure_.
    Input,

    /// _items... predicate_ **output:_k_** → ø
    ///
    /// 1. Pops `predicate` from the stack.
    /// 2. Pops `k` _portable items_ from the stack.
    /// 3. Creates a contract with the `k` items as a payload, the predicate `pred`, and anchor set to the _VM’s last anchor_.
    /// 4. Adds an _output entry_ to the _transaction log_.
    /// 5. Updates the _VM’s last anchor_ with the _contract ID_ of the new contract.
    ///
    /// Immediate data `k` is encoded as _LE32_.
    ///
    /// Fails if:
    /// * VM’s _last anchor_ is not set,
    /// * payload items are not _portable_.
    Output(usize),

    /// _items... pred_ **contract:_k_** → _contract_
    ///
    /// 1. Pops _predicate_ `pred` from the stack.
    /// 2. Pops `k` _portable items_ from the stack.
    /// 3. Creates a contract with the `k` items as a payload, the predicate `pred`, and anchor set to the _VM’s last anchor_.
    /// 4. Pushes the contract onto the stack.
    /// 5. Update the _VM’s last anchor_ with the _contract ID_ of the new contract.
    ///
    /// Immediate data `k` is encoded as _LE32_.
    ///
    /// Fails if:
    /// * VM’s _last anchor_ is not set,
    /// * payload items are not _portable_.
    Contract(usize),

    /// _data_ **log** → ø
    ///
    /// 1. Pops `data` from the stack.
    /// 2. Adds _data entry_ with it to the _transaction log_.
    ///
    /// Fails if `data` is not a _string_.
    Log,

    /// _prog_ **eval** → _results..._
    ///
    /// 1. Pops _program_ `prog`.
    /// 2. Set the `prog` as current.
    ///
    /// Fails if `prog` is not a _program_.
    Eval,

    /// _contract(P) proof prog_ **call** → _results..._
    ///
    /// 1. Pops _program_ `prog`, the _call proof_ `proof`, and a _contract_ `contract`.
    /// 2. Reads the _predicate_ `P` from the contract.
    /// 3. Reads the signing key `X`, list of neighbors `neighbors`, and their positions `positions` from the _call proof_ `proof`.
    /// 4. Uses the _program_ `prog`, `neighbors`, and `positions` to compute the Merkle root `M`.
    /// 5. Forms a statement to verify a relation between `P`, `M`, and `X`:
    ///     ```ascii
    ///     0 == -P + X + h1(X, M)·G
    ///     ```
    /// 6. Adds the statement to the _deferred point operations_.
    /// 7. Places the _payload_ on the stack (last item on top).
    /// 8. Set the `prog` as current.
    ///
    /// Fails if:
    /// 1. `prog` is not a _program_,
    /// 2. or `proof` is not a _string_,
    /// 3. or `contract` is not a _contract_.
    Call,

    /// _contract(predicate, payload)_ **signtx** → _items..._
    ///
    /// 1. Pops the _contract_ from the stack.
    /// 2. Adds the contract’s `predicate` as a _verification key_
    ///    to the list of deferred keys for _transaction signature_
    ///    check at the end of the VM execution.
    /// 3. Places the `payload` on the stack (last item on top), discarding the contract.
    ///
    /// Note: the instruction never fails as the only check (signature verification)
    /// is deferred until the end of VM execution.
    Signtx,

    /// _contract(predicate, payload) prog sig_ **signid** → _items..._
    ///
    /// 1. Pop _string_ `sig`, _program_ `prog` and the _contract_ from the stack.
    /// 2. Read the `predicate` from the contract.
    /// 3. Place the `payload` on the stack (last item on top), discarding the contract.
    /// 4. Instantiate the _transcript_:
    ///     ```ascii
    ///     T = Transcript("ZkVM.signid")
    ///     ```
    /// 5. Commit the _contract ID_ `contract.id` to the transcript:
    ///     ```ascii
    ///     T.append("contract", contract_id)
    ///     ```
    /// 6. Commit the program `prog` to the transcript:
    ///     ```ascii
    ///     T.append("prog", prog)
    ///     ```
    /// 7. Extract nonce commitment `R` and scalar `s` from a 64-byte string `sig`:
    ///     ```ascii
    ///     R = sig[ 0..32]
    ///     s = sig[32..64]
    ///     ```
    /// 8. Perform the _signature protocol_ using the transcript `T`, public key `P = predicate` and the values `R` and `s`:
    ///     ```ascii
    ///     (s = dlog(R) + e·dlog(P))
    ///     s·B  ==  R + c·P
    ///     ```
    /// 9. Add the statement to the list of _deferred point operations_.
    /// 10. Set the `prog` as current.
    ///
    /// Fails if:
    /// 1. `sig` is not a 64-byte long _string_,
    /// 2. or `prog` is not a _program_,
    /// 3. or `contract` is not a _contract_.
    Signid,

    /// _contract(predicate, payload) prog sig_ **signtag** → _items... tag_
    ///
    /// 1. Pop _string_ `sig`, _program_ `prog` and the _contract_ from the stack.
    /// 2. Read the `predicate` from the contract.
    /// 3. Place the `payload` on the stack (last item on top), discarding the contract.
    /// 4. Verifies that the top item is a _string_, and reads it as a `tag`. The item remains on the stack.
    /// 5. Instantiate the _transcript_:
    ///     ```ascii
    ///     T = Transcript("ZkVM.signtag")
    ///     ```
    /// 6. Commit the `tag` to the transcript:
    ///     ```ascii
    ///     T.append("tag", tag)
    ///     ```
    /// 7. Commit the program `prog` to the transcript:
    ///     ```ascii
    ///     T.append("prog", prog)
    ///     ```
    /// 8. Extract nonce commitment `R` and scalar `s` from a 64-byte data `sig`:
    ///     ```ascii
    ///     R = sig[ 0..32]
    ///     s = sig[32..64]
    ///     ```
    /// 9. Perform the _signature protocol_ using the transcript `T`, public key `P = predicate` and the values `R` and `s`:
    ///     ```ascii
    ///     (s = dlog(R) + e·dlog(P))
    ///     s·B  ==  R + c·P
    ///     ```
    /// 10. Add the statement to the list of _deferred point operations_.
    /// 11. Set the `prog` as current.
    ///
    /// Fails if:
    /// 1. `sig` is not a 64-byte long _string_,
    /// 2. or `prog` is not a _program_,
    /// 3. or `contract` is not a _contract_,
    /// 4. or last item in the `payload` (`tag`) is not a _string_.
    Signtag,

    /// Unassigned opcode.
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
    /// A code for [Instruction::Scalar].
    Scalar = 0x05,
    /// A code for [Instruction::Commit]
    Commit = 0x06,
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
    /// A code for [Instruction::Fee]
    Fee = 0x19,
    /// A code for [Instruction::Input]
    Input = 0x1a,
    /// A code for [Instruction::Output]
    Output = 0x1b,
    /// A code for [Instruction::Contract]
    Contract = 0x1c,
    /// A code for [Instruction::Log]
    Log = 0x1d,
    /// A code for [Instruction::Eval]
    Eval = 0x1e,
    /// A code for [Instruction::Call]
    Call = 0x1f,
    /// A code for [Instruction::Signtx]
    Signtx = 0x20,
    /// A code for [Instruction::Signid]
    Signid = 0x21,
    /// A code for [Instruction::Signtag]
    Signtag = MAX_OPCODE,
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

impl Encodable for Instruction {
    /// Appends the bytecode representation of an Instruction
    /// to the program.
    fn encode(&self, w: &mut impl Writer) -> Result<(), WriteError> {
        let mut write = |op: Opcode| w.write_u8(b"op", op.to_u8());
        match self {
            Instruction::Push(data) => {
                write(Opcode::Push)?;
                w.write_u32(b"n", data.encoded_size() as u32)?;
                data.encode(w)?;
            }
            Instruction::Program(subprog) => {
                write(Opcode::Program)?;
                w.write_u32(b"n", subprog.encoded_size() as u32)?;
                subprog.encode(w)?;
            }
            Instruction::Drop => write(Opcode::Drop)?,
            Instruction::Dup(idx) => {
                write(Opcode::Dup)?;
                w.write_u32(b"k", *idx as u32)?;
            }
            Instruction::Roll(idx) => {
                write(Opcode::Roll)?;
                w.write_u32(b"k", *idx as u32)?;
            }
            Instruction::Scalar => write(Opcode::Scalar)?,
            Instruction::Commit => write(Opcode::Commit)?,
            Instruction::Alloc(_) => write(Opcode::Alloc)?,
            Instruction::Mintime => write(Opcode::Mintime)?,
            Instruction::Maxtime => write(Opcode::Maxtime)?,
            Instruction::Expr => write(Opcode::Expr)?,
            Instruction::Neg => write(Opcode::Neg)?,
            Instruction::Add => write(Opcode::Add)?,
            Instruction::Mul => write(Opcode::Mul)?,
            Instruction::Eq => write(Opcode::Eq)?,
            Instruction::Range => write(Opcode::Range)?,
            Instruction::And => write(Opcode::And)?,
            Instruction::Or => write(Opcode::Or)?,
            Instruction::Not => write(Opcode::Not)?,
            Instruction::Verify => write(Opcode::Verify)?,
            Instruction::Unblind => write(Opcode::Unblind)?,
            Instruction::Issue => write(Opcode::Issue)?,
            Instruction::Borrow => write(Opcode::Borrow)?,
            Instruction::Retire => write(Opcode::Retire)?,
            Instruction::Cloak(m, n) => {
                write(Opcode::Cloak)?;
                w.write_u32(b"m", *m as u32)?;
                w.write_u32(b"n", *n as u32)?;
            }
            Instruction::Fee => write(Opcode::Fee)?,
            Instruction::Input => write(Opcode::Input)?,
            Instruction::Output(k) => {
                write(Opcode::Output)?;
                w.write_u32(b"k", *k as u32)?;
            }
            Instruction::Contract(k) => {
                write(Opcode::Contract)?;
                w.write_u32(b"k", *k as u32)?;
            }
            Instruction::Log => write(Opcode::Log)?,
            Instruction::Eval => write(Opcode::Eval)?,
            Instruction::Call => write(Opcode::Call)?,
            Instruction::Signtx => write(Opcode::Signtx)?,
            Instruction::Signid => write(Opcode::Signid)?,
            Instruction::Signtag => write(Opcode::Signtag)?,
            Instruction::Ext(x) => w.write_u8(b"ext", *x)?,
        };
        Ok(())
    }
}

impl ExactSizeEncodable for Instruction {
    fn encoded_size(&self) -> usize {
        match self {
            Instruction::Push(data) => 1 + 4 + data.encoded_size(),
            Instruction::Program(progitem) => 1 + 4 + progitem.encoded_size(),
            Instruction::Dup(_) => 1 + 4,
            Instruction::Roll(_) => 1 + 4,
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
    /// Return `VMError::InvalidFormat` if there are not enough bytes to parse an
    /// instruction.
    pub fn parse(program: &mut impl Reader) -> Result<Self, VMError> {
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
                let data = program.read_bytes(strlen)?;
                Ok(Instruction::Push(String::Opaque(data)))
            }
            Opcode::Program => {
                let strlen = program.read_size()?;
                let data = program.read_bytes(strlen)?;
                Ok(Instruction::Program(ProgramItem::Bytecode(data)))
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
            Opcode::Scalar => Ok(Instruction::Scalar),
            Opcode::Commit => Ok(Instruction::Commit),
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
            Opcode::Fee => Ok(Instruction::Fee),
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
            Opcode::Eval => Ok(Instruction::Eval),
            Opcode::Call => Ok(Instruction::Call),
            Opcode::Signtx => Ok(Instruction::Signtx),
            Opcode::Signid => Ok(Instruction::Signid),
            Opcode::Signtag => Ok(Instruction::Signtag),
        }
    }
}
