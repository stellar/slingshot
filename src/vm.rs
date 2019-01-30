use bulletproofs::r1cs;
use bulletproofs::r1cs::R1CSProof;
use bulletproofs::{BulletproofGens, PedersenGens};
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use spacesuit;
use std::iter::FromIterator;

use crate::encoding;
use crate::errors::VMError;
use crate::ops::Instruction;
use crate::point_ops::PointOp;
use crate::predicate::Predicate;
use crate::signature::*;
use crate::transcript::TranscriptProtocol;
use crate::txlog::{Entry, TxID, UTXO};
use crate::types::*;

/// Current tx version determines which extension opcodes are treated as noops (see VM.extension flag).
pub const CURRENT_VERSION: u64 = 1;

/// Prefix for the data type in the Output Structure
pub const DATA_TYPE: u8 = 0x00;

/// Prefix for the value type in the Output Structure
pub const VALUE_TYPE: u8 = 0x01;

/// Instance of a transaction that contains all necessary data to validate it.
pub struct Tx {
    /// Version of the transaction
    pub version: u64,

    /// Timestamp before which tx is invalid (sec)
    pub mintime: u64,

    /// Timestamp after which tx is invalid (sec)
    pub maxtime: u64,

    /// Program representing the transaction
    pub program: Vec<u8>,

    /// Aggregated signature of the txid
    pub signature: Signature,

    /// Constraint system proof for all the constraints
    pub proof: R1CSProof,
}

/// Represents a verified transaction: a txid and a list of state updates.
pub struct VerifiedTx {
    /// Version of the transaction
    pub version: u64,

    /// Timestamp before which tx is invalid (sec)
    pub mintime: u64,

    /// Timestamp after which tx is invalid (sec)
    pub maxtime: u64,

    /// Transaction ID
    pub id: TxID,

    // List of inputs, outputs and nonces to be inserted/deleted in the blockchain state.
    pub log: Vec<Entry>,
}

/// The ZkVM state used to validate a transaction.
pub struct VM<'tx, 'transcript, 'gens> {
    mintime: u64,
    maxtime: u64,
    program: &'tx [u8],

    // is true when tx version is in the future and
    // we allow treating unassigned opcodes as no-ops.
    extension: bool,

    // set to true by `input` and `nonce` instructions
    // when the txid is guaranteed to be unique.
    unique: bool,

    // stack of all items in the VM
    stack: Vec<Item<'tx>>,

    current_run: Run<'tx>,
    run_stack: Vec<Run<'tx>>,
    txlog: Vec<Entry>,
    signtx_keys: Vec<VerificationKey>,
    deferred_operations: Vec<PointOp>,
    variable_commitments: Vec<VariableCommitment>,
    cs: r1cs::Verifier<'transcript, 'gens>,
}

/// An state of running a single program string.
/// VM consists of a stack of such _Runs_.
struct Run<'tx> {
    program: &'tx [u8],
    offset: usize,
}

/// And indirect reference to a high-level variable within a constraint system.
/// Variable types store index of such commitments that allows replacing them.
enum VariableCommitment {
    /// Variable is not attached to the CS yet,
    /// so its commitment is replaceable via `reblind`.
    Detached(CompressedRistretto),

    /// Variable is attached to the CS yet and has an index in CS,
    /// so its commitment is no longer replaceable via `reblind`.
    Attached(CompressedRistretto, r1cs::Variable),
}

impl<'tx, 'transcript, 'gens> VM<'tx, 'transcript, 'gens> {
    /// Creates a new instance of ZkVM with the appropriate parameters
    pub fn verify_tx(tx: &Tx, bp_gens: &BulletproofGens) -> Result<VerifiedTx, VMError> {
        // Allow extension opcodes if tx version is above the currently supported one.
        let extension = tx.version > CURRENT_VERSION;

        // Construct a CS verifier to be used during ZkVM execution.
        let mut r1cs_transcript = Transcript::new(b"ZkVM.r1cs");
        let pc_gens = PedersenGens::default();
        let cs = r1cs::Verifier::new(&bp_gens, &pc_gens, &mut r1cs_transcript);

        let mut vm = VM {
            mintime: tx.mintime,
            maxtime: tx.maxtime,
            program: &tx.program,

            extension,
            unique: false,
            stack: Vec::new(),

            current_run: Run {
                program: &tx.program,
                offset: 0,
            },
            run_stack: Vec::new(),
            txlog: vec![Entry::Header(tx.version, tx.mintime, tx.maxtime)],
            signtx_keys: Vec::new(),
            deferred_operations: Vec::new(),
            variable_commitments: Vec::new(),
            cs,
        };

        vm.run()?;

        let txid = TxID::from_log(&vm.txlog[..]);

        // Verify the signatures over txid
        let mut signtx_transcript = Transcript::new(b"ZkVM.signtx");
        signtx_transcript.commit_bytes(b"txid", &txid.0);
        let signtx_point_op = tx
            .signature
            .verify_aggregated(&mut signtx_transcript, &vm.signtx_keys[..]);
        vm.deferred_operations.push(signtx_point_op);

        // Verify all deferred crypto operations.
        PointOp::verify_batch(&vm.deferred_operations[..])?;

        // Verify the R1CS proof
        vm.cs
            .verify(&tx.proof)
            .map_err(|_| VMError::InvalidR1CSProof)?;

        Ok(VerifiedTx {
            version: tx.version,
            mintime: tx.mintime,
            maxtime: tx.maxtime,
            id: txid,
            log: vm.txlog,
        })
    }

    /// Runs through the entire program and nested programs until completion.
    fn run(&mut self) -> Result<(), VMError> {
        loop {
            if !self.step()? {
                break;
            }
        }

        if self.stack.len() > 0 {
            return Err(VMError::StackNotClean);
        }

        if self.unique == false {
            return Err(VMError::NotUniqueTxid);
        }

        Ok(())
    }

    /// Returns `true` if we need to continue execution,
    /// `false` if the VM execution is completed.
    fn finish_run(&mut self) -> bool {
        // Do we have more programs to run?
        if let Some(run) = self.run_stack.pop() {
            // Continue with the previously remembered program
            self.current_run = run;
            return true;
        }

        // Finish the execution
        return false;
    }

    /// Returns a flag indicating whether to continue the execution
    fn step(&mut self) -> Result<bool, VMError> {
        // Have we reached the end of the current program?
        if self.current_run.offset == self.current_run.program.len() {
            return Ok(self.finish_run());
        }

        // Read the next instruction and advance the program state.
        let (instr, instr_size) =
            Instruction::parse(&self.current_run.program[self.current_run.offset..])
                .ok_or(VMError::FormatError)?;

        // Immediately update the offset for the next instructions
        self.current_run.offset += instr_size;

        match instr {
            Instruction::Push(len) => self.pushdata(len)?,
            Instruction::Drop => self.drop()?,
            Instruction::Dup(i) => self.dup(i)?,
            Instruction::Roll(i) => self.roll(i)?,
            Instruction::Const => unimplemented!(),
            Instruction::Var => unimplemented!(),
            Instruction::Alloc => unimplemented!(),
            Instruction::Mintime => unimplemented!(),
            Instruction::Maxtime => unimplemented!(),
            Instruction::Neg => unimplemented!(),
            Instruction::Add => unimplemented!(),
            Instruction::Mul => unimplemented!(),
            Instruction::Eq => unimplemented!(),
            Instruction::Range(_) => unimplemented!(),
            Instruction::And => unimplemented!(),
            Instruction::Or => unimplemented!(),
            Instruction::Verify => unimplemented!(),
            Instruction::Blind => unimplemented!(),
            Instruction::Reblind => unimplemented!(),
            Instruction::Unblind => unimplemented!(),
            Instruction::Issue => self.issue()?,
            Instruction::Borrow => unimplemented!(),
            Instruction::Retire => self.retire()?,
            Instruction::Qty => unimplemented!(),
            Instruction::Flavor => unimplemented!(),
            Instruction::Cloak(m, n) => self.cloak(m, n)?,
            Instruction::Import => unimplemented!(),
            Instruction::Export => unimplemented!(),
            Instruction::Input => self.input()?,
            Instruction::Output(k) => self.output(k)?,
            Instruction::Contract(k) => self.contract(k)?,
            Instruction::Nonce => self.nonce()?,
            Instruction::Log => unimplemented!(),
            Instruction::Signtx => self.signtx()?,
            Instruction::Call => unimplemented!(),
            Instruction::Left => unimplemented!(),
            Instruction::Right => unimplemented!(),
            Instruction::Delegate => unimplemented!(),
            Instruction::Ext(opcode) => self.ext(opcode)?,
        }

        return Ok(true);
    }

    fn pushdata(&mut self, len: usize) -> Result<(), VMError> {
        let range = self.current_run.offset - len..self.current_run.offset;
        self.stack.push(Item::Data(Data {
            bytes: &self.current_run.program[range],
        }));
        Ok(())
    }

    fn drop(&mut self) -> Result<(), VMError> {
        match self.pop_item()? {
            Item::Data(_) => Ok(()),
            Item::Variable(_) => Ok(()),
            Item::Expression(_) => Ok(()),
            Item::Constraint(_) => Ok(()),
            _ => Err(VMError::TypeNotCopyable),
        }
    }

    fn dup(&mut self, i: usize) -> Result<(), VMError> {
        if i >= self.stack.len() {
            return Err(VMError::StackUnderflow);
        }
        let item_idx = self.stack.len() - i - 1;
        let item = match &self.stack[item_idx] {
            Item::Data(x) => Item::Data(*x),
            Item::Variable(x) => Item::Variable(x.clone()),
            Item::Expression(x) => Item::Expression(x.clone()),
            Item::Constraint(x) => Item::Constraint(x.clone()),
            _ => return Err(VMError::TypeNotCopyable),
        };
        self.push_item(item);
        Ok(())
    }

    fn roll(&mut self, i: usize) -> Result<(), VMError> {
        if i >= self.stack.len() {
            return Err(VMError::StackUnderflow);
        }
        let item = self.stack.remove(self.stack.len() - i - 1);
        self.push_item(item);
        Ok(())
    }

    fn nonce(&mut self) -> Result<(), VMError> {
        let predicate = Predicate(self.pop_item()?.to_data()?.to_point()?);
        let contract = Contract {
            predicate,
            payload: Vec::new(),
        };
        self.txlog.push(Entry::Nonce(predicate, self.maxtime));
        self.push_item(contract);
        self.unique = true;
        Ok(())
    }

    fn issue(&mut self) -> Result<(), VMError> {
        let predicate = Predicate(self.pop_item()?.to_data()?.to_point()?);
        let flv = self.pop_item()?.to_variable()?;
        let qty = self.pop_item()?.to_variable()?;

        let (flv_point, _) = self.attach_variable(flv);
        let (qty_point, _) = self.attach_variable(qty);

        let value = Value { qty, flv };

        let flv_scalar = Value::issue_flavor(&predicate);
        // flv_point == flavor·B    ->   0 == -flv_point + flv_scalar·B
        self.deferred_operations.push(PointOp {
            primary: Some(flv_scalar),
            secondary: None,
            arbitrary: vec![(-Scalar::one(), flv_point)],
        });

        let qty_expr = self.variable_to_expression(qty);
        self.add_range_proof(64, qty_expr)?;

        self.txlog.push(Entry::Issue(qty_point, flv_point));

        let contract = Contract {
            predicate,
            payload: vec![PortableItem::Value(value)],
        };

        self.push_item(contract);
        Ok(())
    }

    fn retire(&mut self) -> Result<(), VMError> {
        let value = self.pop_item()?.to_value()?;
        let qty = self.get_variable_commitment(value.qty);
        let flv = self.get_variable_commitment(value.flv);
        self.txlog.push(Entry::Retire(qty, flv));
        Ok(())
    }

    /// _input_ **input** → _contract_
    fn input(&mut self) -> Result<(), VMError> {
        let serialized_input = self.pop_item()?.to_data()?;
        let (contract, _, utxo) = self.decode_input(serialized_input.bytes)?;
        self.push_item(contract);
        self.txlog.push(Entry::Input(utxo));
        self.unique = true;
        Ok(())
    }

    /// _items... predicate_ **output:_k_** → ø
    fn output(&mut self, k: usize) -> Result<(), VMError> {
        let predicate = Predicate(self.pop_item()?.to_data()?.to_point()?);

        if k > self.stack.len() {
            return Err(VMError::StackUnderflow);
        }
        let payload = self
            .stack
            .drain(self.stack.len() - k..)
            .map(|item| item.to_portable())
            .collect::<Result<Vec<_>, _>>()?;

        let output = self.encode_output(Contract { predicate, payload });
        self.txlog.push(Entry::Output(output));
        Ok(())
    }

    fn contract(&mut self, k: usize) -> Result<(), VMError> {
        let predicate = Predicate(self.pop_item()?.to_data()?.to_point()?);

        if k > self.stack.len() {
            return Err(VMError::StackUnderflow);
        }
        let payload = self
            .stack
            .drain(self.stack.len() - k..)
            .map(|item| item.to_portable())
            .collect::<Result<Vec<_>, _>>()?;

        self.push_item(Contract { predicate, payload });
        Ok(())
    }

    fn cloak(&mut self, m: usize, n: usize) -> Result<(), VMError> {
        // _widevalues commitments_ **cloak:_m_:_n_** → _values_
        // Merges and splits `m` [wide values](#wide-value-type) into `n` [values](#values).

        if m > self.stack.len() || n > self.stack.len() {
            return Err(VMError::StackUnderflow);
        }
        // Now that individual m and n are bounded by the (not even close to overflow) stack size,
        // we can add them together.
        // This does not overflow if the stack size is below 2^30 items.
        assert!(self.stack.len() < (1usize << 30));
        if (m + 2 * n) > self.stack.len() {
            return Err(VMError::StackUnderflow);
        }

        let mut output_values: Vec<Value> = Vec::with_capacity(2 * n);

        let mut cloak_ins: Vec<spacesuit::AllocatedValue> = Vec::with_capacity(m);
        let mut cloak_outs: Vec<spacesuit::AllocatedValue> = Vec::with_capacity(2 * n);

        // Make cloak outputs and output values using (qty,flv) commitments
        for _ in 0..n {
            let flv = self.pop_item()?.to_data()?.to_point()?;
            let qty = self.pop_item()?.to_data()?.to_point()?;

            let qty = self.make_variable(qty);
            let flv = self.make_variable(flv);

            let value = Value { qty, flv };
            let cloak_value = self.value_to_cloak_value(&value);

            // insert in the same order as they are on stack (the deepest item will be at index 0)
            output_values.insert(0, value);
            cloak_outs.insert(0, cloak_value);
        }

        // Make cloak inputs out of wide values
        for _ in 0..m {
            let item = self.pop_item()?;
            let walue = self.item_to_wide_value(item)?;

            let cloak_value = self.wide_value_to_cloak_value(&walue);

            // insert in the same order as they are on stack (the deepest item will be at index 0)
            cloak_ins.insert(0, cloak_value);
        }

        spacesuit::cloak(&mut self.cs, cloak_ins, cloak_outs).map_err(|_| VMError::FormatError)?;

        // Push in the same order.
        for v in output_values.into_iter() {
            self.push_item(v);
        }

        Ok(())
    }

    // _contract_ **signtx** → _results..._
    fn signtx(&mut self) -> Result<(), VMError> {
        let contract = self.pop_item()?.to_contract()?;
        self.signtx_keys.push(VerificationKey(contract.predicate.0));
        for item in contract.payload.into_iter() {
            self.push_item(item);
        }
        Ok(())
    }

    fn ext(&mut self, _: u8) -> Result<(), VMError> {
        if self.extension {
            // if extensions are allowed by tx version,
            // unknown opcodes are treated as no-ops.
            Ok(())
        } else {
            Err(VMError::ExtensionsNotAllowed)
        }
    }
}

// Utility methods

impl<'tx, 'transcript, 'gens> VM<'tx, 'transcript, 'gens> {
    fn pop_item(&mut self) -> Result<Item<'tx>, VMError> {
        self.stack.pop().ok_or(VMError::StackUnderflow)
    }

    fn push_item<I>(&mut self, item: I)
    where
        I: Into<Item<'tx>>,
    {
        self.stack.push(item.into())
    }

    fn make_variable(&mut self, commitment: CompressedRistretto) -> Variable {
        let index = self.variable_commitments.len();
        self.variable_commitments
            .push(VariableCommitment::Detached(commitment));
        Variable { index }
    }

    fn get_variable_commitment(&self, var: Variable) -> CompressedRistretto {
        // This subscript never fails because the variable is created only via `make_variable`.
        match self.variable_commitments[var.index] {
            VariableCommitment::Detached(p) => p,
            VariableCommitment::Attached(p, _) => p,
        }
    }

    fn attach_variable(&mut self, var: Variable) -> (CompressedRistretto, r1cs::Variable) {
        // This subscript never fails because the variable is created only via `make_variable`.
        match self.variable_commitments[var.index] {
            VariableCommitment::Detached(p) => {
                let r1cs_var = self.cs.commit(p);
                self.variable_commitments[var.index] = VariableCommitment::Attached(p, r1cs_var);
                (p, r1cs_var)
            }
            VariableCommitment::Attached(p, r1cs_var) => (p, r1cs_var),
        }
    }

    fn value_to_cloak_value(&mut self, value: &Value) -> spacesuit::AllocatedValue {
        spacesuit::AllocatedValue {
            q: self.attach_variable(value.qty).1,
            f: self.attach_variable(value.flv).1,
            // TBD: maintain assignments inside Value types in order to use ZkVM to compute the R1CS proof
            assignment: None,
        }
    }

    fn wide_value_to_cloak_value(&mut self, walue: &WideValue) -> spacesuit::AllocatedValue {
        spacesuit::AllocatedValue {
            q: walue.r1cs_qty,
            f: walue.r1cs_flv,
            // TBD: maintain assignments inside WideValue types in order to use ZkVM to compute the R1CS proof
            assignment: None,
        }
    }

    fn item_to_wide_value(&mut self, item: Item<'tx>) -> Result<WideValue, VMError> {
        match item {
            Item::Value(value) => Ok(WideValue {
                r1cs_qty: self.attach_variable(value.qty).1,
                r1cs_flv: self.attach_variable(value.flv).1,
            }),
            Item::WideValue(w) => Ok(w),
            _ => Err(VMError::TypeNotWideValue),
        }
    }

    fn item_to_expression(&mut self, item: Item<'tx>) -> Result<Expression, VMError> {
        match item {
            Item::Variable(v) => Ok(self.variable_to_expression(v)),
            Item::Expression(expr) => Ok(expr),
            _ => Err(VMError::TypeNotExpression),
        }
    }

    fn variable_to_expression(&mut self, var: Variable) -> Expression {
        let (_, r1cs_var) = self.attach_variable(var);
        Expression {
            terms: vec![(r1cs_var, Scalar::one())],
        }
    }

    /// Parses the input and returns the instantiated contract, txid and UTXO identifier.
    fn decode_input(&mut self, input: &'tx [u8]) -> Result<(Contract<'tx>, TxID, UTXO), VMError> {
        //        Input  =  PreviousTxID || PreviousOutput
        // PreviousTxID  =  <32 bytes>

        let (txid, output) = encoding::read_u8x32(input)?;
        let txid = TxID(txid);
        let contract = self.decode_output(output)?;
        let utxo = UTXO::from_output(output, &txid);
        Ok((contract, txid, utxo))
    }

    /// Parses the output and returns an instantiated contract.
    fn decode_output(&mut self, output: &'tx [u8]) -> Result<(Contract<'tx>), VMError> {
        //    Output  =  Predicate  ||  LE32(k)  ||  Item[0]  || ... ||  Item[k-1]
        // Predicate  =  <32 bytes>
        //      Item  =  enum { Data, Value }
        //      Data  =  0x00  ||  LE32(len)  ||  <bytes>
        //     Value  =  0x01  ||  <32 bytes> ||  <32 bytes>

        let (predicate, payload) = encoding::read_point(output)?;
        let predicate = Predicate(predicate);

        let (k, mut items) = encoding::read_usize(payload)?;

        // sanity check: avoid allocating unreasonably more memory
        // just because an untrusted length prefix says so.
        if k > items.len() {
            return Err(VMError::FormatError);
        }

        let mut payload: Vec<PortableItem<'tx>> = Vec::with_capacity(k);
        for _ in 0..k {
            let (item_type, rest) = encoding::read_u8(items)?;
            let item = match item_type {
                DATA_TYPE => {
                    let (len, rest) = encoding::read_usize(rest)?;
                    let (bytes, rest) = encoding::read_bytes(len, rest)?;
                    items = rest;
                    PortableItem::Data(Data { bytes })
                }
                VALUE_TYPE => {
                    let (qty, rest) = encoding::read_point(rest)?;
                    let (flv, rest) = encoding::read_point(rest)?;

                    let qty = self.make_variable(qty);
                    let flv = self.make_variable(flv);

                    items = rest;
                    PortableItem::Value(Value { qty, flv })
                }
                _ => return Err(VMError::FormatError),
            };
            payload.push(item);
        }

        Ok(Contract { predicate, payload })
    }

    fn encode_output(&mut self, contract: Contract<'tx>) -> Vec<u8> {
        let mut output = Vec::with_capacity(contract.output_size());
        encoding::write_point(&contract.predicate.0, &mut output);
        encoding::write_u32(contract.payload.len() as u32, &mut output);

        for item in contract.payload.iter() {
            match item {
                PortableItem::Data(d) => {
                    encoding::write_u8(DATA_TYPE, &mut output);
                    encoding::write_u32(d.bytes.len() as u32, &mut output);
                    encoding::write_bytes(d.bytes, &mut output);
                }
                PortableItem::Value(v) => {
                    encoding::write_u8(VALUE_TYPE, &mut output);
                    let qty = self.get_variable_commitment(v.qty);
                    let flv = self.get_variable_commitment(v.flv);
                    encoding::write_point(&qty, &mut output);
                    encoding::write_point(&flv, &mut output);
                }
            }
        }

        output
    }

    fn add_range_proof(&mut self, bitrange: usize, expr: Expression) -> Result<(), VMError> {
        spacesuit::range_proof(
            &mut self.cs,
            r1cs::LinearCombination::from_iter(expr.terms),
            // TBD: maintain the assignment for the expression and provide it here
            None,
            bitrange,
        )
        .map_err(|_| VMError::R1CSInconsistency)
    }
}

impl<'tx> Contract<'tx> {
    fn output_size(&self) -> usize {
        let mut size = 32 + 4;
        for item in self.payload.iter() {
            match item {
                PortableItem::Data(d) => size += 1 + 4 + d.bytes.len(),
                PortableItem::Value(_) => size += 1 + 64,
            }
        }
        size
    }
}
