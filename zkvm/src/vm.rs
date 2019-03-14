use bulletproofs::r1cs;
use bulletproofs::r1cs::R1CSProof;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use serde::de::Visitor;
use serde::{self, Deserialize, Deserializer, Serialize, Serializer};
use spacesuit;
use spacesuit::BitRange;
use std::iter::FromIterator;
use std::mem;

use crate::constraints::{Commitment, Constraint, Expression, Variable};
use crate::contract::{Anchor, Contract, Output, PortableItem};
use crate::encoding;
use crate::encoding::SliceReader;
use crate::errors::VMError;
use crate::ops::Instruction;
use crate::point_ops::PointOp;
use crate::predicate::Predicate;
use crate::scalar_witness::ScalarWitness;
use crate::signature::*;
use crate::txlog::{Entry, TxID, TxLog};
use crate::types::*;

/// Current tx version determines which extension opcodes are treated as noops (see VM.extension flag).
pub const CURRENT_VERSION: u64 = 1;

/// Header metadata for the transaction
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct TxHeader {
    /// Version of the transaction
    pub version: u64,

    /// Timestamp before which tx is invalid (sec)
    pub mintime: u64,

    /// Timestamp after which tx is invalid (sec)
    pub maxtime: u64,
}

impl TxHeader {
    fn serialized_size(&self) -> usize {
        8 * 3
    }

    fn encode(&self, buf: &mut Vec<u8>) {
        encoding::write_u64(self.version, buf);
        encoding::write_u64(self.mintime, buf);
        encoding::write_u64(self.maxtime, buf);
    }

    fn decode<'a>(reader: &mut SliceReader<'a>) -> Result<Self, VMError> {
        Ok(TxHeader {
            version: reader.read_u64()?,
            mintime: reader.read_u64()?,
            maxtime: reader.read_u64()?,
        })
    }
}

/// Instance of a transaction that contains all necessary data to validate it.
pub struct Tx {
    /// Header metadata
    pub header: TxHeader,

    /// Program representing the transaction
    pub program: Vec<u8>,

    /// Aggregated signature of the txid
    pub signature: Signature,

    /// Constraint system proof for all the constraints
    pub proof: R1CSProof,
}

impl Tx {
    fn encode(&self, buf: &mut Vec<u8>) {
        self.header.encode(buf);
        encoding::write_size(self.program.len(), buf);
        buf.extend(&self.program);
        buf.extend_from_slice(&self.signature.to_bytes());
        buf.extend_from_slice(&self.proof.to_bytes());
    }

    fn decode<'a>(r: &mut SliceReader<'a>) -> Result<Tx, VMError> {
        let header = TxHeader::decode(r)?;
        let prog_len = r.read_size()?;
        let program = r.read_bytes(prog_len)?.to_vec();

        let signature = Signature::from_bytes(r.read_u8x64()?)?;
        let proof =
            R1CSProof::from_bytes(r.read_bytes(r.len())?).map_err(|_| VMError::FormatError)?;
        Ok(Tx {
            header,
            program,
            signature,
            proof,
        })
    }

    /// Serializes the tx into a byte array.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.serialized_size());
        self.encode(&mut buf);
        buf
    }

    /// Returns the size in bytes required to serialize the `Tx`.
    pub fn serialized_size(&self) -> usize {
        // header is 8 bytes * 3 fields = 24 bytes
        // program length is 4 bytes
        // program is self.program.len() bytes
        // signature is 64 bytes
        // proof is 14*32 + the ipp bytes
        self.header.serialized_size() + 4 + self.program.len() + 64 + self.proof.serialized_size()
    }

    /// Deserializes the tx from a byte slice.
    ///
    /// Returns an error if the byte slice cannot be parsed into a `Tx`.
    pub fn from_bytes(slice: &[u8]) -> Result<Tx, VMError> {
        SliceReader::parse(slice, |r| Self::decode(r))
    }
}

impl Serialize for Tx {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&self.to_bytes()[..])
    }
}
impl<'de> Deserialize<'de> for Tx {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct TxVisitor;

        impl<'de> Visitor<'de> for TxVisitor {
            type Value = Tx;

            fn expecting(&self, formatter: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                formatter.write_str("a valid Tx")
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Tx, E>
            where
                E: serde::de::Error,
            {
                Tx::from_bytes(v).map_err(serde::de::Error::custom)
            }
        }

        deserializer.deserialize_bytes(TxVisitor)
    }
}

/// Represents a verified transaction: a txid and a list of state updates.
pub struct VerifiedTx {
    /// Transaction header
    pub header: TxHeader,

    /// Transaction ID
    pub id: TxID,

    /// Transaction log: a list of changes to the blockchain state (UTXOs to delete/insert, etc.)
    pub log: TxLog,
}

pub(crate) struct VM<'d, CS, D>
where
    CS: r1cs::ConstraintSystem,
    D: Delegate<CS>,
{
    mintime: u64,
    maxtime: u64,

    // is true when tx version is in the future and
    // we allow treating unassigned opcodes as no-ops.
    extension: bool,

    // updated by nonce/input/issue/contract/output instructions
    last_anchor: Option<Anchor>,

    // stack of all items in the VM
    stack: Vec<Item>,

    delegate: &'d mut D,

    current_run: D::RunType,
    run_stack: Vec<D::RunType>,
    txlog: TxLog,
}

pub(crate) trait Delegate<CS: r1cs::ConstraintSystem> {
    type RunType;

    /// Adds a Commitment to the underlying constraint system, producing a high-level variable
    fn commit_variable(
        &mut self,
        com: &Commitment,
    ) -> Result<(CompressedRistretto, r1cs::Variable), VMError>;

    /// Adds a point operation to the list of deferred operation for later batch verification
    fn verify_point_op<F>(&mut self, point_op_fn: F) -> Result<(), VMError>
    where
        F: FnOnce() -> PointOp;

    /// Adds a key represented by Predicate to either verify or
    /// sign a transaction
    fn process_tx_signature(&mut self, pred: Predicate) -> Result<(), VMError>;

    /// Returns the delegate's underlying constraint system
    fn cs(&mut self) -> &mut CS;

    /// Returns the next instruction.
    /// Returns Err() upon decoding/format error.
    /// Returns Ok(Some()) if there is another instruction available.
    /// Returns Ok(None) if there is no more instructions to execute.
    fn next_instruction(&mut self, run: &mut Self::RunType)
        -> Result<Option<Instruction>, VMError>;

    fn new_run(&self, prog: Data) -> Result<Self::RunType, VMError>;
}

impl<'d, CS, D> VM<'d, CS, D>
where
    CS: r1cs::ConstraintSystem,
    D: Delegate<CS>,
{
    /// Instantiates a new VM instance.
    pub fn new(header: TxHeader, run: D::RunType, delegate: &'d mut D) -> Self {
        VM {
            mintime: header.mintime,
            maxtime: header.maxtime,
            extension: header.version > CURRENT_VERSION,
            last_anchor: None,
            delegate,
            stack: Vec::new(),
            current_run: run,
            run_stack: Vec::new(),
            txlog: vec![Entry::Header(header)],
        }
    }

    /// Runs through the entire program and nested programs until completion.
    pub fn run(mut self) -> Result<(TxID, TxLog), VMError> {
        loop {
            if !self.step()? {
                break;
            }
        }

        if self.stack.len() > 0 {
            return Err(VMError::StackNotClean);
        }

        if self.last_anchor.is_none() {
            return Err(VMError::AnchorMissing);
        }

        let txid = TxID::from_log(&self.txlog[..]);

        Ok((txid, self.txlog))
    }

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
        if let Some(instr) = self.delegate.next_instruction(&mut self.current_run)? {
            // Attempt to read the next instruction and advance the program state
            match instr {
                // the data is just a slice, so the clone would copy the slice struct,
                // not the actual buffer of bytes.
                Instruction::Push(data) => self.pushdata(data)?,
                Instruction::Drop => self.drop()?,
                Instruction::Dup(i) => self.dup(i)?,
                Instruction::Roll(i) => self.roll(i)?,
                Instruction::Const => self.r#const()?,
                Instruction::Var => self.var()?,
                Instruction::Alloc(sw) => self.alloc(sw)?,
                Instruction::Mintime => self.mintime()?,
                Instruction::Maxtime => self.maxtime()?,
                Instruction::Expr => self.expr()?,
                Instruction::Neg => self.neg()?,
                Instruction::Add => self.add()?,
                Instruction::Mul => self.mul()?,
                Instruction::Eq => self.eq()?,
                Instruction::Range(i) => self.range(i)?,
                Instruction::And => self.and()?,
                Instruction::Or => self.or()?,
                Instruction::Verify => self.verify()?,
                Instruction::Unblind => self.unblind()?,
                Instruction::Issue => self.issue()?,
                Instruction::Borrow => self.borrow()?,
                Instruction::Retire => self.retire()?,
                Instruction::Cloak(m, n) => self.cloak(m, n)?,
                Instruction::Import => unimplemented!(),
                Instruction::Export => unimplemented!(),
                Instruction::Input => self.input()?,
                Instruction::Output(k) => self.output(k)?,
                Instruction::Contract(k) => self.contract(k)?,
                Instruction::Nonce => self.nonce()?,
                Instruction::Log => self.log()?,
                Instruction::Signtx => self.signtx()?,
                Instruction::Call => self.call()?,
                Instruction::Left => self.left()?,
                Instruction::Right => self.right()?,
                Instruction::Delegate => self.delegate()?,
                Instruction::Ext(opcode) => self.ext(opcode)?,
            }
            return Ok(true);
        } else {
            // Reached the end of the current program
            return Ok(self.finish_run());
        }
    }

    fn pushdata(&mut self, data: Data) -> Result<(), VMError> {
        self.push_item(data);
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
            Item::Data(x) => Item::Data(x.clone()),
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

    fn expr(&mut self) -> Result<(), VMError> {
        let var = self.pop_item()?.to_variable()?;
        let expr = self.variable_to_expression(var)?;
        self.push_item(expr);
        Ok(())
    }

    fn neg(&mut self) -> Result<(), VMError> {
        let expr = self.pop_item()?.to_expression()?;
        self.push_item(-expr);
        Ok(())
    }

    fn add(&mut self) -> Result<(), VMError> {
        let expr2 = self.pop_item()?.to_expression()?;
        let expr1 = self.pop_item()?.to_expression()?;
        let expr3 = expr1 + expr2;
        self.push_item(expr3);
        Ok(())
    }

    fn mul(&mut self) -> Result<(), VMError> {
        let expr2 = self.pop_item()?.to_expression()?;
        let expr1 = self.pop_item()?.to_expression()?;
        let expr3 = expr1.multiply(expr2, self.delegate.cs());
        self.push_item(expr3);
        Ok(())
    }

    fn eq(&mut self) -> Result<(), VMError> {
        let expr2 = self.pop_item()?.to_expression()?;
        let expr1 = self.pop_item()?.to_expression()?;
        let constraint = Constraint::Eq(expr1, expr2);
        self.push_item(constraint);
        Ok(())
    }

    fn range(&mut self, i: BitRange) -> Result<(), VMError> {
        let expr = self.pop_item()?.to_expression()?;
        self.add_range_proof(i, expr.clone())?;
        self.push_item(expr);
        Ok(())
    }

    fn and(&mut self) -> Result<(), VMError> {
        let c2 = self.pop_item()?.to_constraint()?;
        let c1 = self.pop_item()?.to_constraint()?;
        let c3 = Constraint::And(Box::new(c1), Box::new(c2));
        self.push_item(c3);
        Ok(())
    }

    fn or(&mut self) -> Result<(), VMError> {
        let c2 = self.pop_item()?.to_constraint()?;
        let c1 = self.pop_item()?.to_constraint()?;
        let c3 = Constraint::Or(Box::new(c1), Box::new(c2));
        self.push_item(c3);
        Ok(())
    }

    fn verify(&mut self) -> Result<(), VMError> {
        let constraint = self.pop_item()?.to_constraint()?;
        constraint.verify(self.delegate.cs())?;
        Ok(())
    }

    fn unblind(&mut self) -> Result<(), VMError> {
        // Pop expression `expr`
        let expr = self.pop_item()?.to_expression()?;

        // Pop commitment `V`
        let v_commitment = self.pop_item()?.to_data()?.to_commitment()?;
        let v_point = v_commitment.to_point();

        // Pop scalar `v`
        let scalar_witness = self.pop_item()?.to_data()?.to_scalar()?;
        let v_scalar = scalar_witness.to_scalar();

        self.delegate.verify_point_op(|| {
            // Check V = vB => V-vB = 0
            PointOp {
                primary: Some(-v_scalar),
                secondary: None,
                arbitrary: vec![(Scalar::one(), v_point)],
            }
        })?;

        // Add constraint `V == expr`
        let (_, v) = self.delegate.commit_variable(&v_commitment)?;
        self.delegate.cs().constrain(expr.to_r1cs_lc() - v);

        // Push variable
        self.push_item(Variable {
            commitment: v_commitment,
        });
        Ok(())
    }

    fn r#const(&mut self) -> Result<(), VMError> {
        let scalar_witness = self.pop_item()?.to_data()?.to_scalar()?;
        self.push_item(Expression::constant(scalar_witness));
        Ok(())
    }

    fn var(&mut self) -> Result<(), VMError> {
        let commitment = self.pop_item()?.to_data()?.to_commitment()?;
        let v = Variable { commitment };
        self.push_item(v);
        Ok(())
    }

    fn alloc(&mut self, sw: Option<ScalarWitness>) -> Result<(), VMError> {
        let var = self
            .delegate
            .cs()
            .allocate(sw.map(|s| s.to_scalar()))
            .map_err(|e| VMError::R1CSError(e))?;
        let expr = Expression::LinearCombination(vec![(var, Scalar::one())], sw);
        self.push_item(expr);
        Ok(())
    }

    fn mintime(&mut self) -> Result<(), VMError> {
        self.push_item(Expression::constant(self.mintime));
        Ok(())
    }

    fn maxtime(&mut self) -> Result<(), VMError> {
        self.push_item(Expression::constant(self.maxtime));
        Ok(())
    }

    // pred blockid `nonce` → contract
    fn nonce(&mut self) -> Result<(), VMError> {
        let blockid = self.pop_item()?.to_data()?.to_bytes();
        let blockid = SliceReader::parse(&blockid, |r| r.read_u8x32())?;
        let predicate = self.pop_item()?.to_data()?.to_predicate()?;
        let nonce_anchor = Anchor::nonce(blockid, &predicate, self.maxtime);

        self.last_anchor = Some(nonce_anchor); // will be immediately moved into contract below
        let contract = self.make_output(predicate, vec![])?.into_contract().0;

        self.txlog
            .push(Entry::Nonce(blockid, self.maxtime, nonce_anchor));
        self.push_item(contract);
        Ok(())
    }

    fn log(&mut self) -> Result<(), VMError> {
        let data = self.pop_item()?.to_data()?;
        self.txlog.push(Entry::Data(data.to_bytes()));
        Ok(())
    }

    /// _qty flv data pred_ **issue** → _contract_
    fn issue(&mut self) -> Result<(), VMError> {
        let predicate = self.pop_item()?.to_data()?.to_predicate()?;
        let metadata = self.pop_item()?.to_data()?;
        let flv = self.pop_item()?.to_variable()?;
        let qty = self.pop_item()?.to_variable()?;

        let (flv_point, _) = self.delegate.commit_variable(&flv.commitment)?;
        let (qty_point, _) = self.delegate.commit_variable(&qty.commitment)?;

        self.delegate.verify_point_op(|| {
            let flv_scalar = Value::issue_flavor(&predicate, metadata);
            // flv_point == flavor·B    ->   0 == -flv_point + flv_scalar·B
            PointOp {
                primary: Some(flv_scalar),
                secondary: None,
                arbitrary: vec![(-Scalar::one(), flv_point)],
            }
        })?;

        let value = Value {
            qty: qty.commitment.clone(),
            flv: flv.commitment,
        };

        let qty_expr = self.variable_to_expression(qty)?;
        self.add_range_proof(BitRange::max(), qty_expr)?;

        self.txlog.push(Entry::Issue(qty_point, flv_point));

        let payload = vec![PortableItem::Value(value)];
        let contract = self.make_output(predicate, payload)?.into_contract().0;

        self.push_item(contract);
        Ok(())
    }

    fn borrow(&mut self) -> Result<(), VMError> {
        let flv = self.pop_item()?.to_variable()?;
        let qty = self.pop_item()?.to_variable()?;

        let (_, flv_var) = self.delegate.commit_variable(&flv.commitment)?;
        let (_, qty_var) = self.delegate.commit_variable(&qty.commitment)?;
        let flv_assignment = flv.commitment.assignment().map(|sw| sw.to_scalar());
        let qty_assignment = ScalarWitness::option_to_integer(qty.commitment.assignment())?;

        spacesuit::range_proof(
            self.delegate.cs(),
            qty_var.into(),
            qty_assignment,
            BitRange::max(),
        )
        .map_err(|_| VMError::R1CSInconsistency)?;

        let neg_qty_var = self
            .delegate
            .cs()
            .allocate(qty_assignment.map(|q| -q.to_scalar()))
            .map_err(|e| VMError::R1CSError(e))?;
        self.delegate.cs().constrain(qty_var + neg_qty_var);
        let value = Value {
            qty: qty.commitment.clone(),
            flv: flv.commitment,
        };
        let wide_value = WideValue {
            r1cs_qty: neg_qty_var,
            r1cs_flv: flv_var,
            witness: match (qty_assignment, flv_assignment) {
                (Some(q), Some(f)) => Some((q, f)),
                _ => None,
            },
        };
        self.push_item(wide_value);
        self.push_item(value);
        Ok(())
    }

    fn retire(&mut self) -> Result<(), VMError> {
        let value = self.pop_item()?.to_value()?;
        self.txlog
            .push(Entry::Retire(value.qty.into(), value.flv.into()));
        Ok(())
    }

    /// _input_ **input** → _contract_
    fn input(&mut self) -> Result<(), VMError> {
        let output = self.pop_item()?.to_data()?.to_output()?;
        let (contract, contract_id) = output.into_contract();
        self.push_item(contract);
        self.txlog.push(Entry::Input(contract_id));
        self.last_anchor = Some(contract_id.to_anchor().ratchet());
        Ok(())
    }

    /// _items... predicate_ **output:_k_** → ø
    fn output(&mut self, k: usize) -> Result<(), VMError> {
        let output = self.pop_output(k)?;
        self.txlog.push(Entry::Output(output));
        Ok(())
    }

    fn contract(&mut self, k: usize) -> Result<(), VMError> {
        let output = self.pop_output(k)?;
        self.push_item(output.into_contract().0);
        Ok(())
    }

    fn pop_output(&mut self, k: usize) -> Result<Output, VMError> {
        let predicate = self.pop_item()?.to_data()?.to_predicate()?;

        if k > self.stack.len() {
            return Err(VMError::StackUnderflow);
        }

        let payload = self
            .stack
            .drain(self.stack.len() - k..)
            .map(|item| item.to_portable())
            .collect::<Result<Vec<_>, _>>()?;

        self.make_output(predicate, payload)
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

        let mut output_values: Vec<Value> = Vec::with_capacity(n);

        let mut cloak_ins: Vec<spacesuit::AllocatedValue> = Vec::with_capacity(m);
        let mut cloak_outs: Vec<spacesuit::AllocatedValue> = Vec::with_capacity(n);

        // Make cloak outputs and output values using (qty,flv) commitments
        for _ in 0..n {
            let flv = self.pop_item()?.to_data()?.to_commitment()?;
            let qty = self.pop_item()?.to_data()?.to_commitment()?;

            let value = Value { qty, flv };

            let cloak_value = self.value_to_cloak_value(&value)?;

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

        spacesuit::cloak(self.delegate.cs(), cloak_ins, cloak_outs)
            .map_err(|_| VMError::FormatError)?;

        // Push in the same order.
        for v in output_values.into_iter() {
            self.push_item(v);
        }

        Ok(())
    }

    // Prover:
    // - remember the signing key (Scalar) in a list and make a sig later.
    // Verifier:
    // - remember the verificaton key (Point) in a list and check a sig later.
    // Both: put the payload onto the stack.
    // _contract_ **signtx** → _results..._
    fn signtx(&mut self) -> Result<(), VMError> {
        let contract = self.pop_item()?.to_contract()?;
        self.delegate.process_tx_signature(contract.predicate)?;
        for item in contract.payload.into_iter() {
            self.push_item(item);
        }
        Ok(())
    }

    fn call(&mut self) -> Result<(), VMError> {
        // Pop program, salt, contract, and predicate
        let prog = self.pop_item()?.to_data()?;
        let salt = self.pop_item()?.to_data()?;
        let contract = self.pop_item()?.to_contract()?;
        let predicate = contract.predicate;

        // 0 = -P + h(prog) * B2
        self.delegate.verify_point_op(|| {
            predicate.prove_program_predicate(&prog.clone().to_bytes(), &salt.clone().to_bytes())
        })?;

        // Place contract payload on the stack
        for item in contract.payload.into_iter() {
            self.push_item(item);
        }

        // Replace current program with new program
        self.continue_with_program(prog)?;
        Ok(())
    }

    fn left_or_right<F>(&mut self, assign: F) -> Result<(), VMError>
    where
        F: FnOnce(&mut Contract, Predicate, Predicate) -> (),
    {
        let r = self.pop_item()?.to_data()?.to_predicate()?;
        let l = self.pop_item()?.to_data()?.to_predicate()?;

        let mut contract = self.pop_item()?.to_contract()?;
        let p = &contract.predicate;

        self.delegate.verify_point_op(|| p.prove_or(&l, &r))?;

        assign(&mut contract, l, r);

        self.push_item(contract);
        Ok(())
    }

    fn left(&mut self) -> Result<(), VMError> {
        self.left_or_right(|contract, left, _| {
            contract.predicate = left;
        })
    }

    fn right(&mut self) -> Result<(), VMError> {
        self.left_or_right(|contract, _, right| {
            contract.predicate = right;
        })
    }

    fn delegate(&mut self) -> Result<(), VMError> {
        // Signature
        let sig = self.pop_item()?.to_data()?.to_bytes();
        let signature = Signature::from_bytes(SliceReader::parse(&sig, |r| r.read_u8x64())?)?;

        // Program
        let prog = self.pop_item()?.to_data()?;

        // Place all items in payload onto the stack
        let contract = self.pop_item()?.to_contract()?;
        for item in contract.payload.into_iter() {
            self.push_item(item);
        }

        // Verification key from predicate
        let verification_key = contract.predicate.to_key()?;

        // Verify signature using Verification key, over the message `program`
        let mut t = Transcript::new(b"ZkVM.delegate");
        t.commit_bytes(b"prog", &prog.clone().to_bytes());
        self.delegate
            .verify_point_op(|| signature.verify_single(&mut t, verification_key))?;

        // Replace current program with new program
        self.continue_with_program(prog)?;
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
impl<'d, CS, D> VM<'d, CS, D>
where
    CS: r1cs::ConstraintSystem,
    D: Delegate<CS>,
{
    fn pop_item(&mut self) -> Result<Item, VMError> {
        self.stack.pop().ok_or(VMError::StackUnderflow)
    }

    fn push_item<T>(&mut self, item: T)
    where
        T: Into<Item>,
    {
        self.stack.push(item.into())
    }

    fn value_to_cloak_value(
        &mut self,
        value: &Value,
    ) -> Result<spacesuit::AllocatedValue, VMError> {
        Ok(spacesuit::AllocatedValue {
            q: self.delegate.commit_variable(&value.qty)?.1,
            f: self.delegate.commit_variable(&value.flv)?.1,
            assignment: value.assignment()?.map(|(q, f)| spacesuit::Value { q, f }),
        })
    }

    fn wide_value_to_cloak_value(&mut self, walue: &WideValue) -> spacesuit::AllocatedValue {
        spacesuit::AllocatedValue {
            q: walue.r1cs_qty,
            f: walue.r1cs_flv,
            assignment: match walue.witness {
                None => None,
                Some(w) => Some(spacesuit::Value { q: w.0, f: w.1 }),
            },
        }
    }

    fn item_to_wide_value(&mut self, item: Item) -> Result<WideValue, VMError> {
        match item {
            Item::Value(value) => Ok(WideValue {
                r1cs_qty: self.delegate.commit_variable(&value.qty)?.1,
                r1cs_flv: self.delegate.commit_variable(&value.flv)?.1,
                witness: value.assignment()?,
            }),
            Item::WideValue(w) => Ok(w),
            _ => Err(VMError::TypeNotWideValue),
        }
    }

    fn variable_to_expression(&mut self, var: Variable) -> Result<Expression, VMError> {
        let (_, r1cs_var) = self.delegate.commit_variable(&var.commitment)?;

        Ok(Expression::LinearCombination(
            vec![(r1cs_var, Scalar::one())],
            var.commitment.assignment(),
        ))
    }

    fn continue_with_program(&mut self, prog: Data) -> Result<(), VMError> {
        let new_run = self.delegate.new_run(prog)?;
        let paused_run = mem::replace(&mut self.current_run, new_run);
        self.run_stack.push(paused_run);
        Ok(())
    }

    fn add_range_proof(&mut self, bitrange: BitRange, expr: Expression) -> Result<(), VMError> {
        let (lc, assignment) = match expr {
            Expression::Constant(x) => (r1cs::LinearCombination::from(x), Some(x)),
            Expression::LinearCombination(terms, assignment) => {
                (r1cs::LinearCombination::from_iter(terms), assignment)
            }
        };
        spacesuit::range_proof(
            self.delegate.cs(),
            lc,
            ScalarWitness::option_to_integer(assignment)?,
            bitrange,
        )
        .map_err(|_| VMError::R1CSInconsistency)
    }

    /// Creates and anchors the contract
    fn make_output(
        &mut self,
        predicate: Predicate,
        payload: Vec<PortableItem>,
    ) -> Result<Output, VMError> {
        let anchor = mem::replace(&mut self.last_anchor, None).ok_or(VMError::AnchorMissing)?;
        let output = Output::new(Contract {
            anchor,
            predicate,
            payload,
        });
        self.last_anchor = Some(output.id().to_anchor());
        Ok(output)
    }
}
