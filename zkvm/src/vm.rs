use bulletproofs::r1cs;
use core::iter;
use core::iter::FromIterator;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use musig::{BatchVerification, Signature};
use spacesuit;
use spacesuit::BitRange;
use std::mem;

use crate::constraints::{Commitment, Constraint, Expression, Variable};
use crate::contract::{Anchor, Contract, ContractID, PortableItem};
use crate::encoding::*;
use crate::errors::VMError;
use crate::fees::{fee_flavor, CheckedFee};
use crate::ops::Instruction;
use crate::predicate::{CallProof, Predicate};
use crate::program::ProgramItem;
use crate::scalar_witness::ScalarWitness;
use crate::tx::{TxEntry, TxHeader, TxID, TxLog};
use crate::types::*;

/// Current tx version determines which extension opcodes are treated as noops (see VM.extension flag).
pub const CURRENT_VERSION: u64 = 1;

pub(crate) struct VM<'d, CS, D>
where
    CS: r1cs::RandomizableConstraintSystem,
    D: Delegate<CS>,
{
    mintime_ms: u64,
    maxtime_ms: u64,

    // is true when tx version is in the future and
    // we allow treating unassigned opcodes as no-ops.
    extension: bool,

    // updated by input/issue/contract/output instructions
    last_anchor: Option<Anchor>,

    // stack of all items in the VM
    stack: Vec<Item>,

    delegate: &'d mut D,

    current_run: D::RunType,
    run_stack: Vec<D::RunType>,
    txlog: TxLog,

    // collect the total fee to check for overflow
    total_fee: CheckedFee,
}

pub(crate) trait Delegate<CS: r1cs::RandomizableConstraintSystem> {
    /// Container type for the currently running program.
    type RunType;

    /// Batch verifier for signature checks and Taproot.
    type BatchVerifier: BatchVerification;

    /// Adds a Commitment to the underlying constraint system, producing a high-level variable
    fn commit_variable(
        &mut self,
        com: &Commitment,
    ) -> Result<(CompressedRistretto, r1cs::Variable), VMError>;

    /// Adds a key represented by Predicate to either verify or
    /// sign a transaction
    fn process_tx_signature(
        &mut self,
        pred: Predicate,
        contract_id: ContractID,
    ) -> Result<(), VMError>;

    /// Returns the delegate's underlying constraint system
    fn cs(&mut self) -> &mut CS;

    /// Returns the delegate's batch verifier.
    fn batch_verifier(&mut self) -> &mut Self::BatchVerifier;

    /// Returns the next instruction.
    /// Returns Err() upon decoding/format error.
    /// Returns Ok(Some()) if there is another instruction available.
    /// Returns Ok(None) if there is no more instructions to execute.
    fn next_instruction(&mut self, run: &mut Self::RunType)
        -> Result<Option<Instruction>, VMError>;

    fn new_run(&self, prog: ProgramItem) -> Result<Self::RunType, VMError>;
}

impl<'d, CS, D> VM<'d, CS, D>
where
    CS: r1cs::RandomizableConstraintSystem,
    D: Delegate<CS>,
{
    /// Instantiates a new VM instance.
    pub fn new(header: TxHeader, run: D::RunType, delegate: &'d mut D) -> Self {
        VM {
            mintime_ms: header.mintime_ms,
            maxtime_ms: header.maxtime_ms,
            extension: header.version > CURRENT_VERSION,
            last_anchor: None,
            delegate,
            stack: Vec::new(),
            current_run: run,
            run_stack: Vec::new(),
            txlog: vec![TxEntry::Header(header)].into(),
            total_fee: CheckedFee::zero(),
        }
    }

    /// Runs through the entire program and nested programs until completion.
    pub fn run(mut self) -> Result<(TxID, TxLog, CheckedFee), VMError> {
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

        Ok((txid, self.txlog, self.total_fee))
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
                Instruction::Push(data) => self.pushdata(data),
                Instruction::Program(prog) => self.pushprogram(prog),
                Instruction::Drop => self.drop()?,
                Instruction::Dup(i) => self.dup(i)?,
                Instruction::Roll(i) => self.roll(i)?,
                Instruction::Scalar => self.scalar()?,
                Instruction::Commit => self.commit()?,
                Instruction::Alloc(sw) => self.alloc(sw)?,
                Instruction::Mintime => self.mintime()?,
                Instruction::Maxtime => self.maxtime()?,
                Instruction::Expr => self.expr()?,
                Instruction::Neg => self.neg()?,
                Instruction::Add => self.add()?,
                Instruction::Mul => self.mul()?,
                Instruction::Eq => self.eq()?,
                Instruction::Range => self.range()?,
                Instruction::And => self.and()?,
                Instruction::Or => self.or()?,
                Instruction::Not => self.not()?,
                Instruction::Verify => self.verify()?,
                Instruction::Unblind => self.unblind()?,
                Instruction::Issue => self.issue()?,
                Instruction::Borrow => self.borrow()?,
                Instruction::Retire => self.retire()?,
                Instruction::Cloak(m, n) => self.cloak(m, n)?,
                Instruction::Fee => self.fee()?,
                Instruction::Input => self.input()?,
                Instruction::Output(k) => self.output(k)?,
                Instruction::Contract(k) => self.contract(k)?,
                Instruction::Log => self.log()?,
                Instruction::Eval => self.eval()?,
                Instruction::Call => self.call()?,
                Instruction::Signtx => self.signtx()?,
                Instruction::Signid => self.signid()?,
                Instruction::Signtag => self.signtag()?,
                Instruction::Ext(opcode) => self.ext(opcode)?,
            }
            return Ok(true);
        } else {
            // Reached the end of the current program
            return Ok(self.finish_run());
        }
    }

    fn pushdata(&mut self, str: String) {
        self.push_item(str);
    }

    fn pushprogram(&mut self, prog: ProgramItem) {
        self.push_item(prog);
    }

    fn drop(&mut self) -> Result<(), VMError> {
        let _dropped = self.pop_item()?.to_droppable()?;
        Ok(())
    }

    fn dup(&mut self, i: usize) -> Result<(), VMError> {
        if i >= self.stack.len() {
            return Err(VMError::StackUnderflow);
        }
        let item_idx = self.stack.len() - i - 1;
        let copied = self.stack[item_idx].dup_copyable()?;
        self.push_item(copied);
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
        let constraint = Constraint::eq(expr1, expr2);
        self.push_item(constraint);
        Ok(())
    }

    fn range(&mut self) -> Result<(), VMError> {
        let expr = self.pop_item()?.to_expression()?;
        self.add_range_proof(expr.clone())?;
        self.push_item(expr);
        Ok(())
    }

    fn and(&mut self) -> Result<(), VMError> {
        let c2 = self.pop_item()?.to_constraint()?;
        let c1 = self.pop_item()?.to_constraint()?;
        let c3 = Constraint::and(c1, c2);
        self.push_item(c3);
        Ok(())
    }

    fn or(&mut self) -> Result<(), VMError> {
        let c2 = self.pop_item()?.to_constraint()?;
        let c1 = self.pop_item()?.to_constraint()?;
        let c3 = Constraint::or(c1, c2);
        self.push_item(c3);
        Ok(())
    }

    fn not(&mut self) -> Result<(), VMError> {
        let c1 = self.pop_item()?.to_constraint()?;
        let c2 = Constraint::not(c1);
        self.push_item(c2);
        Ok(())
    }

    fn verify(&mut self) -> Result<(), VMError> {
        let constraint = self.pop_item()?.to_constraint()?;
        constraint.verify(self.delegate.cs())?;
        Ok(())
    }

    fn unblind(&mut self) -> Result<(), VMError> {
        // Pop scalar `v` and commitment `V`
        let v_scalar = self.pop_item()?.to_string()?.to_scalar()?.to_scalar();
        let v_point = self.pop_item()?.to_string()?.to_commitment()?.to_point();

        self.delegate.batch_verifier().append(
            -v_scalar,
            iter::once(Scalar::one()),
            iter::once(v_point.decompress()),
        );

        // Push commitment item
        self.push_item(String::Opaque(v_point.as_bytes().to_vec()));
        Ok(())
    }

    fn scalar(&mut self) -> Result<(), VMError> {
        let scalar_witness = self.pop_item()?.to_string()?.to_scalar()?;
        self.push_item(Expression::constant(scalar_witness));
        Ok(())
    }

    fn commit(&mut self) -> Result<(), VMError> {
        let commitment = self.pop_item()?.to_string()?.to_commitment()?;
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
        self.push_item(Expression::constant(self.mintime_ms));
        Ok(())
    }

    fn maxtime(&mut self) -> Result<(), VMError> {
        self.push_item(Expression::constant(self.maxtime_ms));
        Ok(())
    }

    fn log(&mut self) -> Result<(), VMError> {
        let data = self.pop_item()?.to_string()?;
        self.txlog.push(TxEntry::Data(data.to_bytes()));
        Ok(())
    }

    /// _qty flv data pred_ **issue** → _contract_
    fn issue(&mut self) -> Result<(), VMError> {
        let predicate = self.pop_item()?.to_string()?.to_predicate()?;
        let metadata = self.pop_item()?.to_string()?;
        let flv = self.pop_item()?.to_variable()?;
        let qty = self.pop_item()?.to_variable()?;

        let (flv_point, _) = self.delegate.commit_variable(&flv.commitment)?;
        let (qty_point, _) = self.delegate.commit_variable(&qty.commitment)?;

        let flv_scalar = Value::issue_flavor(&predicate, metadata);
        // flv_point == flavor·B    ->   0 == -flv_point + flv_scalar·B
        self.delegate.batch_verifier().append(
            flv_scalar,
            iter::once(-Scalar::one()),
            iter::once(flv_point.decompress()),
        );

        let value = Value {
            qty: qty.commitment.clone(),
            flv: flv.commitment,
        };

        let qty_expr = self.variable_to_expression(qty)?;
        self.add_range_proof(qty_expr)?;

        self.txlog.push(TxEntry::Issue(qty_point, flv_point));

        let payload = vec![PortableItem::Value(value)];
        let contract = self.make_contract(predicate, payload)?;

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

        let neg_qty_assignment = qty_assignment.map(|q| -q);

        let neg_qty_var = self
            .delegate
            .cs()
            .allocate(neg_qty_assignment.map(|q| q.to_scalar()))
            .map_err(|e| VMError::R1CSError(e))?;

        self.delegate.cs().constrain(qty_var + neg_qty_var);

        let value = Value {
            qty: qty.commitment.clone(),
            flv: flv.commitment,
        };
        let wide_value = WideValue(spacesuit::AllocatedValue {
            q: neg_qty_var,
            f: flv_var,
            assignment: match (neg_qty_assignment, flv_assignment) {
                (Some(q), Some(f)) => Some(spacesuit::Value { q, f }),
                _ => None,
            },
        });
        self.push_item(wide_value);
        self.push_item(value);
        Ok(())
    }

    fn retire(&mut self) -> Result<(), VMError> {
        let value = self.pop_item()?.to_value()?;
        self.txlog
            .push(TxEntry::Retire(value.qty.into(), value.flv.into()));
        Ok(())
    }

    /// _input_ **input** → _contract_
    fn input(&mut self) -> Result<(), VMError> {
        let contract = self.pop_item()?.to_string()?.to_output()?;
        let contract_id = contract.id();
        self.txlog.push(TxEntry::Input(contract_id));
        self.push_item(contract);
        self.last_anchor = Some(contract_id.to_anchor().ratchet());
        Ok(())
    }

    /// _items... predicate_ **output:_k_** → ø
    fn output(&mut self, k: usize) -> Result<(), VMError> {
        let contract = self.pop_contract(k)?;
        self.txlog.push(TxEntry::Output(contract));
        Ok(())
    }

    fn contract(&mut self, k: usize) -> Result<(), VMError> {
        let contract = self.pop_contract(k)?;
        self.push_item(contract);
        Ok(())
    }

    fn pop_contract(&mut self, k: usize) -> Result<Contract, VMError> {
        let predicate = self.pop_item()?.to_string()?.to_predicate()?;

        if k > self.stack.len() {
            return Err(VMError::StackUnderflow);
        }

        let payload = self
            .stack
            .drain(self.stack.len() - k..)
            .map(|item| item.to_portable())
            .collect::<Result<Vec<_>, _>>()?;

        self.make_contract(predicate, payload)
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
            let flv = self.pop_item()?.to_string()?.to_commitment()?;
            let qty = self.pop_item()?.to_string()?.to_commitment()?;

            let value = Value { qty, flv };

            let cloak_value = self.value_to_cloak_value(&value)?;

            // insert in the same order as they are on stack (the deepest item will be at index 0)
            output_values.push(value);
            cloak_outs.insert(0, cloak_value);
        }

        // Make cloak inputs out of wide values
        for _ in 0..m {
            let item = self.pop_item()?;
            let walue = self.item_to_wide_value(item)?;

            // insert in the same order as they are on stack (the deepest item will be at index 0)
            cloak_ins.insert(0, walue.0);
        }

        spacesuit::cloak(self.delegate.cs(), cloak_ins, cloak_outs)
            .map_err(|_| VMError::InvalidFormat)?;

        // Push in the same order.
        for v in output_values.into_iter() {
            self.push_item(v);
        }

        Ok(())
    }

    // _qty_ **fee** → _widevalue_
    fn fee(&mut self) -> Result<(), VMError> {
        let fee = self.pop_item()?.to_string()?.to_u32()? as u64;
        let fee_scalar = Scalar::from(fee);
        self.total_fee = self.total_fee.add(fee).ok_or(VMError::FeeTooHigh)?;

        let v = spacesuit::Value {
            q: -spacesuit::SignedInteger::from(fee),
            f: fee_flavor(),
        };

        let av = v
            .allocate(self.delegate.cs())
            .map_err(|e| VMError::R1CSError(e))?;

        self.delegate.cs().constrain(av.q + fee_scalar);
        self.delegate.cs().constrain(av.f - fee_flavor());

        self.push_item(WideValue(av));

        self.txlog.push(TxEntry::Fee(fee));
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
        let contract_id = contract.id();

        self.delegate
            .process_tx_signature(contract.predicate, contract_id)?;
        for item in contract.payload.into_iter() {
            self.push_item(item);
        }
        Ok(())
    }

    fn eval(&mut self) -> Result<(), VMError> {
        // Pop program
        let program_item = self.pop_item()?.to_program()?;

        // Replace current program with new program
        self.continue_with_program(program_item)?;
        Ok(())
    }

    fn call(&mut self) -> Result<(), VMError> {
        // Pop program, call proof, and contract
        let program_item = self.pop_item()?.to_program()?;
        let call_proof_bytes = self.pop_item()?.to_string()?.to_bytes();
        let call_proof = (&call_proof_bytes[..]).read_all(|r| CallProof::decode(r))?;
        let contract = self.pop_item()?.to_contract()?;

        // 0 == -P + X + h1(X, M)*B
        contract.predicate.verify_taproot_batched(
            &program_item,
            &call_proof,
            self.delegate.batch_verifier(),
        );

        // Place contract payload on the stack
        for item in contract.payload.into_iter() {
            self.push_item(item);
        }

        // Replace current program with new program
        self.continue_with_program(program_item)?;
        Ok(())
    }

    fn signid(&mut self) -> Result<(), VMError> {
        // Signature
        let sig = self.pop_item()?.to_string()?.to_bytes();
        let signature = Signature::from_bytes((&sig[..]).read_all(|r| r.read_u8x64())?)
            .map_err(|_| VMError::InvalidFormat)?;

        // Program
        let prog = self.pop_item()?.to_program()?;

        // Place all items in payload onto the stack
        let contract = self.pop_item()?.to_contract()?;
        let contract_id = contract.id();

        for item in contract.payload.into_iter() {
            self.push_item(item);
        }

        // Verification key from predicate
        let verification_key = contract.predicate.verification_key();

        // Verify signature using Verification key, over the message `program`
        let mut t = Transcript::new(b"ZkVM.signid");
        t.append_message(b"contract", contract_id.as_ref());
        t.append_message(b"prog", &prog.to_bytes());
        signature.verify_batched(&mut t, verification_key, self.delegate.batch_verifier());

        // Replace current program with new program
        self.continue_with_program(prog)?;
        Ok(())
    }

    fn signtag(&mut self) -> Result<(), VMError> {
        // Signature
        let sig = self.pop_item()?.to_string()?.to_bytes();
        let signature = Signature::from_bytes((&sig[..]).read_all(|r| r.read_u8x64())?)
            .map_err(|_| VMError::InvalidFormat)?;

        // Program
        let prog = self.pop_item()?.to_program()?;

        // Place all items in payload onto the stack
        let contract = self.pop_item()?.to_contract()?;

        for item in contract.payload.into_iter() {
            self.push_item(item);
        }

        // Get the tag from the top of the stack (which was the top of the payload)
        // Keep the tag on the stack, so the contract could use it.
        let tag = self.pop_item()?.to_string()?;
        self.push_item(tag.clone());

        // Verification key from predicate
        let verification_key = contract.predicate.verification_key();

        // Verify signature using Verification key, over the message `program`
        let mut t = Transcript::new(b"ZkVM.signtag");
        t.append_message(b"tag", &tag.to_bytes());
        t.append_message(b"prog", &prog.to_bytes());
        signature.verify_batched(&mut t, verification_key, self.delegate.batch_verifier());

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
    CS: r1cs::RandomizableConstraintSystem,
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
            assignment: value.assignment().map(|(q, f)| spacesuit::Value { q, f }),
        })
    }

    fn item_to_wide_value(&mut self, item: Item) -> Result<WideValue, VMError> {
        match item {
            Item::Value(value) => Ok(WideValue(self.value_to_cloak_value(&value)?)),
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

    fn continue_with_program(&mut self, prog: ProgramItem) -> Result<(), VMError> {
        let new_run = self.delegate.new_run(prog)?;
        let paused_run = mem::replace(&mut self.current_run, new_run);
        self.run_stack.push(paused_run);
        Ok(())
    }

    fn add_range_proof(&mut self, expr: Expression) -> Result<(), VMError> {
        match expr {
            Expression::Constant(x) => {
                if x.in_range() {
                    Ok(())
                } else {
                    Err(VMError::InvalidBitrange)
                }
            }
            Expression::LinearCombination(terms, assignment) => spacesuit::range_proof(
                self.delegate.cs(),
                r1cs::LinearCombination::from_iter(terms),
                ScalarWitness::option_to_integer(assignment)?,
                BitRange::max(),
            )
            .map_err(|_| VMError::R1CSInconsistency),
        }
    }

    /// Creates and anchors the contract
    fn make_contract(
        &mut self,
        predicate: Predicate,
        payload: Vec<PortableItem>,
    ) -> Result<Contract, VMError> {
        let anchor = mem::replace(&mut self.last_anchor, None).ok_or(VMError::AnchorMissing)?;
        let contract = Contract {
            predicate,
            payload,
            anchor,
        };
        self.last_anchor = Some(contract.id().to_anchor());
        Ok(contract)
    }
}
