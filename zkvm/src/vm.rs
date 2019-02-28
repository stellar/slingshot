use bulletproofs::r1cs;
use bulletproofs::r1cs::R1CSProof;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use spacesuit;
use spacesuit::SignedInteger;
use std::iter::FromIterator;

use crate::constraints::{Commitment, Constraint, Expression, Variable};
use crate::contract::{Contract, PortableItem};
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

    // set to true by `input` and `nonce` instructions
    // when the txid is guaranteed to be unique.
    unique: bool,

    // stack of all items in the VM
    stack: Vec<Item>,

    delegate: &'d mut D,

    current_run: D::RunType,
    run_stack: Vec<D::RunType>,
    txlog: TxLog,
    variable_commitments: Vec<VariableCommitment>,
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
}

/// And indirect reference to a high-level variable within a constraint system.
/// Variable types store index of such commitments that allows replacing them.
#[derive(Debug)]
pub struct VariableCommitment {
    /// Pedersen commitment to a variable
    commitment: Commitment,

    /// Attached/detached state
    /// None - if the variable is not attached to the CS yet,
    /// so its commitment is replaceable via `reblind`.
    /// Some - if variable is attached to the CS yet and has an index in CS,
    /// so its commitment is no longer replaceable via `reblind`.
    variable: Option<r1cs::Variable>,
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
            unique: false,
            delegate,
            stack: Vec::new(),
            current_run: run,
            run_stack: Vec::new(),
            txlog: vec![Entry::Header(header)],
            variable_commitments: Vec::new(),
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

        if self.unique == false {
            return Err(VMError::NotUniqueTxid);
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
                Instruction::Alloc => unimplemented!(),
                Instruction::Mintime => self.mintime()?,
                Instruction::Maxtime => self.maxtime()?,
                Instruction::Expr => self.expr()?,
                Instruction::Neg => self.neg()?,
                Instruction::Add => self.add()?,
                Instruction::Mul => self.mul()?,
                Instruction::Eq => self.eq()?,
                Instruction::Range(_) => unimplemented!(),
                Instruction::And => self.and()?,
                Instruction::Or => self.or()?,
                Instruction::Verify => self.verify()?,
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
                Instruction::Log => self.log()?,
                Instruction::Signtx => self.signtx()?,
                Instruction::Call => unimplemented!(),
                Instruction::Left => self.left()?,
                Instruction::Right => self.right()?,
                Instruction::Delegate => unimplemented!(),
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

    fn r#const(&mut self) -> Result<(), VMError> {
        let data = self.pop_item()?.to_data()?.to_bytes();
        let scalar = SliceReader::parse(&data, |r| r.read_scalar())?;
        self.push_item(Expression::constant(scalar));
        Ok(())
    }

    fn var(&mut self) -> Result<(), VMError> {
        let comm = self.pop_item()?.to_data()?.to_commitment()?;
        let v = self.commitment_to_variable(comm);
        self.push_item(v);
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

    fn nonce(&mut self) -> Result<(), VMError> {
        let predicate = self.pop_item()?.to_data()?.to_predicate()?;
        let point = predicate.to_point();
        let contract = Contract {
            predicate,
            payload: Vec::new(),
        };
        self.txlog.push(Entry::Nonce(point, self.maxtime));
        self.push_item(contract);
        self.unique = true;
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

        let (flv_point, _) = self.attach_variable(flv)?;
        let (qty_point, _) = self.attach_variable(qty)?;

        self.delegate.verify_point_op(|| {
            let flv_scalar = Value::issue_flavor(&predicate, metadata);
            // flv_point == flavor·B    ->   0 == -flv_point + flv_scalar·B
            PointOp {
                primary: Some(flv_scalar),
                secondary: None,
                arbitrary: vec![(-Scalar::one(), flv_point)],
            }
        })?;

        let value = Value { qty, flv };

        let qty_expr = self.variable_to_expression(qty)?;
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
        let qty = self.variable_to_commitment(value.qty);
        let flv = self.variable_to_commitment(value.flv);
        self.txlog.push(Entry::Retire(qty.into(), flv.into()));
        Ok(())
    }

    /// _input_ **input** → _contract_
    fn input(&mut self) -> Result<(), VMError> {
        let input = self.pop_item()?.to_data()?.to_input()?;
        let (contract, utxo) = input.unfreeze(|c| self.commitment_to_variable(c));
        self.push_item(contract);
        self.txlog.push(Entry::Input(utxo));
        self.unique = true;
        Ok(())
    }

    /// _items... predicate_ **output:_k_** → ø
    fn output(&mut self, k: usize) -> Result<(), VMError> {
        let contract = self.pop_contract(k)?;
        let frozen_contract = contract.freeze(|v| self.variable_to_commitment(v));
        self.txlog.push(Entry::Output(frozen_contract.to_bytes()));
        Ok(())
    }

    fn contract(&mut self, k: usize) -> Result<(), VMError> {
        let contract = self.pop_contract(k)?;
        self.push_item(contract);
        Ok(())
    }

    fn pop_contract(&mut self, k: usize) -> Result<Contract, VMError> {
        let predicate = self.pop_item()?.to_data()?.to_predicate()?;

        if k > self.stack.len() {
            return Err(VMError::StackUnderflow);
        }

        let payload = self
            .stack
            .drain(self.stack.len() - k..)
            .map(|item| item.to_portable())
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Contract { predicate, payload })
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
            let flv = self.pop_item()?.to_data()?.to_commitment()?;
            let qty = self.pop_item()?.to_data()?.to_commitment()?;

            let flv = self.commitment_to_variable(flv);
            let qty = self.commitment_to_variable(qty);

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

    fn commitment_to_variable(&mut self, commitment: Commitment) -> Variable {
        let index = self.variable_commitments.len();

        self.variable_commitments.push(VariableCommitment {
            commitment: commitment,
            variable: None,
        });
        Variable { index }
    }

    fn variable_to_commitment(&self, var: Variable) -> Commitment {
        self.variable_commitments[var.index].commitment.clone()
    }

    fn attach_variable(
        &mut self,
        var: Variable,
    ) -> Result<(CompressedRistretto, r1cs::Variable), VMError> {
        // This subscript never fails because the variable is created only via `commitment_to_variable`.
        let v_com = &self.variable_commitments[var.index];
        match v_com.variable {
            Some(v) => Ok((v_com.commitment.to_point(), v)),
            None => {
                let (point, r1cs_var) = self.delegate.commit_variable(&v_com.commitment)?;
                self.variable_commitments[var.index].variable = Some(r1cs_var);
                Ok((point, r1cs_var))
            }
        }
    }

    fn value_to_cloak_value(
        &mut self,
        value: &Value,
    ) -> Result<spacesuit::AllocatedValue, VMError> {
        Ok(spacesuit::AllocatedValue {
            q: self.attach_variable(value.qty)?.1,
            f: self.attach_variable(value.flv)?.1,
            assignment: self
                .value_witness(&value)?
                .map(|(q, f)| spacesuit::Value { q, f }),
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
                r1cs_qty: self.attach_variable(value.qty)?.1,
                r1cs_flv: self.attach_variable(value.flv)?.1,
                witness: self.value_witness(&value)?,
            }),
            Item::WideValue(w) => Ok(w),
            _ => Err(VMError::TypeNotWideValue),
        }
    }

    fn variable_to_expression(&mut self, var: Variable) -> Result<Expression, VMError> {
        let (_, r1cs_var) = self.attach_variable(var)?;

        Ok(Expression::LinearCombination(
            vec![(r1cs_var, Scalar::one())],
            self.variable_assignment(var),
        ))
    }

    /// Returns Ok(Some((qty,flv))) assignment pair if it's missing or consistent.
    /// Return Err if the witness is present, but is inconsistent.
    fn value_witness(&mut self, value: &Value) -> Result<Option<(SignedInteger, Scalar)>, VMError> {
        match (
            self.variable_assignment(value.qty),
            self.variable_assignment(value.flv),
        ) {
            (Some(ScalarWitness::Integer(q)), Some(ScalarWitness::Scalar(f))) => Ok(Some((q, f))),
            (None, None) => Ok(None),
            (_, _) => return Err(VMError::InconsistentWitness),
        }
    }

    fn variable_assignment(&mut self, var: Variable) -> Option<ScalarWitness> {
        self.variable_commitments[var.index]
            .commitment
            .witness()
            .map(|(content, _)| content)
    }

    fn add_range_proof(&mut self, bitrange: usize, expr: Expression) -> Result<(), VMError> {
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
}
