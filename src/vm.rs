use bulletproofs::r1cs;
use bulletproofs::r1cs::R1CSProof;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use spacesuit;
use std::iter::FromIterator;

use crate::encoding;
use crate::encoding::Subslice;
use crate::errors::VMError;
use crate::ops::Instruction;
use crate::point_ops::PointOp;
use crate::signature::*;
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

pub struct VM<'d, CS, D>
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
    txlog: Vec<Entry>,
    variable_commitments: Vec<VariableCommitment>,
}

pub trait Delegate<CS: r1cs::ConstraintSystem> {
    type RunType: RunTrait;

    /// Adds a Commitment to the underlying constraint system, producing a high-level variable
    fn commit_variable(&mut self, com: &Commitment) -> (CompressedRistretto, r1cs::Variable);

    /// Adds a point operation to the list of deferred operation for later batch verification
    fn verify_point_op<F>(&mut self, point_op_fn: F)
    where
        F: FnOnce() -> PointOp;

    /// Adds a key represented by Predicate to either verify or
    /// sign a transaction
    fn process_tx_signature(&mut self, pred: Predicate) -> Result<(), VMError>;

    /// Returns the delegate's underlying constraint system
    fn cs(&mut self) -> &mut CS;
}

/// A trait for an instance of a "run": a currently executed program.
pub trait RunTrait {
    /// Returns the next instruction.
    /// Returns Err() upon decoding/format error.
    /// Returns Ok(Some()) if there is another instruction available.
    /// Returns Ok(None) if there is no more instructions to execute.
    fn next_instruction(&mut self) -> Result<Option<Instruction>, VMError>;
}

/// And indirect reference to a high-level variable within a constraint system.
/// Variable types store index of such commitments that allows replacing them.
struct VariableCommitment {
    /// Pedersen commitment to a variable
    commitment: Commitment,

    /// Attached/detached state
    /// None if the variable is not attached to the CS yet,
    /// so its commitment is replaceable via `reblind`.
    /// Some if variable is attached to the CS yet and has an index in CS,
    /// so its commitment is no longer replaceable via `reblind`.
    variable: Option<r1cs::Variable>,
}

impl<'d, CS, D> VM<'d, CS, D>
where
    CS: r1cs::ConstraintSystem,
    D: Delegate<CS>,
{
    /// Instantiates a new VM instance.
    pub fn new(
        version: u64,
        mintime: u64,
        maxtime: u64,
        run: D::RunType,
        delegate: &'d mut D,
    ) -> Self {
        VM {
            mintime,
            maxtime,
            extension: version > CURRENT_VERSION,
            unique: false,
            delegate,
            stack: Vec::new(),
            current_run: run,
            run_stack: Vec::new(),
            txlog: vec![Entry::Header(version, mintime, maxtime)],
            variable_commitments: Vec::new(),
        }
    }

    /// Runs through the entire program and nested programs until completion.
    pub fn run(mut self) -> Result<(TxID, Vec<Entry>), VMError> {
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
        if let Some(instr) = self.current_run.next_instruction()? {
            // if let Some(instr) = self.next_instruction()? {
            // Attempt to read the next instruction and advance the program state
            match instr {
                // the data is just a slice, so the clone would copy the slice struct,
                // not the actual buffer of bytes.
                Instruction::Push(data) => self.pushdata(data)?,
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
            Item::Data(x) => Item::Data(x.tbd_clone()?),
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

    fn issue(&mut self) -> Result<(), VMError> {
        let predicate = self.pop_item()?.to_data()?.to_predicate()?;
        let flv = self.pop_item()?.to_variable()?;
        let qty = self.pop_item()?.to_variable()?;

        let (flv_point, _) = self.attach_variable(flv);
        let (qty_point, _) = self.attach_variable(qty);

        self.delegate.verify_point_op(|| {
            let flv_scalar = Value::issue_flavor(&predicate);
            // flv_point == flavor·B    ->   0 == -flv_point + flv_scalar·B
            PointOp {
                primary: Some(flv_scalar),
                secondary: None,
                arbitrary: vec![(-Scalar::one(), flv_point)],
            }
        });

        let value = Value { qty, flv };

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
        let input = self.pop_item()?.to_data()?.to_input()?;
        let (contract, utxo) = self.spend_input(input)?;
        self.push_item(contract);
        self.txlog.push(Entry::Input(utxo));
        self.unique = true;
        Ok(())
    }

    /// _items... predicate_ **output:_k_** → ø
    fn output(&mut self, k: usize) -> Result<(), VMError> {
        let contract = self.pop_contract(k)?;
        let output = self.encode_output(contract);
        self.txlog.push(Entry::Output(output));
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

            let flv = self.make_variable(flv);
            let qty = self.make_variable(qty);

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

    fn make_variable(&mut self, commitment: Commitment) -> Variable {
        let index = self.variable_commitments.len();

        self.variable_commitments.push(VariableCommitment {
            commitment: commitment,
            variable: None,
        });
        Variable { index }
    }

    fn get_variable_commitment(&self, var: Variable) -> CompressedRistretto {
        let var_com = &self.variable_commitments[var.index].commitment;
        var_com.to_point()
    }

    fn attach_variable(&mut self, var: Variable) -> (CompressedRistretto, r1cs::Variable) {
        // This subscript never fails because the variable is created only via `make_variable`.
        let v_com = &self.variable_commitments[var.index];
        match v_com.variable {
            Some(v) => (v_com.commitment.to_point(), v),
            None => {
                let (point, r1cs_var) = self.delegate.commit_variable(&v_com.commitment);
                self.variable_commitments[var.index].variable = Some(r1cs_var);
                (point, r1cs_var)
            }
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

    fn item_to_wide_value(&mut self, item: Item) -> Result<WideValue, VMError> {
        match item {
            Item::Value(value) => Ok(WideValue {
                r1cs_qty: self.attach_variable(value.qty).1,
                r1cs_flv: self.attach_variable(value.flv).1,
                // TBD: add witness for Value types where it exists.
                witness: None,
            }),
            Item::WideValue(w) => Ok(w),
            _ => Err(VMError::TypeNotWideValue),
        }
    }

    fn variable_to_expression(&mut self, var: Variable) -> Expression {
        let (_, r1cs_var) = self.attach_variable(var);
        Expression {
            terms: vec![(r1cs_var, Scalar::one())],
        }
    }

    fn spend_input(&mut self, input: Input) -> Result<(Contract, UTXO), VMError> {
        match input {
            Input::Opaque(data) => self.decode_input(data),
            Input::Witness(w) => unimplemented!(),
        }
    }

    fn decode_input(&mut self, data: Vec<u8>) -> Result<(Contract, UTXO), VMError> {
        // Input  =  PreviousTxID || PreviousOutput
        // PreviousTxID  =  <32 bytes>
        let mut slice = Subslice::new(&data);
        let txid = TxID(slice.read_u8x32()?);
        let output_slice = &slice;
        let contract = self.decode_output(slice)?;
        let utxo = UTXO::from_output(output_slice, &txid);
        Ok((contract, utxo))
    }

    fn decode_output<'a>(&mut self, mut output: Subslice<'a>) -> Result<Contract, VMError> {
        //    Output  =  Predicate  ||  LE32(k)  ||  Item[0]  || ... ||  Item[k-1]
        // Predicate  =  <32 bytes>
        //      Item  =  enum { Data, Value }
        //      Data  =  0x00  ||  LE32(len)  ||  <bytes>
        //     Value  =  0x01  ||  <32 bytes> ||  <32 bytes>

        let predicate = Predicate::Opaque(output.read_point()?);
        let k = output.read_size()?;

        // sanity check: avoid allocating unreasonably more memory
        // just because an untrusted length prefix says so.
        if k > output.len() {
            return Err(VMError::FormatError);
        }

        let mut payload: Vec<PortableItem> = Vec::with_capacity(k);
        for _ in 0..k {
            let item = match output.read_u8()? {
                DATA_TYPE => {
                    let len = output.read_size()?;
                    let bytes = output.read_bytes(len)?;
                    PortableItem::Data(Data::Opaque(bytes.to_vec()))
                }
                VALUE_TYPE => {
                    let qty = output.read_point()?;
                    let flv = output.read_point()?;

                    let qty = self.make_variable(Commitment::Opaque(qty));
                    let flv = self.make_variable(Commitment::Opaque(flv));

                    PortableItem::Value(Value { qty, flv })
                }
                _ => return Err(VMError::FormatError),
            };
            payload.push(item);
        }

        Ok(Contract { predicate, payload })
    }

    fn encode_output(&mut self, contract: Contract) -> Vec<u8> {
        let mut output = Vec::with_capacity(contract.exact_output_size());

        encoding::write_point(&contract.predicate.to_point(), &mut output);
        encoding::write_u32(contract.payload.len() as u32, &mut output);

        // can move all the write functions into type impl
        for item in contract.payload.iter() {
            match item {
                PortableItem::Data(d) => match d {
                    Data::Opaque(data) => {
                        encoding::write_u8(DATA_TYPE, &mut output);
                        encoding::write_u32(data.len() as u32, &mut output);
                        encoding::write_bytes(&data, &mut output);
                    }
                    Data::Witness(_) => unimplemented!(),
                },
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
            self.delegate.cs(),
            r1cs::LinearCombination::from_iter(expr.terms),
            // TBD: maintain the assignment for the expression and provide it here
            None,
            bitrange,
        )
        .map_err(|_| VMError::R1CSInconsistency)
    }
}
