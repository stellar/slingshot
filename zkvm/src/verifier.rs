use bulletproofs::r1cs;
use bulletproofs::r1cs::ConstraintSystem;
use bulletproofs::{BulletproofGens, PedersenGens};
use curve25519_dalek::ristretto::CompressedRistretto;
use merlin::Transcript;
use musig::VerificationKey;

use crate::constraints::Commitment;
use crate::contract::ContractID;
use crate::encoding::*;
use crate::errors::VMError;
use crate::ops::Instruction;
use crate::point_ops::PointOp;
use crate::predicate::Predicate;
use crate::program::ProgramItem;
use crate::tx::{Tx, VerifiedTx};
use crate::vm::{Delegate, VM};

/// This is the entry point API for verifying a transaction.
/// Verifier passes the `Tx` object through the VM,
/// verifies an aggregated transaction signature (see `signtx` instruction),
/// verifies a R1CS proof and returns a `VerifiedTx` with the log of changes
/// to be applied to the blockchain state.
pub struct Verifier<'t> {
    signtx_items: Vec<(VerificationKey, ContractID)>,
    deferred_operations: Vec<PointOp>,
    cs: r1cs::Verifier<'t>,
}

pub struct VerifierRun {
    program: Vec<u8>,
    offset: usize,
}

impl<'t> Delegate<r1cs::Verifier<'t>> for Verifier<'t> {
    type RunType = VerifierRun;

    fn commit_variable(
        &mut self,
        com: &Commitment,
    ) -> Result<(CompressedRistretto, r1cs::Variable), VMError> {
        let point = com.to_point();
        let var = self.cs.commit(point);
        Ok((point, var))
    }

    fn verify_point_op<F>(&mut self, point_op_fn: F) -> Result<(), VMError>
    where
        F: FnOnce() -> PointOp,
    {
        self.deferred_operations.push(point_op_fn());
        Ok(())
    }

    fn process_tx_signature(
        &mut self,
        pred: Predicate,
        contract_id: ContractID,
    ) -> Result<(), VMError> {
        let key = pred.to_verification_key()?;
        Ok(self.signtx_items.push((key, contract_id)))
    }

    fn next_instruction(
        &mut self,
        run: &mut Self::RunType,
    ) -> Result<Option<Instruction>, VMError> {
        if run.offset == run.program.len() {
            return Ok(None);
        }
        let (instr, remainder) = SliceReader::parse(&run.program[run.offset..], |r| {
            Ok((Instruction::parse(r)?, r.skip_trailing_bytes()))
        })?;
        run.offset = run.program.len() - remainder;
        Ok(Some(instr))
    }

    fn new_run(&self, prog: ProgramItem) -> Result<Self::RunType, VMError> {
        Ok(VerifierRun::new(prog.to_bytecode()?))
    }

    fn cs(&mut self) -> &mut r1cs::Verifier<'t> {
        &mut self.cs
    }
}

impl<'t> Verifier<'t> {
    /// Verifies the `Tx` object by executing the VM and returns the `VerifiedTx`.
    /// Returns an error if the program is malformed or any of the proofs are not valid.
    pub fn verify_tx(tx: &Tx, bp_gens: &BulletproofGens) -> Result<VerifiedTx, VMError> {
        // TBD: provide this as a precomputed object to avoid
        // creating secondary point per each tx verification
        let pc_gens = PedersenGens::default();
        let mut r1cs_transcript = Transcript::new(b"ZkVM.r1cs");
        let cs = r1cs::Verifier::new(&mut r1cs_transcript);

        let mut verifier = Verifier {
            signtx_items: Vec::new(),
            deferred_operations: Vec::new(),
            cs,
        };

        let vm = VM::new(
            tx.header,
            VerifierRun::new(tx.program.clone()),
            &mut verifier,
        );

        let (txid, txlog) = vm.run()?;

        // Commit txid so that the proof is bound to the entire transaction, not just the constraint system.
        verifier.cs.transcript().commit_bytes(b"ZkVM.txid", &txid.0);

        // Verify the R1CS proof
        verifier
            .cs
            .verify(&tx.proof, &pc_gens, bp_gens)
            .map_err(|_| VMError::InvalidR1CSProof)?;

        // Verify the signatures over txid
        let mut signtx_transcript = Transcript::new(b"ZkVM.signtx");
        signtx_transcript.commit_bytes(b"txid", &txid.0);

        if verifier.signtx_items.len() != 0 {
            verifier.deferred_operations.push(
                tx.signature
                    .verify_multi(&mut signtx_transcript, verifier.signtx_items)
                    .into(),
            );
        }

        // Verify all deferred crypto operations.
        PointOp::verify_batch(&verifier.deferred_operations[..])?;

        Ok(VerifiedTx {
            header: tx.header,
            id: txid,
            log: txlog,
        })
    }
}

impl VerifierRun {
    fn new(program: Vec<u8>) -> Self {
        VerifierRun { program, offset: 0 }
    }
}
