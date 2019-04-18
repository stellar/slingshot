use bulletproofs::r1cs;
use bulletproofs::{BulletproofGens, PedersenGens};
use curve25519_dalek::ristretto::CompressedRistretto;
use merlin::Transcript;
use musig::{Multikey, VerificationKey};

use crate::constraints::Commitment;
use crate::encoding::*;
use crate::errors::VMError;
use crate::ops::Instruction;
use crate::point_ops::PointOp;
use crate::predicate::Predicate;
use crate::program::ProgramItem;
use crate::vm::{Delegate, Tx, VerifiedTx, VM};

/// This is the entry point API for verifying a transaction.
/// Verifier passes the `Tx` object through the VM,
/// verifies an aggregated transaction signature (see `signtx` instruction),
/// verifies a R1CS proof and returns a `VerifiedTx` with the log of changes
/// to be applied to the blockchain state.
pub struct Verifier<'t> {
    signtx_keys: Vec<VerificationKey>,
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

    fn process_tx_signature(&mut self, pred: Predicate) -> Result<(), VMError> {
        let key = VerificationKey::from_compressed(pred.to_point()).ok_or(VMError::InvalidPoint)?;
        Ok(self.signtx_keys.push(key))
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
        let mut r1cs_transcript = Transcript::new(b"ZkVM.r1cs");
        let cs = r1cs::Verifier::new(&mut r1cs_transcript);

        let mut verifier = Verifier {
            signtx_keys: Vec::new(),
            deferred_operations: Vec::new(),
            cs: cs,
        };

        let vm = VM::new(
            tx.header,
            VerifierRun::new(tx.program.clone()),
            &mut verifier,
        );

        let (txid, txlog) = vm.run()?;

        // Verify the signatures over txid
        let mut signtx_transcript = Transcript::new(b"ZkVM.signtx");
        signtx_transcript.commit_bytes(b"txid", &txid.0);

        if verifier.signtx_keys.len() != 0 {
            verifier.deferred_operations.push(
                // TODO: use MuSig multi-message API, signing contract
                // IDs in addition to TxID for each key.
                tx.signature
                    .verify(
                        &mut signtx_transcript,
                        Multikey::new(verifier.signtx_keys)
                            .map_err(|_| VMError::KeyAggregationFailed)?
                            .aggregated_key(),
                    )
                    .into(),
            );
        }

        // Verify all deferred crypto operations.
        PointOp::verify_batch(&verifier.deferred_operations[..])?;

        // Verify the R1CS proof

        // TBD: provide is as a precomputed object to avoid
        // creating secondary point per each tx verification
        let pc_gens = PedersenGens::default();

        verifier
            .cs
            .verify(&tx.proof, &pc_gens, bp_gens)
            .map_err(|_| VMError::InvalidR1CSProof)?;

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
