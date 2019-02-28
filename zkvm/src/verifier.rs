use bulletproofs::r1cs;
use bulletproofs::{BulletproofGens, PedersenGens};
use curve25519_dalek::ristretto::CompressedRistretto;
use merlin::Transcript;

use crate::constraints::Commitment;
use crate::encoding::*;
use crate::errors::VMError;
use crate::ops::Instruction;
use crate::point_ops::PointOp;
use crate::predicate::Predicate;
use crate::signature::VerificationKey;

use crate::vm::{Delegate, Tx, VerifiedTx, VM};

/// This is the entry point API for verifying a transaction.
/// Verifier passes the `Tx` object through the VM,
/// verifies an aggregated transaction signature (see `signtx` instruction),
/// verifies a R1CS proof and returns a `VerifiedTx` with the log of changes
/// to be applied to the blockchain state.
pub struct Verifier<'a, 'b> {
    signtx_keys: Vec<VerificationKey>,
    deferred_operations: Vec<PointOp>,
    cs: r1cs::Verifier<'a, 'b>,
}

pub struct VerifierRun {
    program: Vec<u8>,
    offset: usize,
}

impl<'a, 'b> Delegate<r1cs::Verifier<'a, 'b>> for Verifier<'a, 'b> {
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
        Ok(self.signtx_keys.push(VerificationKey(pred.to_point())))
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

    fn cs(&mut self) -> &mut r1cs::Verifier<'a, 'b> {
        &mut self.cs
    }
}

impl<'a, 'b> Verifier<'a, 'b> {
    /// Verifies the `Tx` object by executing the VM and returns the `VerifiedTx`.
    /// Returns an error if the program is malformed or any of the proofs are not valid.
    pub fn verify_tx<'g>(tx: Tx, bp_gens: &'g BulletproofGens) -> Result<VerifiedTx, VMError> {
        let mut r1cs_transcript = Transcript::new(b"ZkVM.r1cs");
        let pc_gens = PedersenGens::default();
        let cs = r1cs::Verifier::new(bp_gens, &pc_gens, &mut r1cs_transcript);

        let mut verifier = Verifier {
            signtx_keys: Vec::new(),
            deferred_operations: Vec::new(),
            cs: cs,
        };

        let vm = VM::new(tx.header, VerifierRun::new(tx.program), &mut verifier);

        let (txid, txlog) = vm.run()?;

        // Verify the signatures over txid
        let mut signtx_transcript = Transcript::new(b"ZkVM.signtx");
        signtx_transcript.commit_bytes(b"txid", &txid.0);

        let signtx_point_op = tx
            .signature
            .verify_aggregated(&mut signtx_transcript, &verifier.signtx_keys);
        verifier.deferred_operations.push(signtx_point_op);
        // Verify all deferred crypto operations.
        PointOp::verify_batch(&verifier.deferred_operations[..])?;

        // Verify the R1CS proof
        verifier
            .cs
            .verify(&tx.proof)
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
