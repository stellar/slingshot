use bulletproofs::r1cs;
use bulletproofs::{BulletproofGens, PedersenGens};
use curve25519_dalek::ristretto::CompressedRistretto;
use merlin::Transcript;

use crate::encoding::*;
use crate::errors::VMError;
use crate::ops::Instruction;
use crate::point_ops::PointOp;
use crate::signature::VerificationKey;
use crate::types::*;

use crate::vm::{Delegate, RunTrait, Tx, VerifiedTx, VM};

pub struct Verifier<'a, 'b> {
    signtx_keys: Vec<VerificationKey>,
    deferred_operations: Vec<PointOp>,
    cs: r1cs::Verifier<'a, 'b>,
}

pub struct RunVerifier {
    program: Vec<u8>,
    offset: usize,
}

impl<'a, 'b> Delegate<r1cs::Verifier<'a, 'b>> for Verifier<'a, 'b> {
    type RunType = RunVerifier;

    fn commit_variable(&mut self, com: &Commitment) -> (CompressedRistretto, r1cs::Variable) {
        let point = com.to_point();
        let var = self.cs.commit(point);
        (point, var)
    }

    fn verify_point_op<F>(&mut self, point_op_fn: F)
    where
        F: FnOnce() -> PointOp,
    {
        self.deferred_operations.push(point_op_fn());
    }

    fn process_tx_signature(&mut self, pred: Predicate) -> Result<(), VMError> {
        match pred {
            Predicate::Opaque(p) => Ok(self.signtx_keys.push(VerificationKey(p))),
            Predicate::Witness(_) => Err(VMError::PredicateNotOpaque),
        }
    }

    fn cs(&mut self) -> &mut r1cs::Verifier<'a, 'b> {
        &mut self.cs
    }
}

impl<'a, 'b> Verifier<'a, 'b> {
    pub fn verify_tx<'g>(tx: Tx, bp_gens: &'g BulletproofGens) -> Result<VerifiedTx, VMError> {
        let mut r1cs_transcript = Transcript::new(b"ZkVM.r1cs");
        let pc_gens = PedersenGens::default();
        let cs = r1cs::Verifier::new(bp_gens, &pc_gens, &mut r1cs_transcript);

        let mut verifier = Verifier {
            signtx_keys: Vec::new(),
            deferred_operations: Vec::new(),
            cs: cs,
        };

        let vm = VM::new(
            tx.version,
            tx.mintime,
            tx.maxtime,
            RunVerifier::new(tx.program),
            &mut verifier,
        );

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
            version: tx.version,
            mintime: tx.mintime,
            maxtime: tx.maxtime,
            id: txid,
            log: txlog,
        })
    }
}

impl RunVerifier {
    fn new(program: Vec<u8>) -> Self {
        RunVerifier { program, offset: 0 }
    }
}

impl RunTrait for RunVerifier {
    fn next_instruction(&mut self) -> Result<Option<Instruction>, VMError> {
        let mut program = Subslice::new_with_range(&self.program, self.offset..self.program.len())?;

        // Reached the end of the program - no more instructions to execute.
        if program.len() == 0 {
            return Ok(None);
        }
        let instr = Instruction::parse(&mut program)?;
        self.offset = program.range().start;
        Ok(Some(instr))
    }
}
