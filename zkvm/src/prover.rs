use bulletproofs::r1cs;
use bulletproofs::{BulletproofGens, PedersenGens};
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use std::collections::VecDeque;

use crate::errors::VMError;
use crate::ops::Instruction;
use crate::point_ops::PointOp;
use crate::signature::Signature;
use crate::txlog::{TxID, TxLog};
use crate::types::*;
use crate::vm::{Delegate, Tx, VM};

pub struct Prover<'a, 'b> {
    signtx_keys: Vec<Scalar>,
    cs: r1cs::Prover<'a, 'b>,
}

pub struct ProverRun {
    program: VecDeque<Instruction>,
}

impl<'a, 'b> Delegate<r1cs::Prover<'a, 'b>> for Prover<'a, 'b> {
    type RunType = ProverRun;

    fn commit_variable(
        &mut self,
        com: &Commitment,
    ) -> Result<(CompressedRistretto, r1cs::Variable), VMError> {
        let (v, v_blinding) = match com {
            Commitment::Open(w) => (w.value.into(), w.blinding),
            Commitment::Closed(_) => return Err(VMError::WitnessMissing),
        };
        Ok(self.cs.commit(v, v_blinding))
    }

    fn verify_point_op<F>(&mut self, point_op_fn: F) -> Result<(), VMError>
    where
        F: FnOnce() -> PointOp,
    {
        Ok(())
    }

    fn process_tx_signature(&mut self, pred: Predicate) -> Result<(), VMError> {
        match pred.witness() {
            None => Err(VMError::WitnessMissing),
            Some(w) => match w {
                PredicateWitness::Key(s) => Ok(self.signtx_keys.push(s.clone())),
                _ => Err(VMError::TypeNotKey),
            },
        }
    }

    fn next_instruction(
        &mut self,
        run: &mut Self::RunType,
    ) -> Result<Option<Instruction>, VMError> {
        Ok(run.program.pop_front())
    }

    fn cs(&mut self) -> &mut r1cs::Prover<'a, 'b> {
        &mut self.cs
    }
}

impl<'a, 'b> Prover<'a, 'b> {
    pub fn build_tx<'g>(
        program: Vec<Instruction>,
        version: u64,
        mintime: u64,
        maxtime: u64,
        bp_gens: &'g BulletproofGens,
    ) -> Result<(Tx, TxID, TxLog), VMError> {
        // Prepare the constraint system
        let mut r1cs_transcript = Transcript::new(b"ZkVM.r1cs");
        let pc_gens = PedersenGens::default();
        let cs = r1cs::Prover::new(bp_gens, &pc_gens, &mut r1cs_transcript);

        // Serialize the tx program
        let mut bytecode = Vec::new();
        Instruction::encode_program(program.iter(), &mut bytecode);

        let mut prover = Prover {
            signtx_keys: Vec::new(),
            cs,
        };

        let vm = VM::new(
            version,
            mintime,
            maxtime,
            ProverRun {
                program: program.into(),
            },
            &mut prover,
        );

        let (txid, txlog) = vm.run()?;

        // Sign txid
        let mut signtx_transcript = Transcript::new(b"ZkVM.signtx");
        signtx_transcript.commit_bytes(b"txid", &txid.0);
        let signature = Signature::sign_aggregated(&mut signtx_transcript, &prover.signtx_keys);

        // Generate the R1CS proof
        let proof = prover.cs.prove().map_err(|_| VMError::InvalidR1CSProof)?;

        Ok((
            Tx {
                version,
                mintime,
                maxtime,
                signature,
                proof,
                program: bytecode,
            },
            txid,
            txlog,
        ))
    }
}
