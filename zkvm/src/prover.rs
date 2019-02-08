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
use crate::types::*;
use crate::vm::{Delegate, Tx, VM};

pub struct Prover<'a, 'b> {
    signtx_keys: Vec<Scalar>,
    cs: r1cs::Prover<'a, 'b>,
    bytecode: Vec<u8>,
}

pub struct ProverRun {
    program: VecDeque<Instruction>,
    root: bool,
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
        match pred {
            Predicate::Opaque(_) => Err(VMError::WitnessMissing),
            Predicate::Witness(w) => match *w {
                PredicateWitness::Key(s) => Ok(self.signtx_keys.push(s)),
                _ => Err(VMError::TypeNotKey),
            },
        }
    }

    fn next_instruction(
        &mut self,
        run: &mut Self::RunType,
    ) -> Result<Option<Instruction>, VMError> {
        let instruction = run.program.pop_front();
        if run.root {
            match &instruction {
                Some(i) => i.encode(&mut self.bytecode),
                None => (),
            };
        }
        Ok(instruction)
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
    ) -> Result<Tx, VMError> {
        let mut r1cs_transcript = Transcript::new(b"ZkVM.r1cs");
        let pc_gens = PedersenGens::default();
        let cs = r1cs::Prover::new(bp_gens, &pc_gens, &mut r1cs_transcript);

        let mut prover = Prover {
            signtx_keys: Vec::new(),
            cs: cs,
            bytecode: Vec::new(),
        };

        let vm = VM::new(
            version,
            mintime,
            maxtime,
            ProverRun::root(program),
            &mut prover,
        );

        let (txid, _) = vm.run()?;

        // Sign txid
        let mut signtx_transcript = Transcript::new(b"ZkVM.signtx");
        signtx_transcript.commit_bytes(b"txid", &txid.0);
        let signature = Signature::sign_aggregated(&mut signtx_transcript, &prover.signtx_keys);

        // Generate the R1CS proof
        let proof = prover.cs.prove().map_err(|_| VMError::InvalidR1CSProof)?;

        Ok(Tx {
            version,
            mintime,
            maxtime,
            signature,
            proof,
            program: prover.bytecode,
        })
    }
}

impl ProverRun {
    fn root(program: Vec<Instruction>) -> Self {
        ProverRun {
            program: program.into(),
            root: true,
        }
    }
    fn subprogram(program: Vec<Instruction>) -> Self {
        ProverRun {
            program: program.into(),
            root: false,
        }
    }
}
