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
use crate::vm::{Delegate, RunTrait, Tx, VM};

pub struct Prover<'a, 'b> {
    signtx_keys: Vec<Scalar>,
    cs: r1cs::Prover<'a, 'b>,
}

pub struct RunProver {
    program: VecDeque<Instruction>,
}

impl<'a, 'b> Delegate<r1cs::Prover<'a, 'b>> for Prover<'a, 'b> {
    type RunType = RunProver;

    fn commit_variable(
        &mut self,
        com: &Commitment,
    ) -> Result<(CompressedRistretto, r1cs::Variable), VMError> {
        let (v, v_blinding) = match com {
            Commitment::Open(w) => {
                let val = match w.value {
                    ScalarWitness::Integer(s) => s.into(),
                    ScalarWitness::Scalar(s) => s,
                };
                (val, w.blinding)
            }
            Commitment::Closed(_) => return Err(VMError::WitnessMissing),
        };
        Ok(self.cs.commit(v, v_blinding))
    }

    fn verify_point_op<F>(&mut self, point_op_fn: F)
    where
        F: FnOnce() -> PointOp,
    {
        return;
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
        };

        let vm = VM::new(
            version,
            mintime,
            maxtime,
            RunProver::new(&program),
            &mut prover,
        );

        let (txid, _) = vm.run()?;

        // Sign txid
        let mut signtx_transcript = Transcript::new(b"ZkVM.signtx");
        signtx_transcript.commit_bytes(b"txid", &txid.0);
        let signature = Signature::sign_aggregated(&mut signtx_transcript, &prover.signtx_keys);

        // Generate the R1CS proof
        let proof = prover.cs.prove().map_err(|_| VMError::InvalidR1CSProof)?;

        // Encode program into bytecode

        // TBD: determine program capacity
        let mut bytecode = Vec::new();

        program
            .iter()
            .map(|p| p.encode())
            .for_each(|mut v| bytecode.append(&mut v));

        Ok(Tx {
            version,
            mintime,
            maxtime,
            signature,
            proof,
            program: bytecode,
        })
    }
}

impl RunProver {
    fn new(program: &Vec<Instruction>) -> Self {
        RunProver {
            program: program.clone().into(),
        }
    }
}

impl RunTrait for RunProver {
    fn next_instruction(&mut self) -> Result<Option<Instruction>, VMError> {
        Ok(self.program.pop_front())
    }
}
