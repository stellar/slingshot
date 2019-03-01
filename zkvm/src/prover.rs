use bulletproofs::r1cs;
use bulletproofs::{BulletproofGens, PedersenGens};
use curve25519_dalek::ristretto::CompressedRistretto;
use merlin::Transcript;
use std::collections::VecDeque;

use crate::constraints::Commitment;
use crate::errors::VMError;
use crate::ops::Instruction;
use crate::point_ops::PointOp;
use crate::predicate::Predicate;
use crate::signature::{Signature, VerificationKey};
use crate::txlog::{TxID, TxLog};
use crate::vm::{Delegate, Tx, TxHeader, VM};

/// This is the entry point API for creating a transaction.
/// Prover passes the list of instructions through the VM,
/// creates an aggregated transaction signature (for `signtx` instruction),
/// creates a R1CS proof and returns a complete `Tx` object that can be published.
pub struct Prover<'a, 'b> {
    signtx_keys: Vec<VerificationKey>,
    cs: r1cs::Prover<'a, 'b>,
}

pub(crate) struct ProverRun {
    program: VecDeque<Instruction>,
}

impl<'a, 'b> Delegate<r1cs::Prover<'a, 'b>> for Prover<'a, 'b> {
    type RunType = ProverRun;

    fn commit_variable(
        &mut self,
        com: &Commitment,
    ) -> Result<(CompressedRistretto, r1cs::Variable), VMError> {
        let (v, v_blinding) = com.witness().ok_or(VMError::WitnessMissing)?;
        Ok(self.cs.commit(v.into(), v_blinding))
    }

    fn verify_point_op<F>(&mut self, _point_op_fn: F) -> Result<(), VMError>
    where
        F: FnOnce() -> PointOp,
    {
        Ok(())
    }

    fn process_tx_signature(&mut self, pred: Predicate) -> Result<(), VMError> {
        let k = pred.to_key()?;
        self.signtx_keys.push(k);
        Ok(())
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
    /// Builds a transaction with a given list of instructions and a `TxHeader`.
    /// Returns a transaction `Tx` along with its ID (`TxID`) and a transaction log (`TxLog`).
    /// Fails if the input program is malformed, or some witness data is missing.
    pub fn build_tx<'g, F>(
        program: Vec<Instruction>,
        header: TxHeader,
        bp_gens: &'g BulletproofGens,
        sign_tx_fn: F,
    ) -> Result<(Tx, TxID, TxLog), VMError>
    where
        F: FnOnce(&mut Transcript, &Vec<VerificationKey>) -> Signature,
    {
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
            header,
            ProverRun {
                program: program.into(),
            },
            &mut prover,
        );

        let (txid, txlog) = vm.run()?;

        // Sign txid
        // TBD: implement holistic Signer trait/interface for tx signing
        let mut signtx_transcript = Transcript::new(b"ZkVM.signtx");
        signtx_transcript.commit_bytes(b"txid", &txid.0);
        let signature = sign_tx_fn(&mut signtx_transcript, &prover.signtx_keys);

        // Generate the R1CS proof
        let proof = prover.cs.prove().map_err(|_| VMError::InvalidR1CSProof)?;

        Ok((
            Tx {
                header,
                signature,
                proof,
                program: bytecode,
            },
            txid,
            txlog,
        ))
    }
}
