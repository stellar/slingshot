use bulletproofs::r1cs;
use bulletproofs::r1cs::ConstraintSystem;
use bulletproofs::{BulletproofGens, PedersenGens};
use curve25519_dalek::ristretto::CompressedRistretto;
use merlin::Transcript;
use musig::VerificationKey;
use std::collections::VecDeque;

use crate::constraints::Commitment;
use crate::contract::ContractID;
use crate::encoding::Encodable;
use crate::errors::VMError;
use crate::ops::Instruction;
use crate::point_ops::PointOp;
use crate::predicate::Predicate;
use crate::program::{Program, ProgramItem};
use crate::tx::{TxHeader, UnsignedTx};
use crate::vm::{Delegate, VM};
/// This is the entry point API for creating a transaction.
/// Prover passes the list of instructions through the VM,
/// creates an aggregated transaction signature (for `signtx` instruction),
/// creates a R1CS proof and returns a complete `Tx` object that can be published.
pub struct Prover<'t, 'g> {
    // TBD: use Multikey as a witness thing
    signtx_items: Vec<(VerificationKey, ContractID)>,
    cs: r1cs::Prover<'t, 'g>,
}

pub(crate) struct ProverRun {
    program: VecDeque<Instruction>,
}

impl<'t, 'g> Delegate<r1cs::Prover<'t, 'g>> for Prover<'t, 'g> {
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

    fn process_tx_signature(
        &mut self,
        pred: Predicate,
        contract_id: ContractID,
    ) -> Result<(), VMError> {
        let k = pred.to_verification_key_witness()?;
        self.signtx_items.push((k, contract_id));
        Ok(())
    }

    fn next_instruction(
        &mut self,
        run: &mut Self::RunType,
    ) -> Result<Option<Instruction>, VMError> {
        Ok(run.program.pop_front())
    }

    fn new_run(&self, data: ProgramItem) -> Result<Self::RunType, VMError> {
        Ok(ProverRun {
            program: data.to_program()?.to_vec().into(),
        })
    }

    fn cs(&mut self) -> &mut r1cs::Prover<'t, 'g> {
        &mut self.cs
    }
}

impl<'t, 'g> Prover<'t, 'g> {
    /// Builds a transaction with a given list of instructions and a `TxHeader`.
    /// Returns a transaction `Tx` along with its ID (`TxID`) and a transaction log (`TxLog`).
    /// Fails if the input program is malformed, or some witness data is missing.
    pub fn build_tx(
        program: Program,
        header: TxHeader,
        bp_gens: &BulletproofGens,
    ) -> Result<UnsignedTx, VMError> {
        // Prepare the constraint system
        let mut r1cs_transcript = Transcript::new(b"ZkVM.r1cs");
        let pc_gens = PedersenGens::default();
        let cs = r1cs::Prover::new(&pc_gens, &mut r1cs_transcript);

        // Serialize the tx program
        let mut bytecode = Vec::new();
        program.encode(&mut bytecode);

        let mut prover = Prover {
            signtx_items: Vec::new(),
            cs,
        };

        let vm = VM::new(
            header,
            ProverRun {
                program: program.to_vec().into(),
            },
            &mut prover,
        );

        let (txid, txlog) = vm.run()?;

        // Commit txid so that the proof is bound to the entire transaction, not just the constraint system.
        prover.cs.transcript().commit_bytes(b"ZkVM.txid", &txid.0);

        // Generate the R1CS proof
        let proof = prover
            .cs
            .prove(bp_gens)
            .map_err(|_| VMError::InvalidR1CSProof)?;

        // Defer signing of the transaction to the UnsignedTx API.
        Ok(UnsignedTx {
            header,
            program: bytecode,
            proof,
            txid,
            txlog,
            signing_instructions: prover.signtx_items,
        })
    }
}
