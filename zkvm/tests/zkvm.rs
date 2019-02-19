use bulletproofs::r1cs;
use bulletproofs::{BulletproofGens, PedersenGens};
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use std::collections::VecDeque;

use zkvm::*;

// Take some key as a param
fn issue_contract(qty: u64, flv: Scalar, pred: &Predicate) -> Vec<Instruction> {
    vec![
        // pushdata qty [qty]
        // TBD: fix implicit type conversions to avoid this nightmare
        Instruction::Push(Data::Witness(DataWitness::Commitment(Box::new(
            Commitment::Open(Box::new(CommitmentWitness::from_secret(qty))),
        )))),
        // stack: qty-var
        Instruction::Var,
        // stack: flv, qty-var
        Instruction::Push(Data::Witness(DataWitness::Commitment(Box::new(
            Commitment::Open(Box::new(CommitmentWitness::unblinded(flv))),
        )))),
        // stack: flv-var, qty-var
        Instruction::Var,
        // stack: pred, flv-var, qty-var
        Instruction::Push(pred.clone().into()),
        // stack: issue-contract
        Instruction::Issue,
        // stack: pred, issue-contract
        Instruction::Push(pred.clone().into()),
        // stack: nonce-contract, issue-contract
        Instruction::Nonce,
        // stack: issue-contract
        Instruction::Signtx,
        // stack: issue-payload...
        Instruction::Signtx,
        // stack: pred, issue-payload...
        Instruction::Push(pred.clone().into()),
        // stack: empty
        Instruction::Output(1),
    ]
}

#[test]
fn issue() {
    let (tx, txid) = {
        // Random predicate
        let pred = match Predicate::from_witness(PredicateWitness::Key(Scalar::random(
            &mut rand::thread_rng(),
        ))) {
            Err(_) => return assert!(false),
            Ok(x) => x,
        };

        // Generate flavor scalar
        let mut t = Transcript::new(b"ZkVM.issue");
        t.commit_bytes(b"predicate", pred.point().as_bytes());
        let flavor = t.challenge_scalar(b"flavor");

        let program = issue_contract(1u64, flavor, &pred);

        let bp_gens = BulletproofGens::new(64, 1);
        let txresult = Prover::build_tx(program, 0u64, 0u64, 0u64, &bp_gens);
        let (tx, txid, txlog) = match txresult {
            Err(err) => return assert!(false, err.to_string()),
            Ok(x) => x,
        };
        (tx, txid)
    };

    // Verify tx
    let bp_gens = BulletproofGens::new(64, 1);
    match Verifier::verify_tx(tx, &bp_gens) {
        Err(err) => return assert!(false, err.to_string()),
        Ok(_) => return,
    };
}
