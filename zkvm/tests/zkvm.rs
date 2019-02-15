use bulletproofs::r1cs;
use bulletproofs::{BulletproofGens, PedersenGens};
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use std::collections::VecDeque;

use zkvm::*;

// Take some key as a param
fn issue_contract(qty: Scalar, flv: Scalar, pred: &Predicate) -> Vec<Instruction> {
    vec![
        // TBD: replace with real scalars
        // pushdata qty
        Instruction::Push(Data::Witness(DataWitness::Scalar(Box::new(qty)))),
        // var
        Instruction::Var,
        // TBD: replace with real scalars
        // pushdata flv
        Instruction::Push(Data::Witness(DataWitness::Scalar(Box::new(flv)))),
        // var
        Instruction::Var,
        // Predicate
        Instruction::Push(Data::Witness(DataWitness::Predicate(Box::new(
            pred.clone(),
        )))),
        Instruction::Issue,
        // Predicate
        Instruction::Push(Data::Witness(DataWitness::Predicate(Box::new(
            pred.clone(),
        )))),
        // Nonce
        Instruction::Nonce,
        // Signtx
        Instruction::Signtx,
    ]
}

#[test]
fn issue() {
    let privkey = Scalar::random(&mut rand::thread_rng());
    let pubkey = VerificationKey::from_secret(&privkey);

    let predicate = match Predicate::from_witness(PredicateWitness::Key(privkey)) {
        Err(_) => return assert!(false),
        Ok(x) => x,
    };

    // pushdata qty
    // var
    // pushdata flv
    // var
    // pushdata pred <- pubkey to issue to
    // issue
    let program = issue_contract(Scalar::one(), Scalar::one(), &predicate);

    let bp_gens = BulletproofGens::new(64, 1);
    let txresult = Prover::build_tx(program, 0u64, 0u64, 0u64, &bp_gens);
    let (tx, txid, txlog) = match txresult {
        Err(err) => return assert!(false, err),
        Ok(x) => x,
    };
}
