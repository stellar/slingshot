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
        // var [qty var]
        Instruction::Var,
        // pushdata flv [qty var] [flv]
        Instruction::Push(Data::Witness(DataWitness::Commitment(Box::new(
            Commitment::Open(Box::new(CommitmentWitness::from_secret(flv))),
        )))),
        // var [qty var] [flv var]
        Instruction::Var,
        // pushdata predicate [qty var] [flv var] [pred]
        Instruction::Push(pred.clone().into()),
        // issue [c:issue]
        Instruction::Issue,
        // pushdata predicate [c:issue] [pred]
        Instruction::Push(pred.clone().into()),
        // nonce [c:issue] [c:nonce]
        Instruction::Nonce,
        // signtx [c:issue]
        Instruction::Signtx,
        // signtx [...payload]
        Instruction::Signtx,
        // pushdata predicate [...payload] [pred]
        Instruction::Push(pred.clone().into()),
        // output:1
        Instruction::Output(1),
    ]
}

// TBD: define test helpers similar to cloak for proving + verifying

#[test]
fn issue() {
    let (tx, txid) = {
        let privkey = Scalar::random(&mut rand::thread_rng());

        let predicate = match Predicate::from_witness(PredicateWitness::Key(privkey)) {
            Err(_) => return assert!(false),
            Ok(x) => x,
        };

        let program = issue_contract(1u64, 888u64.into(), &predicate);

        let bp_gens = BulletproofGens::new(64, 1);
        let txresult = Prover::build_tx(program, 0u64, 0u64, 0u64, &bp_gens);
        let (tx, txid, txlog) = match txresult {
            Err(err) => return assert!(false, err.to_string()),
            Ok(x) => x,
        };
        (tx, txid)
    };

    println!("prover txid {:?}", txid);

    // verify
    let bp_gens = BulletproofGens::new(64, 1);
    match Verifier::verify_tx(tx, &bp_gens) {
        Err(err) => return assert!(false, err.to_string()),
        Ok(_) => return,
    };
}
