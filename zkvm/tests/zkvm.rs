use bulletproofs::BulletproofGens;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;

use zkvm::*;

fn issue_contract(
    qty: u64,
    flv: Scalar,
    issuance_pred: &Predicate,
    nonce_pred: &Predicate,
    recipient_pred: &Predicate,
) -> Vec<Instruction> {
    vec![
        Instruction::Push(Commitment::from(CommitmentWitness::blinded(qty)).into()), // stack: qty
        Instruction::Var, // stack: qty-var
        Instruction::Push(Commitment::from(CommitmentWitness::unblinded(flv)).into()), // stack: qty-var, flv
        Instruction::Var,                                 // stack: qty-var, flv-var
        Instruction::Push(issuance_pred.clone().into()),  // stack: qty-var, flv-var, pred
        Instruction::Issue,                               // stack: issue-contract
        Instruction::Push(nonce_pred.clone().into()),     // stack: issue-contract, pred
        Instruction::Nonce,                               // stack: issue-contract, nonce-contract
        Instruction::Signtx,                              // stack: issue-contract
        Instruction::Signtx,                              // stack: issued-value
        Instruction::Push(recipient_pred.clone().into()), // stack: issued-value, pred
        Instruction::Output(1),                           // stack: empty
    ]
}

#[test]
fn issue() {
    let (tx, _, txlog) = {
        let issuance_pred = Predicate::from_witness(PredicateWitness::Key(Scalar::random(
            &mut rand::thread_rng(),
        )))
        .unwrap();

        let nonce_pred = Predicate::from_witness(PredicateWitness::Key(Scalar::random(
            &mut rand::thread_rng(),
        )))
        .unwrap();

        let recipient_pred = Predicate::from_witness(PredicateWitness::Key(Scalar::random(
            &mut rand::thread_rng(),
        )))
        .unwrap();

        // Generate flavor scalar
        let mut t = Transcript::new(b"ZkVM.issue");
        t.commit_bytes(b"predicate", issuance_pred.point().as_bytes());
        let flavor = t.challenge_scalar(b"flavor");

        let program = issue_contract(1u64, flavor, &issuance_pred, &nonce_pred, &recipient_pred);

        let bp_gens = BulletproofGens::new(64, 1);
        // TBD: add TxHeader type to make this call more readable
        let txresult = Prover::build_tx(program, 0u64, 0u64, 0u64, &bp_gens);
        let (tx, txid, txlog) = match txresult {
            Err(err) => return assert!(false, err.to_string()),
            Ok(x) => x,
        };
        (tx, txid, txlog)
    };

    // Verify tx
    let bp_gens = BulletproofGens::new(64, 1);
    match Verifier::verify_tx(tx, &bp_gens) {
        Err(err) => return assert!(false, err.to_string()),
        Ok(v) => {
            assert_eq!(v.log, txlog);
        }
    };
}
