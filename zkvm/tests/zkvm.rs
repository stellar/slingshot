use bulletproofs::BulletproofGens;
use curve25519_dalek::scalar::Scalar;
use hex;
use merlin::Transcript;

use zkvm::*;

fn issue_contract(
    qty: u64,
    flv: Scalar,
    issuance_pred: Predicate,
    nonce_pred: Predicate,
    recipient_pred: Predicate,
) -> Vec<Instruction> {
    vec![
        Instruction::Push(
            Commitment::from(CommitmentWitness {
                value: qty.into(),
                blinding: Scalar::from(1u64),
            })
            .into(),
        ), // stack: qty
        Instruction::Var, // stack: qty-var
        Instruction::Push(Commitment::from(CommitmentWitness::unblinded(flv)).into()), // stack: qty-var, flv
        Instruction::Var,                         // stack: qty-var, flv-var
        Instruction::Push(issuance_pred.into()),  // stack: qty-var, flv-var, pred
        Instruction::Issue,                       // stack: issue-contract
        Instruction::Push(nonce_pred.into()),     // stack: issue-contract, pred
        Instruction::Nonce,                       // stack: issue-contract, nonce-contract
        Instruction::Signtx,                      // stack: issue-contract
        Instruction::Signtx,                      // stack: issued-value
        Instruction::Push(recipient_pred.into()), // stack: issued-value, pred
        Instruction::Output(1),                   // stack: empty
    ]
}

#[test]
fn issue() {
    let (tx, txid, txlog) = {
        // Generate predicates
        let issuance_pred = PredicateWitness::Key(Scalar::from(0u64)).to_predicate();
        let nonce_pred = PredicateWitness::Key(Scalar::from(1u64)).to_predicate();
        let recipient_pred = PredicateWitness::Key(Scalar::from(2u64)).to_predicate();

        // Generate flavor scalar
        let mut t = Transcript::new(b"ZkVM.issue");
        t.commit_bytes(b"predicate", issuance_pred.to_point().as_bytes());
        let flavor = t.challenge_scalar(b"flavor");

        // Build program
        let program = issue_contract(1u64, flavor, issuance_pred, nonce_pred, recipient_pred);

        // Build tx
        let bp_gens = BulletproofGens::new(64, 1);
        // TBD: add TxHeader type to make this call more readable
        let txresult = Prover::build_tx(program, 0u64, 0u64, 0u64, &bp_gens);
        let (tx, txid, txlog) = match txresult {
            Err(err) => return assert!(false, err.to_string()),
            Ok(x) => x,
        };
        (tx, txid, txlog)
    };

    // Check txid
    assert_eq!(
        "9d5c0c4f47b894bca9432a2ffbaf21303731cb08d8111e40b004264c3e20d35d",
        hex::encode(txid.0)
    );

    // Verify tx
    let bp_gens = BulletproofGens::new(64, 1);
    match Verifier::verify_tx(tx, &bp_gens) {
        Err(err) => return assert!(false, err.to_string()),
        Ok(v) => {
            assert_eq!(v.log, txlog);
        }
    };
}
