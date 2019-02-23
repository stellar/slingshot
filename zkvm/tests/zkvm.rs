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
    let mut instructions = Program::new();
    instructions
        .push(Commitment::from(CommitmentWitness {
            value: qty.into(),
            blinding: Scalar::from(1u64),
        })) // stack: qty
        .var() // stack: qty-var
        .push(Commitment::from(CommitmentWitness::unblinded(flv))) // stack: qty-var, flv
        .var() // stack: qty-var, flv-var
        .push(issuance_pred) // stack: qty-var, flv-var, pred
        .issue() // stack: issue-contract
        .push(nonce_pred) // stack: issue-contract, pred
        .nonce() // stack: issue-contract, nonce-contract
        .sign_tx() // stack: issue-contract
        .sign_tx() // stack: issued-value
        .push(recipient_pred) // stack: issued-value, pred
        .output(1) // stack: empty
        .to_vec()
}

#[test]
fn issue() {
    let (tx, txid, txlog) = {
        // Generate predicates
        let issuance_pred = Predicate::from_signing_key(Scalar::from(0u64));
        let nonce_pred = Predicate::from_signing_key(Scalar::from(1u64));
        let recipient_pred = Predicate::from_signing_key(Scalar::from(2u64));

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
