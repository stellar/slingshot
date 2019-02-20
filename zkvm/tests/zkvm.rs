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
    let mut instructions = issue_helper(qty, flv, issuance_pred, nonce_pred); // stack: issued-value
    instructions.push(Instruction::Push(recipient_pred.clone().into())); // stack: issued-value, pred
    instructions.push(Instruction::Output(1)); // stack: empty
    instructions
}

fn issue_helper(
    qty: u64,
    flv: Scalar,
    issuance_pred: Predicate,
    nonce_pred: Predicate,
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
    ]
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

// questions:
// - do we have to use separate nonce predicates for the two inputs (to ensure uniqueness if they're same qty?)
fn spend_2_2(
    input_1: u64,
    input_2: u64,
    _output_1: u64,
    _output_2: u64,
    flv: Scalar,
    issuance_pred: Predicate,
    nonce_pred: Predicate,
    recipient_1_pred: Predicate,
    recipient_2_pred: Predicate,
) -> Vec<Instruction> {
    let mut instructions = vec![];
    instructions.append(&mut issue_helper(input_1, flv, issuance_pred.clone(), nonce_pred.clone())); // stack: issued-value-1
    instructions.append(&mut issue_helper(input_2, flv, issuance_pred, nonce_pred)); // stack: issued-value-1, issued-value-2
                                                                                     // TODO: add cloak

    instructions.push(Instruction::Push(recipient_2_pred.clone().into())); // stack: issued-value-1, issued-value-2, recipient-2-pred
    instructions.push(Instruction::Output(1)); // stack: issued-value-1
    instructions.push(Instruction::Push(recipient_1_pred.clone().into())); // stack: issued-value-1, recipient-1-pred
    instructions.push(Instruction::Output(1)); // stack: empty

    instructions
}
