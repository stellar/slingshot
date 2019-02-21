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
// - is it enough (for testing) to get the value from the issue contract? (how do we create a "utxo" in one tx?)
fn spend_2_2_contract(
    input_1: u64,
    input_2: u64,
    output_1: u64,
    output_2: u64,
    flv: Scalar,
    issuance_pred: Predicate,
    nonce_pred: Predicate,
    recipient_1_pred: Predicate,
    recipient_2_pred: Predicate,
) -> Vec<Instruction> {
    let mut instructions = vec![];
    instructions.append(&mut issue_helper(input_1, flv, issuance_pred.clone(), nonce_pred.clone())); // stack: issued-value-1
    instructions.append(&mut issue_helper(input_2, flv, issuance_pred, nonce_pred)); // stack: issued-value-1, issued-value-2

    instructions.push(Instruction::Push(
        Commitment::from(CommitmentWitness::blinded(output_1)).into(),
    )); // stack: issued-value-1, issued-value-2, output-1-quantity
    instructions.push(Instruction::Push(
        Commitment::from(CommitmentWitness::blinded(flv)).into(),
    )); // stack: issued-value-1, issued-value-2, output-1-quantity, output-1-flavor

    instructions.push(Instruction::Push(
        Commitment::from(CommitmentWitness::blinded(output_2)).into(),
    )); // stack: ... output-2-quantity
    instructions.push(Instruction::Push(
        Commitment::from(CommitmentWitness::blinded(flv)).into(),
    )); // stack: ... output-2-quantity, output-2-flavor

    instructions.push(Instruction::Cloak(2, 2)); // stack: output-1, output-2

    instructions.push(Instruction::Push(recipient_2_pred.clone().into())); // stack: issued-value-1, issued-value-2, recipient-2-pred
    instructions.push(Instruction::Output(1)); // stack: issued-value-1
    instructions.push(Instruction::Push(recipient_1_pred.clone().into())); // stack: issued-value-1, recipient-1-pred
    instructions.push(Instruction::Output(1)); // stack: empty

    instructions
}

#[test]
fn spend_2_2() {
    let (tx, _txid, txlog) = {
        // Generate predicates
        let issuance_pred =
            Predicate::from_witness(PredicateWitness::Key(Scalar::from(0u64))).unwrap();
        let nonce_pred =
            Predicate::from_witness(PredicateWitness::Key(Scalar::from(1u64))).unwrap();
        let recipient_1_pred =
            Predicate::from_witness(PredicateWitness::Key(Scalar::from(2u64))).unwrap();
        let recipient_2_pred =
            Predicate::from_witness(PredicateWitness::Key(Scalar::from(3u64))).unwrap();

        // Generate flavor scalar
        let mut t = Transcript::new(b"ZkVM.issue");
        t.commit_bytes(b"predicate", issuance_pred.point().as_bytes());
        let flavor = t.challenge_scalar(b"flavor");

        // Build program
        let program = spend_2_2_contract(
            6u64,
            4u64,
            9u64,
            1u64,
            flavor,
            &issuance_pred,
            &nonce_pred,
            &recipient_1_pred,
            &recipient_2_pred,
        );

        // Build tx
        let bp_gens = BulletproofGens::new(512, 1);
        // TBD: add TxHeader type to make this call more readable
        let txresult = Prover::build_tx(program, 0u64, 0u64, 0u64, &bp_gens);
        let (tx, txid, txlog) = match txresult {
            Err(err) => return assert!(false, err.to_string()),
            Ok(x) => x,
        };
        (tx, txid, txlog)
    };

    // Verify tx
    let bp_gens = BulletproofGens::new(512, 1);
    match Verifier::verify_tx(tx, &bp_gens) {
        Err(err) => return assert!(false, err.to_string()),
        Ok(v) => {
            assert_eq!(v.log, txlog);
        }
    };
}

fn spend_1_2_contract(
    input: u64,
    output_1: u64,
    output_2: u64,
    flv: Scalar,
    input_pred: Predicate,
    recipient_1_pred: Predicate,
    recipient_2_pred: Predicate,
) -> Vec<Instruction> {
    // TODO: just list all the instructions in one vector, instead of pushing
    vec![
        Instruction::Push(
            Input::new(
                vec![(
                    Commitment::from(CommitmentWitness::blinded(input)),
                    Commitment::from(CommitmentWitness::blinded(flv)),
                )],
                input_pred,
                TxID([0; 32]),
            )
            .into(),
        ), // stack: input-data
        Instruction::Input,  // stack: input-contract
        Instruction::Signtx, // stack: input-value
        Instruction::Push(Commitment::from(CommitmentWitness::blinded(output_1)).into()), // stack: input-value, output-1-quantity
        Instruction::Push(Commitment::from(CommitmentWitness::blinded(flv)).into()), // stack: input-value, output-1-quantity, output-1-flavor
        Instruction::Push(Commitment::from(CommitmentWitness::blinded(output_2)).into()), // stack: input-value, output-1-quantity, output-2-quantity
        Instruction::Push(Commitment::from(CommitmentWitness::blinded(flv)).into()), // stack: input-value, output-1-quantity, output-2-quantity, output-2-flavor
        Instruction::Cloak(1, 2), // stack: output-1, output-2
        Instruction::Push(recipient_2_pred.into()), // stack: output-1, output-2, recipient-2-pred
        Instruction::Output(1),   // stack: output-1
        Instruction::Push(recipient_1_pred.into()), // stack: output-1, recipient-1-pred
        Instruction::Output(1),   // stack: empty
    ]
}

#[test]
fn spend_1_2() {
    let (tx, _txid, txlog) = {
        // Generate predicates
        let issuance_pred =
            Predicate::from_witness(PredicateWitness::Key(Scalar::from(0u64))).unwrap();
        let recipient_1_pred =
            Predicate::from_witness(PredicateWitness::Key(Scalar::from(2u64))).unwrap();
        let recipient_2_pred =
            Predicate::from_witness(PredicateWitness::Key(Scalar::from(3u64))).unwrap();

        // Generate flavor scalar
        let mut t = Transcript::new(b"ZkVM.issue");
        t.commit_bytes(b"predicate", issuance_pred.point().as_bytes());
        let flavor = t.challenge_scalar(b"flavor");

        // Build program
        let program = spend_1_2_contract(
            10u64,
            9u64,
            1u64,
            flavor,
            issuance_pred,
            recipient_1_pred,
            recipient_2_pred,
        );

        // Build tx
        let bp_gens = BulletproofGens::new(256, 1);
        // TBD: add TxHeader type to make this call more readable
        let txresult = Prover::build_tx(program, 0u64, 0u64, 0u64, &bp_gens);
        let (tx, txid, txlog) = match txresult {
            Err(err) => return assert!(false, err.to_string()),
            Ok(x) => x,
        };
        (tx, txid, txlog)
    };

    // Verify tx
    let bp_gens = BulletproofGens::new(256, 1);
    match Verifier::verify_tx(tx, &bp_gens) {
        Err(err) => return assert!(false, err.to_string()),
        Ok(v) => {
            assert_eq!(v.log, txlog);
        }
    };
}
