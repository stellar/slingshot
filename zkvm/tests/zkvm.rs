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

fn input_helper(qty: u64, flv: Scalar, pred: Predicate) -> Vec<Instruction> {
    vec![
        Instruction::Push(
            Input::new(
                vec![(
                    Commitment::from(CommitmentWitness::blinded(qty)),
                    Commitment::from(CommitmentWitness::blinded(flv)),
                )],
                pred,
                TxID([0; 32]),
            )
            .into(),
        ), // stack: input-data
        Instruction::Input,  // stack: input-contract
        Instruction::Signtx, // stack: input-value
    ]
}

fn cloak_helper(input_count: usize, outputs: Vec<(u64, Scalar)>) -> Vec<Instruction> {
    let output_count = outputs.len();
    let mut instructions = vec![];

    for (qty, flv) in outputs {
        instructions.push(Instruction::Push(
            Commitment::from(CommitmentWitness::blinded(qty)).into(),
        ));
        instructions.push(Instruction::Push(
            Commitment::from(CommitmentWitness::blinded(flv)).into(),
        ));
    }
    instructions.push(Instruction::Cloak(input_count, output_count));
    instructions
}

fn output_helper(pred: Predicate) -> Vec<Instruction> {
    vec![
        // stack: output
        Instruction::Push(pred.into()), // stack: output, pred
        Instruction::Output(1),         // stack: empty
    ]
}

fn predicate_helper(
    pred_num: usize,
    flavor_num: usize,
) -> (Vec<Predicate>, Vec<(Predicate, Scalar)>) {
    unimplemented!();
}

fn spend_2_2_contract(
    input_1: u64,
    input_2: u64,
    output_1: u64,
    output_2: u64,
    flv: Scalar,
    input_1_pred: Predicate,
    input_2_pred: Predicate,
    output_1_pred: Predicate,
    output_2_pred: Predicate,
) -> Vec<Instruction> {
    let mut instructions = vec![];
    instructions.append(&mut input_helper(input_1, flv, input_1_pred));
    instructions.append(&mut input_helper(input_2, flv, input_2_pred));

    instructions.append(&mut cloak_helper(2, vec![(output_1, flv), (output_2, flv)]));

    instructions.append(&mut output_helper(output_2_pred));
    instructions.append(&mut output_helper(output_1_pred));

    instructions
}

#[test]
fn spend_2_2() {
    let (tx, _txid, txlog) = {
        // Generate predicates
        let input_1_pred =
            Predicate::from_witness(PredicateWitness::Key(Scalar::from(0u64))).unwrap();
        let input_2_pred =
            Predicate::from_witness(PredicateWitness::Key(Scalar::from(1u64))).unwrap();
        let output_1_pred =
            Predicate::from_witness(PredicateWitness::Key(Scalar::from(2u64))).unwrap();
        let output_2_pred =
            Predicate::from_witness(PredicateWitness::Key(Scalar::from(3u64))).unwrap();
        let issuance_pred =
            Predicate::from_witness(PredicateWitness::Key(Scalar::from(4u64))).unwrap();

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
            input_1_pred,
            input_2_pred,
            output_1_pred,
            output_2_pred,
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
    output_1_pred: Predicate,
    output_2_pred: Predicate,
) -> Vec<Instruction> {
    let mut instructions = vec![];
    instructions.append(&mut input_helper(input, flv, input_pred));

    instructions.append(&mut cloak_helper(1, vec![(output_1, flv), (output_2, flv)]));

    instructions.append(&mut output_helper(output_2_pred));
    instructions.append(&mut output_helper(output_1_pred));

    instructions
}

#[test]
fn spend_1_2() {
    let (tx, _txid, txlog) = {
        // Generate predicates
        let issuance_pred =
            Predicate::from_witness(PredicateWitness::Key(Scalar::from(0u64))).unwrap();
        let input_pred =
            Predicate::from_witness(PredicateWitness::Key(Scalar::from(1u64))).unwrap();
        let output_1_pred =
            Predicate::from_witness(PredicateWitness::Key(Scalar::from(2u64))).unwrap();
        let output_2_pred =
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
            input_pred,
            output_1_pred,
            output_2_pred,
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
