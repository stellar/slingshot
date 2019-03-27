use bulletproofs::{BulletproofGens, PedersenGens};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_COMPRESSED;
use curve25519_dalek::scalar::Scalar;
use hex;

use zkvm::{
    Anchor, Commitment, Contract, Data, Output, PortableItem, Predicate, Program, Prover,
    Signature, TxHeader, TxID, VMError, Value, Verifier,
};

// TODO(vniu): move builder convenience functions into separate crate,
// and refactor tests and Token
trait ProgramHelper {
    fn issue_helper(
        &mut self,
        qty: u64,
        flv: Scalar,
        issuance_pred: Predicate,
        nonce_pred: Predicate,
    ) -> &mut Self;

    fn input_helper(&mut self, qty: u64, flv: Scalar, pred: Predicate) -> &mut Self;

    fn cloak_helper(&mut self, input_count: usize, outputs: Vec<(u64, Scalar)>) -> &mut Self;

    fn output_helper(&mut self, pred: Predicate) -> &mut Self;
}

impl ProgramHelper for Program {
    fn issue_helper(
        &mut self,
        qty: u64,
        flv: Scalar,
        issuance_pred: Predicate,
        nonce_pred: Predicate,
    ) -> &mut Self {
        let dummy_block_id = Data::Opaque([0xffu8; 32].to_vec());
        self.push(nonce_pred)
            .push(dummy_block_id)
            .nonce()
            .sign_tx() // stack is clean
            .push(Commitment::blinded_with_factor(qty, Scalar::from(1u64))) // stack: qty
            .var() // stack: qty-var
            .push(Commitment::unblinded(flv)) // stack: qty-var, flv
            .var() // stack: qty-var, flv-var
            .push(Data::default()) // stack: qty-var, flv-var, data
            .push(issuance_pred) // stack: qty-var, flv-var, data, pred
            .issue() // stack: issue-contract
            .sign_tx(); // stack: issued-value
        self
    }

    fn input_helper(&mut self, qty: u64, flv: Scalar, pred: Predicate) -> &mut Self {
        let prev_output = make_output(qty, flv, pred);
        self.push(Output::new(prev_output)) // stack: input-data
            .input() // stack: input-contract
            .sign_tx(); // stack: input-value
        self
    }

    fn cloak_helper(&mut self, input_count: usize, outputs: Vec<(u64, Scalar)>) -> &mut Self {
        let output_count = outputs.len();

        for (qty, flv) in outputs {
            self.push(Commitment::blinded(qty));
            self.push(Commitment::blinded(flv));
        }
        self.cloak(input_count, output_count);
        self
    }

    fn output_helper(&mut self, pred: Predicate) -> &mut Self {
        // stack: output
        self.push(pred); // stack: output, pred
        self.output(1); // stack: empty
        self
    }
}

/// Generates the given number of signing key Predicates, returning
/// the Predicates and the secret signing keys.
fn generate_predicates(pred_num: usize) -> (Vec<Predicate>, Vec<Scalar>) {
    let gens = PedersenGens::default();

    let scalars: Vec<Scalar> = (0..pred_num)
        .into_iter()
        .map(|s| Scalar::from(s as u64))
        .collect();

    let predicates: Vec<Predicate> = scalars
        .iter()
        .map(|s| Predicate::Key((s * gens.B).compress().into()))
        .collect();

    (predicates, scalars)
}

/// Returns the secret Scalar and Predicate used to issue
/// a flavor, along with the flavor Scalar.
fn make_flavor() -> (Scalar, Predicate, Scalar) {
    let gens = PedersenGens::default();
    let scalar = Scalar::from(100u64);
    let predicate = Predicate::Key((scalar * gens.B).compress().into());
    let flavor = Value::issue_flavor(&predicate, Data::default());
    (scalar, predicate, flavor)
}

/// Creates an Output contract with given quantity, flavor, and predicate.
fn make_output(qty: u64, flv: Scalar, pred: Predicate) -> Contract {
    let anchor = Anchor::nonce(
        [0u8; 32],
        &Predicate::Opaque(RISTRETTO_BASEPOINT_COMPRESSED),
        0,
    );
    Contract {
        anchor,
        payload: vec![PortableItem::Value(Value {
            qty: Commitment::blinded(qty),
            flv: Commitment::blinded(flv),
        })],
        predicate: pred,
    }
}

fn build_and_verify(program: Program, keys: &Vec<Scalar>) -> Result<TxID, VMError> {
    let (tx, _, _) = {
        // Build tx
        let bp_gens = BulletproofGens::new(256, 1);
        let header = TxHeader {
            version: 0u64,
            mintime: 0u64,
            maxtime: 0u64,
        };
        let gens = PedersenGens::default();
        Prover::build_tx(program, header, &bp_gens, |t, verification_keys| {
            let signtx_keys: Vec<Scalar> = verification_keys
                .iter()
                .filter_map(|vk| {
                    for k in keys {
                        if (k * gens.B).compress() == vk.0 {
                            return Some(*k);
                        }
                    }
                    None
                })
                .collect();
            Signature::sign_aggregated(t, &signtx_keys)
        })?
    };

    // Verify tx
    let bp_gens = BulletproofGens::new(256, 1);

    let vtx = Verifier::verify_tx(tx, &bp_gens)?;
    Ok(vtx.id)
}

fn issue_contract(
    qty: u64,
    flv: Scalar,
    issuance_pred: Predicate,
    nonce_pred: Predicate,
    output_pred: Predicate,
) -> Program {
    Program::build(|p| {
        p.issue_helper(qty, flv, issuance_pred, nonce_pred) // stack: issued-val
            .output_helper(output_pred) // stack: empty
    })
}

#[test]
fn issue() {
    // Generate predicates
    let (predicates, mut scalars) = generate_predicates(2);
    let (issuance_scalar, issuance_pred, flavor) = make_flavor();
    scalars.push(issuance_scalar);

    let correct_program = issue_contract(
        1u64,
        flavor,
        issuance_pred,
        predicates[0].clone(), // nonce predicate
        predicates[1].clone(), // output predicate
    );

    match build_and_verify(correct_program, &scalars) {
        Err(err) => return assert!(false, err.to_string()),
        Ok(txid) => {
            // Check txid
            assert_eq!(
                "316f835973819a8cf6219010faf712bd17a1fe6fa2cc6350e4d96483b2065d82",
                hex::encode(txid.0)
            );
        }
    }

    let wrong_program = issue_contract(
        1u64,
        flavor,
        predicates[0].clone(), // WRONG issuance predicate
        predicates[0].clone(), // nonce predicate
        predicates[1].clone(), // output predicate
    );

    if build_and_verify(wrong_program, &scalars).is_ok() {
        panic!("Issuing with wrong issuance predicate should fail, but didn't");
    }
}

fn spend_1_1_contract(
    input: u64,
    output: u64,
    flv: Scalar,
    input_pred: Predicate,
    output_pred: Predicate,
) -> Program {
    Program::build(|p| {
        p.input_helper(input, flv, input_pred)
            .cloak_helper(1, vec![(output, flv)])
            .output_helper(output_pred)
    })
}

#[test]
fn spend_1_1() {
    // Generate predicates and flavor
    let (predicates, scalars) = generate_predicates(2);
    let flavor = Scalar::from(1u64);

    let correct_program = spend_1_1_contract(
        10u64,
        10u64,
        flavor,
        predicates[0].clone(), // input predicate
        predicates[1].clone(), // output predicate
    );

    match build_and_verify(correct_program, &scalars) {
        Err(err) => panic!(err.to_string()),
        _ => (),
    }

    let wrong_program = spend_1_1_contract(
        5u64,
        10u64,
        flavor,
        predicates[0].clone(), // input predicate
        predicates[1].clone(), // output predicate
    );

    if build_and_verify(wrong_program, &scalars).is_ok() {
        panic!("Input $5, output $10 should have failed but didn't");
    }
}

fn spend_1_2_contract(
    input: u64,
    output_1: u64,
    output_2: u64,
    flv: Scalar,
    input_pred: Predicate,
    output_1_pred: Predicate,
    output_2_pred: Predicate,
) -> Program {
    Program::build(|p| {
        p.input_helper(input, flv, input_pred) // stack: input
            .cloak_helper(1, vec![(output_1, flv), (output_2, flv)]) // stack: output-1, output-2
            .output_helper(output_2_pred) // stack: output-1
            .output_helper(output_1_pred) // stack: empty
    })
}

#[test]
fn spend_1_2() {
    // Generate predicates and flavor
    let (predicates, scalars) = generate_predicates(3);
    let flavor = Scalar::from(1u64);

    let correct_program = spend_1_2_contract(
        10u64,
        9u64,
        1u64,
        flavor,
        predicates[0].clone(), // input predicate
        predicates[1].clone(), // output 1 predicate
        predicates[2].clone(), // output 2 predicate
    );

    match build_and_verify(correct_program, &scalars) {
        Err(err) => assert!(false, err.to_string()),
        _ => (),
    }

    let wrong_program = spend_1_2_contract(
        10u64,
        11u64,
        1u64,
        flavor,
        predicates[0].clone(), // input predicate
        predicates[1].clone(), // output 1 predicate
        predicates[2].clone(), // output 2 predicate
    );

    if build_and_verify(wrong_program, &scalars).is_ok() {
        panic!("Input $10, output $11 and $1 should have failed but didn't");
    }
}

fn spend_2_1_contract(
    input_1: u64,
    input_2: u64,
    output: u64,
    flv: Scalar,
    input_1_pred: Predicate,
    input_2_pred: Predicate,
    output_pred: Predicate,
) -> Program {
    Program::build(|p| {
        p.input_helper(input_1, flv, input_1_pred) // stack: input-1
            .input_helper(input_2, flv, input_2_pred) // stack: input-1, input-2
            .cloak_helper(2, vec![(output, flv)]) // stack: output
            .output_helper(output_pred) // stack: empty
    })
}

#[test]
fn spend_2_1() {
    // Generate predicates and flavor
    let (predicates, scalars) = generate_predicates(3);
    let flavor = Scalar::from(1u64);

    let correct_program = spend_2_1_contract(
        6u64,
        4u64,
        10u64,
        flavor,
        predicates[0].clone(), // input 1 predicate
        predicates[1].clone(), // input 2 predicate
        predicates[2].clone(), // output predicate
    );

    match build_and_verify(correct_program, &scalars) {
        Err(err) => assert!(false, err.to_string()),
        _ => (),
    }

    let wrong_program = spend_2_1_contract(
        6u64,
        4u64,
        11u64,
        flavor,
        predicates[0].clone(), // input 1 predicate
        predicates[1].clone(), // input 2 predicate
        predicates[2].clone(), // output predicate
    );

    if build_and_verify(wrong_program, &scalars).is_ok() {
        panic!("Input $6 and $4, output $11 and $1 should have failed but didn't");
    }
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
) -> Program {
    Program::build(|p| {
        p.input_helper(input_1, flv, input_1_pred) // stack: input-1
            .input_helper(input_2, flv, input_2_pred) // stack: input-1, input-2
            .cloak_helper(2, vec![(output_1, flv), (output_2, flv)]) // stack: output-1, output-2
            .output_helper(output_2_pred) // stack: output-1
            .output_helper(output_1_pred) // stack: empty
    })
}

#[test]
fn spend_2_2() {
    // Generate predicates and flavor
    let (predicates, scalars) = generate_predicates(4);
    let flavor = Scalar::from(1u64);

    let correct_program = spend_2_2_contract(
        6u64,
        4u64,
        9u64,
        1u64,
        flavor,
        predicates[0].clone(), // input 1 predicate
        predicates[1].clone(), // input 2 predicate
        predicates[2].clone(), // output 1 predicate
        predicates[3].clone(), // output 2 predicate
    );

    match build_and_verify(correct_program, &scalars) {
        Err(err) => assert!(false, err.to_string()),
        _ => (),
    }

    let wrong_program = spend_2_2_contract(
        6u64,
        4u64,
        11u64,
        1u64,
        flavor,
        predicates[0].clone(), // input 1 predicate
        predicates[1].clone(), // input 2 predicate
        predicates[2].clone(), // output 1 predicate
        predicates[3].clone(), // output 2 predicate
    );

    if build_and_verify(wrong_program, &scalars).is_ok() {
        panic!("Input $6 and $4, output $11 and $1 should have failed but didn't");
    }
}

fn issue_and_spend_contract(
    issue_qty: u64,
    input_qty: u64,
    output_1: u64,
    output_2: u64,
    flv: Scalar,
    issuance_pred: Predicate,
    nonce_pred: Predicate,
    input_pred: Predicate,
    output_1_pred: Predicate,
    output_2_pred: Predicate,
) -> Program {
    Program::build(|p| {
        p.issue_helper(issue_qty, flv, issuance_pred, nonce_pred) // stack: issued-val
            .input_helper(input_qty, flv, input_pred) // stack: issued-val, input-val
            .cloak_helper(2, vec![(output_1, flv), (output_2, flv)]) // stack: output-1, output-2
            .output_helper(output_2_pred) // stack: output-1
            .output_helper(output_1_pred) // stack: empty
    })
}

#[test]
fn issue_and_spend() {
    // Generate predicates and flavor
    let (predicates, mut scalars) = generate_predicates(4);
    let (issuance_scalar, issuance_pred, flavor) = make_flavor();
    scalars.push(issuance_scalar);

    let correct_program = issue_and_spend_contract(
        4u64,
        6u64,
        9u64,
        1u64,
        flavor,
        issuance_pred.clone(),
        predicates[0].clone(), // nonce predicate
        predicates[1].clone(), // input predicate
        predicates[2].clone(), // output 1 predicate
        predicates[3].clone(), // output 2 predicate
    );

    match build_and_verify(correct_program, &scalars) {
        Err(err) => assert!(false, err.to_string()),
        _ => (),
    }

    let wrong_program = issue_and_spend_contract(
        4u64,
        6u64,
        11u64,
        1u64,
        flavor,
        issuance_pred,
        predicates[0].clone(), // nonce predicate
        predicates[1].clone(), // input predicate
        predicates[2].clone(), // output 1 predicate
        predicates[3].clone(), // output 2 predicate
    );

    if build_and_verify(wrong_program, &scalars).is_ok() {
        panic!("Issue $6 and input $4, output $11 and $1 should have failed but didn't");
    }
}


