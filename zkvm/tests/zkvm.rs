use bulletproofs::BulletproofGens;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_COMPRESSED, ristretto::CompressedRistretto, traits::Identity,
};
use merlin::Transcript;
use musig::{Multisignature, Signature};
use rand::Rng;

use zkvm::{
    Anchor, Commitment, Contract, PortableItem, Predicate, PredicateTree, Program, Prover, String,
    TxHeader, TxID, TxLog, VMError, Value,
};

// TODO(vniu): move builder convenience functions into separate crate,
// and refactor tests and Token
trait ProgramHelper {
    fn issue_helper(&mut self, qty: u64, flv: Scalar, issuance_pred: Predicate) -> &mut Self;

    fn input_helper(&mut self, qty: u64, flv: Scalar, pred: Predicate) -> &mut Self;

    fn cloak_helper(&mut self, input_count: usize, outputs: Vec<(u64, Scalar)>) -> &mut Self;

    fn output_helper(&mut self, pred: Predicate) -> &mut Self;
}

impl ProgramHelper for Program {
    fn issue_helper(&mut self, qty: u64, flv: Scalar, issuance_pred: Predicate) -> &mut Self {
        self.push(Commitment::blinded_with_factor(qty, Scalar::from(1u64))) // stack: qty
            .commit() // stack: qty-var
            .push(Commitment::unblinded(flv)) // stack: qty-var, flv
            .commit() // stack: qty-var, flv-var
            .push(String::default()) // stack: qty-var, flv-var, data
            .push(issuance_pred) // stack: qty-var, flv-var, data, pred
            .issue() // stack: issue-contract
            .signtx(); // stack: issued-value
        self
    }

    fn input_helper(&mut self, qty: u64, flv: Scalar, pred: Predicate) -> &mut Self {
        let prev_output = make_output(qty, flv, pred);
        self.push(prev_output) // stack: input-data
            .input() // stack: input-contract
            .signtx(); // stack: input-value
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

/// Generates a secret Scalar / key Predicate pair
fn generate_predicate(i: u64) -> Predicate {
    Predicate::with_witness(Scalar::from(i))
}

fn predicate_privkey(pred: &Predicate) -> Scalar {
    // If we stored the simple scalar - that's the privkey
    if let Some(privkey) = pred.verification_key_witness::<Scalar>() {
        return *privkey;
    // If we stored the predicate tree, then take the scalar from its inner predicate
    // and apply adjustment factor.
    } else if let Some(tree) = pred.verification_key_witness::<PredicateTree>() {
        if let Some(privkey) = tree.inner_predicate().verification_key_witness::<Scalar>() {
            return privkey + tree.adjustment_factor();
        } else {
        }
    }
    panic!("Expect witness in the Predicate in these tests");
}

/// Returns the secret Scalar and Predicate used to issue
/// a flavor, along with the flavor Scalar.
fn make_flavor() -> (Predicate, Scalar) {
    let predicate = Predicate::with_witness(Scalar::from(100u64));
    let flavor = Value::issue_flavor(&predicate, String::default());
    (predicate, flavor)
}

/// Creates an Output contract with given quantity, flavor, and predicate.
fn make_output(qty: u64, flv: Scalar, predicate: Predicate) -> Contract {
    Contract {
        predicate,
        payload: vec![PortableItem::Value(Value {
            qty: Commitment::blinded(qty),
            flv: Commitment::blinded(flv),
        })],
        anchor: Anchor::from_raw_bytes([0u8; 32]),
    }
}

fn build_and_verify(program: Program) -> Result<(TxID, TxLog), VMError> {
    let (txlog, tx) = {
        // Build tx
        let bp_gens = BulletproofGens::new(256, 1);
        let header = TxHeader {
            version: 0u64,
            mintime_ms: 0u64,
            maxtime_ms: 0u64,
        };
        let utx = Prover::build_tx(program, header, &bp_gens)?;

        let sig = if utx.signing_instructions.len() == 0 {
            Signature {
                R: CompressedRistretto::identity(),
                s: Scalar::zero(),
            }
        } else {
            // find all the secret scalars for the pubkeys used in the VM
            let privkeys: Vec<Scalar> = utx
                .signing_instructions
                .iter()
                .map(|(predicate, _msg)| predicate_privkey(predicate))
                .collect();

            let mut signtx_transcript = Transcript::new(b"ZkVM.signtx");
            signtx_transcript.append_message(b"txid", &utx.txid.0);
            Signature::sign_multi(
                privkeys,
                utx.signing_instructions
                    .iter()
                    .map(|(p, m)| (p.verification_key(), m))
                    .collect(),
                &mut signtx_transcript,
            )
            .unwrap()
        };

        (utx.txlog.clone(), utx.sign(sig))
    };

    // Verify tx
    let bp_gens = BulletproofGens::new(256, 1);

    let vtx = tx.verify(&bp_gens)?;
    Ok((vtx.id, txlog))
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
            .output_helper(output_pred);
    })
}

#[test]
fn spend_1_1() {
    // Generate predicates and flavor
    let pred1 = generate_predicate(1);
    let pred2 = generate_predicate(2);
    let flavor = Scalar::from(1u64);

    let correct_program = spend_1_1_contract(
        10u64,
        10u64,
        flavor,
        pred1.clone(), // input predicate
        pred2.clone(), // output predicate
    );

    match build_and_verify(correct_program) {
        Err(err) => panic!(err.to_string()),
        _ => (),
    }

    let wrong_program = spend_1_1_contract(
        5u64,
        10u64,
        flavor,
        pred1.clone(), // input predicate
        pred2.clone(), // output predicate
    );

    if build_and_verify(wrong_program).is_ok() {
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
            .output_helper(output_1_pred) // stack: output-1
            .output_helper(output_2_pred); // stack: empty
    })
}

#[test]
fn spend_1_2() {
    // Generate predicates and flavor
    let pred1 = generate_predicate(1);
    let pred2 = generate_predicate(2);
    let pred3 = generate_predicate(3);
    let flavor = Scalar::from(1u64);

    let correct_program = spend_1_2_contract(
        10u64,
        9u64,
        1u64,
        flavor,
        pred1.clone(), // input predicate
        pred2.clone(), // output 1 predicate
        pred3.clone(), // output 2 predicate
    );

    match build_and_verify(correct_program) {
        Err(err) => assert!(false, err.to_string()),
        _ => (),
    }

    let wrong_program = spend_1_2_contract(
        10u64,
        11u64,
        1u64,
        flavor,
        pred1.clone(), // input predicate
        pred2.clone(), // output 1 predicate
        pred3.clone(), // output 2 predicate
    );

    if build_and_verify(wrong_program).is_ok() {
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
            .output_helper(output_pred); // stack: empty
    })
}

#[test]
fn spend_2_1() {
    // Generate predicates and flavor
    let pred1 = generate_predicate(1);
    let pred2 = generate_predicate(2);
    let pred3 = generate_predicate(3);
    let flavor = Scalar::from(1u64);

    let correct_program = spend_2_1_contract(
        6u64,
        4u64,
        10u64,
        flavor,
        pred1.clone(), // input 1 predicate
        pred2.clone(), // input 2 predicate
        pred3.clone(), // output predicate
    );

    match build_and_verify(correct_program) {
        Err(err) => assert!(false, err.to_string()),
        _ => (),
    }

    let wrong_program = spend_2_1_contract(
        6u64,
        4u64,
        11u64,
        flavor,
        pred1.clone(), // input 1 predicate
        pred2.clone(), // input 2 predicate
        pred3.clone(), // output predicate
    );

    if build_and_verify(wrong_program).is_ok() {
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
            .output_helper(output_1_pred) // stack: output-1
            .output_helper(output_2_pred); // stack: empty
    })
}

#[test]
fn spend_2_2() {
    // Generate predicates and flavor
    let pred1 = generate_predicate(1);
    let pred2 = generate_predicate(2);
    let pred3 = generate_predicate(3);
    let pred4 = generate_predicate(4);
    let flavor = Scalar::from(1u64);

    let correct_program = spend_2_2_contract(
        6u64,
        4u64,
        9u64,
        1u64,
        flavor,
        pred1.clone(), // input 1 predicate
        pred2.clone(), // input 2 predicate
        pred3.clone(), // output 1 predicate
        pred4.clone(), // output 2 predicate
    );

    match build_and_verify(correct_program) {
        Err(err) => assert!(false, err.to_string()),
        Ok((_txid, txlog)) => {
            assert_eq!(
                txlog
                    .outputs()
                    .map(|c| {
                        c.payload[0]
                            .as_value()
                            .unwrap()
                            .assignment()
                            .unwrap()
                            .0
                            .to_u64()
                            .unwrap()
                    })
                    .collect::<Vec<_>>(),
                vec![9u64, 1u64]
            );
            assert_eq!(
                txlog
                    .outputs()
                    .map(|c| { c.predicate.clone().verification_key() })
                    .collect::<Vec<_>>(),
                vec![pred3.verification_key(), pred4.verification_key()]
            );
        }
    }

    let wrong_program = spend_2_2_contract(
        6u64,
        4u64,
        11u64,
        1u64,
        flavor,
        pred1.clone(), // input 1 predicate
        pred2.clone(), // input 2 predicate
        pred3.clone(), // output 1 predicate
        pred4.clone(), // output 2 predicate
    );

    if build_and_verify(wrong_program).is_ok() {
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
    input_pred: Predicate,
    output_1_pred: Predicate,
    output_2_pred: Predicate,
) -> Program {
    Program::build(|p| {
        p.input_helper(input_qty, flv, input_pred) // stack: issued-val, input-val
            .issue_helper(issue_qty, flv, issuance_pred) // stack: issued-val
            .cloak_helper(2, vec![(output_1, flv), (output_2, flv)]) // stack: output-1, output-2
            .output_helper(output_1_pred) // stack: output-1
            .output_helper(output_2_pred); // stack: empty
    })
}

#[test]
fn issue_and_spend() {
    // Generate predicates and flavor
    let pred1 = generate_predicate(1);
    let pred2 = generate_predicate(2);
    let pred3 = generate_predicate(3);
    let (issuance_pred, flavor) = make_flavor();

    let correct_program = issue_and_spend_contract(
        4u64,
        6u64,
        9u64,
        1u64,
        flavor,
        issuance_pred.clone(),
        pred1.clone(), // input predicate
        pred2.clone(), // output 1 predicate
        pred3.clone(), // output 2 predicate
    );

    match build_and_verify(correct_program) {
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
        pred1.clone(), // input predicate
        pred2.clone(), // output 1 predicate
        pred3.clone(), // output 2 predicate
    );

    if build_and_verify(wrong_program).is_ok() {
        panic!("Issue $6 and input $4, output $11 and $1 should have failed but didn't");
    }
}

/// Program that spends an input on the stack unlocked with knowledge of a secret Scalar.
fn spend_with_secret_scalar(qty: u64, flavor: Scalar, pred: Predicate, secret: Scalar) -> Program {
    Program::build(|p| {
        p.cloak_helper(1, vec![(qty, flavor)])
            .output_helper(pred)
            .scalar()
            .push(secret)
            .scalar()
            .eq()
            .verify();
    })
}

#[test]
fn taproot_happy_path() {
    let pred_tree = PredicateTree::new(Some(generate_predicate(1)), vec![], [0u8; 32]).unwrap();
    let prev_output = make_output(101u64, Scalar::from(1u64), Predicate::tree(pred_tree));

    let prog = Program::build(|p| {
        p.push(prev_output)
            .input()
            .signtx()
            .push(generate_predicate(2)) // send to the key
            .output(1);
    });

    build_and_verify(prog).unwrap();
}

#[test]
fn taproot_program_path() {
    let (qty, flavor) = (101u64, Scalar::from(1u64));
    let inner_pred = generate_predicate(1);
    let output_pred = generate_predicate(2);
    let secret_scalar = Scalar::from(0xc0ffeeu64);
    let spend_prog = spend_with_secret_scalar(qty, flavor, output_pred.clone(), secret_scalar);

    let blinding_key = rand::thread_rng().gen::<[u8; 32]>();
    let tree = PredicateTree::new(Some(inner_pred), vec![spend_prog], blinding_key).unwrap();
    let (call_proof, call_prog) = tree.create_callproof(0).unwrap();
    let prev_output = make_output(qty, flavor, Predicate::tree(tree));

    let prog = Program::build(|p| {
        p.push(secret_scalar)
            .push(prev_output.clone())
            .input()
            .push(String::Opaque(call_proof.to_bytes().clone()))
            .program(call_prog.clone())
            .call();
    });
    build_and_verify(prog).unwrap();

    let wrong_prog = Program::build(|p| {
        p.push(secret_scalar + Scalar::one())
            .push(prev_output.clone())
            .input()
            .push(String::Opaque(call_proof.to_bytes().clone()))
            .program(call_prog)
            .call();
    });
    if build_and_verify(wrong_prog).is_ok() {
        panic!("Unlocking input with incorrect secret scalar should have failed but didn't");
    }
}

#[test]
fn programs_cannot_be_copied() {
    let prog = Program::build(|p| {
        p.program(Program::build(|inner| {
            inner.verify();
        })) // some arbitrary program
        .dup(0);
    });

    assert_eq!(
        build_and_verify(prog).unwrap_err(),
        VMError::TypeNotCopyable
    );
}

#[test]
fn expressions_cannot_be_copied() {
    let prog = Program::build(|p| {
        p.mintime() // some arbitrary expression
            .dup(0);
    });

    assert_eq!(
        build_and_verify(prog).unwrap_err(),
        VMError::TypeNotCopyable
    );
}

#[test]
fn constraints_cannot_be_copied() {
    let prog = Program::build(|p| {
        p.mintime()
            .mintime()
            .eq() // some arbitrary constraint
            .dup(0);
    });

    assert_eq!(
        build_and_verify(prog).unwrap_err(),
        VMError::TypeNotCopyable
    );
}

#[test]
fn eval_test() {
    let pred = generate_predicate(1);
    let prog = Program::build(|p| {
        p.push(String::from(Scalar::from(20u64)));
        p.scalar();
        p.program(Program::build(|p2| {
            p2.push(String::from(Scalar::from(1u64)));
            p2.scalar();
            p2.program(Program::build(|p3| {
                p3.add();
            }));
            p2.eval();
        }));
        p.eval();
        p.push(String::from(Scalar::from(21u64)));
        p.scalar();
        p.eq();
        p.verify();

        // to make program finish we need to spend a dummy input
        p.input_helper(0, Scalar::zero(), pred.clone());
        p.output_helper(pred);
    });

    build_and_verify(prog).expect("should succeed");
}

#[test]
fn borrow_output() {
    //inputs 10 units, borrows 5 units, outputs two (5 units)
    let flv = Scalar::from(1u64);
    let pred1 = generate_predicate(1);
    let pred2 = generate_predicate(2);
    let pred3 = generate_predicate(3);
    let borrow_prog = Program::build(|p| {
        p.input_helper(10, flv, pred1) // stack: Value(10,1)
            .push(Commitment::blinded(5u64)) // stack: Value(10,1), qty(5)
            .commit() // stack: Value(10,1), qty-var(5)
            .push(Commitment::blinded(flv)) // stack: Value(10,1), qty-var(5),   flv(1)
            .commit() // stack: Value(10,1), qty-var(5),   flv-var(1)
            .borrow() // stack: Value(10,1), Value(-5, 1), Value(5,1)
            .output_helper(pred2) // stack: Value(10,1), Value(-5, 1); outputs (5,1)
            .cloak_helper(2, vec![(5u64, flv)]) // stack:  Value(5,1)
            .output_helper(pred3); // outputs (5,1)
    });
    build_and_verify(borrow_prog).unwrap();
}
