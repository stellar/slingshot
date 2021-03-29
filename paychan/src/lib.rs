use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use musig::{Multikey, Signature};
use zkvm::{ClearValue, Commitment, Predicate, PredicateTree, Program, Value, VerificationKey};

fn blinded_value(v: ClearValue) -> Value {
    Value {
        qty: Commitment::blinded(v.qty),
        flv: Commitment::blinded(v.flv),
    }
}

 // Creates program: `<qty> commit <flv> commit borrow => -V +V`
 fn borrow_value(p: &mut Program, v: Value) {
    p.push(v.qty).commit().push(v.flv).commit().borrow();
}

fn output_value(
    p: &mut Program,
    v: Value,
    pred: Predicate,
) {
    // qty commit flv commit borrow => -v +v
    borrow_value(p, v);
    p.push(zkvm::String::Predicate(Box::new(pred)));
    p.output(1);
}

// locks a list of values under a predicate, and leaves negative values on stack.
fn output_multiple_values(
    p: &mut Program,
    mut values: impl ExactSizeIterator<Item = Value>,
    pred: Predicate,
) {
    let n = values.len();
    if n == 0 {
        return;
    } else if n == 1 {
        return output_value(p, values.next().expect("Should have 1 value"), pred);
    }

    for v in values {
        // qty commit flv commit borrow => -v +v
        borrow_value(p, v)
    }
    // n = 1: no rolls
    // n = 2: -a +a -b +b: roll 2, roll 1
    // n = 3: -a +a -b +b -c +c: roll 4, roll 3, roll 2
    // n = 4: -a +a -b +b -c +c -d +d: roll 6, roll 5, roll 4, roll 3
    // =>  roll 2(n-1)-i  n times
    let mut i = 0;
    while i < n {
        p.roll(2 * (n - 1) - i);
        i += 1;
    }
    p.push(zkvm::String::Predicate(Box::new(pred)));
    p.output(n);
}

#[test]
fn test() {
    let alice_prv = Scalar::from(1u64);
    let bob_prv = Scalar::from(2u64);

    let alice = VerificationKey::from_secret(&alice_prv);
    let bob = VerificationKey::from_secret(&bob_prv);

    let alice_bob_joined = Multikey::new(vec![alice.clone(), bob.clone()])
        .expect("won't fail")
        .aggregated_key();

    let flv = Scalar::zero();
    let alice_qty = 100u64;
    let bob_qty = 100u64;
    let shared_value = blinded_value(ClearValue {
        qty: alice_qty + bob_qty,
        flv,
    });

    let values = vec![shared_value];
    let alice_original_balances = vec![blinded_value(ClearValue {
        qty: alice_qty,
        flv,
    })];
    let bob_original_balances = vec![blinded_value(ClearValue { qty: bob_qty, flv })];
    let assets_count = values.len();
    let taproot_exit_blinding = [0u8; 32]; // TBD: real random
    let taproot_init_blinding = [0u8; 32]; // TBD: real random

    // TBD: generate unique tag for this contract from both keys and initial balances.
    // Each party is supposed to have unique keys so the tag is not reused in other channels.
    // Ideally, we'd tie the tag to the coins we are going to spend (can't duplicate that),
    // but that adds extra coupling between preparation of the contract and actual tx signing.

    let channel_tag = [0u8; 32].to_vec();

    // Step 1: Alice and Bob prepare a contract that consists of:
    // 1.1. Exit contract
    // 1.2. Initial contract
    // 1.3. Pre-signed initial distribution
    //
    // Initial contract embeds the exit predicate, so it is computed second.
    // The goal of the initial contract is to provide a bridge into the
    // "exiting" state state that can be overriden with a distribution program.

    // 1.1. Exit contract
    // Expected layout:
    // [value, sequence, timeout, program, tag]
    //
    // P_exit = AB + program {
    //     verify(tx.mintime > self.timeout)
    //     eval(self.redistribution_program)
    // }
    let exit_predicate = Predicate::tree(
        PredicateTree::new(
            Some(Predicate::new(alice_bob_joined.clone())),
            vec![zkvm::Program::build(|p| {
                // stack: assets, seq, timeout, prog, tag
                // timeout is checked as a range proof
                // tx.mintime > self.timeout =>
                // tx.mintime - self.timeout > 0
                p.dup(2) // copy the timeout from the stack
                    .commit()
                    .neg()
                    .mintime()
                    .add()
                    .range()
                    // then, evaluate the distribution program
                    .roll(1); // we won't need to keep the program, so move it to the top

                // TBD: need a plain "call" instruction to evaluate in-place w/o rewrapping.
                // rewrapping the whole thing in another taproot
            })],
            taproot_exit_blinding,
        )
        .expect("won't fail"),
    );

    // 1.2. Initial contract

    //    P_init = AB + program {
    //         // transient contract:
    //         contract(payload {
    //            assets,
    //            seq=0,
    //            timeout=MAX_INT,
    //            "" (empty prog),
    //            tag
    //         ) -> P_exit
    //    }
    let initial_predicate = Predicate::tree(
        PredicateTree::new(
            Some(Predicate::new(alice_bob_joined.clone())),
            vec![zkvm::Program::build(|p| {
                // This is a simple adaptor contract that prepares a good format for applying
                // the pre-signed exit program.
                p.push(zkvm::String::U64(0))
                    .push(zkvm::String::Commitment(Box::new(Commitment::unblinded(
                        u64::max_value(),
                    ))))
                    .push(zkvm::String::Opaque(Program::new().to_bytes()))
                    .push(zkvm::String::Opaque(channel_tag.clone()))
                    .push(zkvm::String::Predicate(Box::new(exit_predicate.clone())))
                    .contract(assets_count + 1 + 1 + 1 + 1);
            })],
            taproot_init_blinding,
        )
        .expect("won't fail"),
    );

    // 1.3. Pre-signed initial distribution
    let initial_distribution = Program::build(|p| {
        output_multiple_values(
            p,
            alice_original_balances.into_iter(),
            Predicate::new(alice.clone()),
        );
        output_multiple_values(
            p,
            bob_original_balances.into_iter(),
            Predicate::new(bob.clone()),
        );
    });

    // override program:
    // program($seq, $tx, $new_distribution) = {
    //     verify($seq > self.seq)
    //     self.redistribution_program = $new_distribution
    //     self.timeout = $tx.maxtime+T
    //     lock(self, P_exit)
    // }
    let initial_exit = Program::build(|p| {
        // stack: assets, seq, timeout, prog, tag
        p.dup(3); // copy the seq from the stack
        // TBD: check the sequence, update timeout and redistribution program
        // TBD: tx.maxtime must be constrained close to mintime so we don't allow locking up resolution too far in the future.
    });

    // Produce a signature for the initial distribution
    // message formatted for signtag instruction.
    let mut t = Transcript::new(b"ZkVM.signtag");
    t.append_message(b"tag", &channel_tag[..]);
    t.append_message(b"prog", &initial_exit.to_bytes());

    // FIXME: this does not accurately emulate two-party interaction.
    // See musig APIs for a proper MPC protocol where keys are not shared.
    let initial_exit_signature = Signature::sign(
        &mut t,
        Multikey::aggregated_signing_key(&vec![alice_prv, bob_prv]),
    );

    // Step 2: Alice and Bob co-sign a tx that locks up their funds in the initial contract.
    // In this example we just cook up a serialized contract that we'll be spending.



    // Step 3: Alice and Bob co-sign distribution program and exchange funds indefinitely

    // Case A: Alice and Bob co-sign exit from the channel

    // Case B: Alice closes channel with the latest version.

    // Case C: Alice detects that channel was closed by Bob and updates her wallet state.

    // Case D: Alice detects that channel was closed by Bob with a stale update and sends out a newer version.

    assert_eq!("a", "b");
}
