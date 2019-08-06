use bulletproofs::BulletproofGens;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use musig::Signature;
use rand::RngCore;

use super::*;
use crate::{
    Anchor, Commitment, Contract, PortableItem, Predicate, Program, Prover, String, TxHeader,
    Value, VerificationKey,
};

fn make_predicate(privkey: u64) -> Predicate {
    Predicate::Key(VerificationKey::from_secret(&Scalar::from(privkey)))
}

fn nonce_flavor() -> Scalar {
    Value::issue_flavor(&make_predicate(0u64), String::default())
}

fn make_nonce_contract(privkey: u64, qty: u64) -> Contract {
    let mut anchor_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut anchor_bytes);

    Contract {
        predicate: make_predicate(privkey),
        payload: vec![PortableItem::Value(Value {
            qty: Commitment::unblinded(qty),
            flv: Commitment::unblinded(nonce_flavor()),
        })],
        anchor: Anchor::from_raw_bytes(anchor_bytes),
    }
}

#[test]
fn test_state_machine() {
    let bp_gens = BulletproofGens::new(256, 1);
    let privkey = Scalar::from(1u64);
    let initial_contract = make_nonce_contract(1, 100);
    let (mut state, proofs) = BlockchainState::make_initial(0u64, vec![initial_contract.id()]);

    let tx = {
        let program = Program::build(|p| {
            p.push(initial_contract.clone())
                .input()
                .sign_tx()
                .push(make_predicate(2u64))
                .output(1)
        });
        let header = TxHeader {
            version: 1u64,
            mintime_ms: 0u64,
            maxtime_ms: u64::max_value(),
        };
        let utx = Prover::build_tx(program, header, &bp_gens).unwrap();

        let mut signtx_transcript = Transcript::new(b"ZkVM.signtx");
        signtx_transcript.append_message(b"txid", &utx.txid.0);

        let sig = Signature::sign_multi(
            &[privkey],
            utx.signing_instructions.clone(),
            &mut signtx_transcript,
        )
        .unwrap();

        utx.sign(sig)
    };

    let (block, _verified_block, future_state) = state
        .make_block(1, 1, Vec::new(), vec![tx], proofs, &bp_gens)
        .unwrap();

    // Apply the block to the state
    let (_verified_block, new_state) = state.apply_block(&block, &bp_gens).unwrap();

    assert_eq!(new_state.utreexo.root(), future_state.utreexo.root());
}
