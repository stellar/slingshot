use curve25519_dalek::scalar::Scalar;
use rand::RngCore;

use super::*;
use crate::{Anchor, Contract, Data, PortableItem, Predicate, VerificationKey};

fn rand_item() -> PortableItem {
    let mut bytes = [0u8; 4];
    rand::thread_rng().fill_bytes(&mut bytes);
    PortableItem::Data(Data::Opaque(bytes.to_vec()))
}

fn rand_contract() -> Contract {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    let privkey = &Scalar::random(&mut rand::thread_rng());
    Contract::new(
        Predicate::Key(VerificationKey::from_secret(privkey)),
        vec![rand_item(), rand_item(), rand_item()],
        Anchor::from_raw_bytes(bytes),
    )
}

#[test]
fn test_apply_txlog() {
    unimplemented!();
    let mut state = BlockchainState::make_initial(0u64, &[]);

    /*
    // Add two outputs
    let (output0, output1) = (rand_contract(), rand_contract());
    state
        .apply_txlog(&vec![
            TxEntry::Output(output0.clone()),
            TxEntry::Output(output1.clone()),
        ])
        .unwrap();
    state
        .apply_txlog(&vec![TxEntry::Input(output0.id())])
        .unwrap();

    // Check that output0 was consumed
    assert!(!state.utxos.contains(&output0.id()));
    assert!(state.utxos.contains(&output1.id()));

    // Consume output1
    state
        .apply_txlog(&vec![TxEntry::Input(output1.id())])
        .unwrap();
    assert_eq!(state.utxos.is_empty(), true);

    // Check error on consuming already-consumed UTXO
    assert!(state
        .apply_txlog(&vec![TxEntry::Input(output1.id())])
        .is_err());
        */
}