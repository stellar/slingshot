use curve25519_dalek::scalar::Scalar;
use keytree::{Xprv, Xpub};
use rand::SeedableRng;
use rand_chacha::ChaChaRng;
use zkvm::{Anchor, Contract, ClearValue};

use crate::{Account, Receiver, ReceiverID};

struct User {
    xprv: Xprv,
    account: Account,
    utxos: Vec<MockUtxo>,
}

struct MockUtxo {
    value: ClearValue,
    sequence: u64,
    anchor: Anchor,
}

#[test]
fn simple_tx() {
    // Alice receives payment from Bob.
    let mut alice = User::new([0; 32]);
    let mut bob = User::new([1; 32]);

    let payment_qty = 13;
    let payment_flv = Scalar::from(0u64);

    // Recipient:
    let receiver = alice.account.generate_receiver(payment_qty, payment_flv);

    // Sender:
    let tx = {
        let (spent_utxos, change_value) = receiver.select_utxos(alice.utxos);
        let change_receiver = 
    }
}

impl User {
    /// Creates a new user account with a privkey and pre-seeded collection of utxos
    fn new(seed: [u8; 32]) -> Self {
        let mut rng = ChaChaRng::from_seed(seed);
        let xprv = Xprv::random(&mut rng);
        let xpub = xprv.to_xpub();

        let mut account = Account::new(xpub);

        // Create some utxos
        let mut utxos = Vec::new();

        let mut anchor = Anchor::from_raw_bytes([0; 32]);

        // Create a few contracts with values of different quantities and flavors {0, 1}.
        for flv_i in 0..2u64 {
            let flv = Scalar::from(flv_i);
            for q in 0..6u64 {
                // 1, 2, 4, 8, 16, 32
                let qty = 1u64 << q;
                // anchors are not unique, but it's irrelevant for this test
                anchor = anchor.ratchet();

                let sequence = account.sequence;
                let receiver = account.generate_receiver(qty, flv);

                utxos.push(MockUtxo {
                    value: ClearValue {
                        qty,
                        flv
                    },
                    sequence,
                    anchor,
                });
            }
        }

        Self {
            xprv,
            account,
            utxos,
        }
    }
}

impl AsRef<ClearValue> for MockUtxo {
    fn as_ref(&self) -> &ClearValue {
        &self.value
    }
}

impl MockUtxo {
    /// Convert utxo to a Contract instance
    fn to_contract(&self, account: &Account) -> Contract {
        account
            .at_sequence(self.sequence)
            .generate_receiver(self.value.qty, self.value.flv)
            .contract(self.anchor)
    }
}