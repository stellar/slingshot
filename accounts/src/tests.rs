use merlin::Transcript;
use rand::SeedableRng;
use rand_chacha::ChaChaRng;

use bulletproofs::BulletproofGens;
use curve25519_dalek::scalar::Scalar;
use keytree::Xprv;
use musig::Signature;

use zkvm::blockchain::{Block, BlockchainState};
use zkvm::utreexo;
use zkvm::{Anchor, ClearValue, Contract, ContractID, Program, Prover, TxEntry, TxHeader};

use crate::{Account, ReceiverReply, ReceiverWitness};

/// The complete state of the user node: their wallet and their blockchain state.
#[derive(Clone)]
struct Node {
    /// Current blockchain state of the node
    blockchain: BlockchainState,
    /// User's wallet data
    wallet: Wallet,
}

/// User's wallet account data
#[derive(Clone)]
struct Wallet {
    /// User's root wallet key
    xprv: Xprv,

    /// User's account metadata
    account: Account,

    /// User's balances
    utxos: Vec<ConfirmedUtxo>,

    /// User's pending incoming payments
    pending_utxos: Vec<PendingUtxo>,
}

/// UTXO that has not been confirmed yet. It is formed from Receiver and ReceiverReply.
/// Users convert pending utxos into ConfirmedUtxo when they detect the output in the blockchain.
#[derive(Clone)]
struct PendingUtxo {
    receiver_witness: ReceiverWitness,
    anchor: Anchor,
}

/// Stored utxo with underlying quantities, blinding factors and a utxo proof.
#[derive(Clone)]
struct ConfirmedUtxo {
    receiver_witness: ReceiverWitness,
    anchor: Anchor,
    proof: utreexo::Proof,
}

#[test]
fn simple_tx() {
    let bp_gens = BulletproofGens::new(256, 1);

    // Overview:
    // 0. Initialize empty wallets for Alice and Bob.
    // 1. Instantiate a blockchain with utxos allocated to Alice.
    // 2. Bob is instantiated with no utxos.
    // 3. Bob creates a receiver.
    // 4. Alice forms a tx paying to this receiver.
    //    Now Bob is receiving a new utxo, Alice is receiving a change utxo.
    // 5. Alice sends ReceiverReply to Bob with contract's anchor.
    // 6. Bob uses ReceiverReply to create PendingUtxo, replies with ACK.
    // 7. Alice stores similar PendingUtxo for her change output.
    // 8. Alice submits tx.
    // 9. Alice/Bob process blockchain:
    //     a. SPV nodes:
    //        1. Network sends to Bob and Alice new blockheader and a changeset:
    //           - added utxo IDs,
    //           - merkle proof set (combined in one tree when optimized) for all deleted utxo ids.
    //        2. Alice/Bob apply changes, producing a new utreexo (and verifying it), and a catchup struct.
    //     b. Full nodes:
    //        1. Network sends to Bob and Alice new block
    //        2. Alice/Bob verify+apply changes, producing a catchup struct.
    // 10. Alice/Bob use Catchup to update all the other proofs for previously stored utxos.
    // 11. Alice/Bob match inserted items with their PendingUtxos to collect proofs for them and turn them into ConfirmedUtxos.

    // 0. Initialize empty wallets for Alice and Bob.
    let mut alice_wallet = Wallet::new([0; 32]);
    let bob_wallet = Wallet::new([1; 32]);

    // 1. Instantiate a blockchain with some utxos allocated to Alice.
    let utxos = alice_wallet.generate_pending_utxos([0; 32]);

    let (network_state, proofs) =
        BlockchainState::make_initial(0u64, utxos.iter().map(|utxo| utxo.contract().id()));

    alice_wallet.utxos = utxos
        .into_iter()
        .zip(proofs.into_iter())
        .map(|(pending_utxo, proof)| pending_utxo.to_confirmed(proof))
        .collect();

    let mut alice = Node {
        blockchain: network_state.clone(),
        wallet: alice_wallet,
    };

    // 2. Bob is instantiated with no utxos.
    let mut bob = Node {
        blockchain: network_state.clone(),
        wallet: bob_wallet,
    };

    // 3. Bob creates a receiver.
    let payment = ClearValue {
        qty: 14,
        flv: Scalar::from(0u64),
    };
    let payment_receiver_witness = bob.wallet.account.generate_receiver(payment);
    let payment_receiver = &payment_receiver_witness.receiver;

    // TBD: at some point (together with creating `PendingUtxo`s?) we need to reserve the spent utxos,
    // so we don't concurrently re-use them in a new tx.

    // Unwrap is used because in this test we know that we are supposed to have enough UTXOs.
    let (spent_utxos, change_value) =
        Account::select_utxos(&payment_receiver.value, &alice.wallet.utxos).unwrap();
    let change_receiver_witness = alice.wallet.account.generate_receiver(change_value);

    // 4. Alice forms a tx paying to this receiver.
    //    Now Bob is receiving a new utxo, Alice is receiving a change utxo.
    let utx = {
        // Note: for clarity, we are not randomizing inputs and outputs in this example.
        // The real transaction must randomize all the things
        let program = Program::build(|p| {
            // claim all the collected utxos
            for stored_utxo in spent_utxos.iter() {
                p.push(stored_utxo.contract());
                p.input();
                p.sign_tx();
            }

            let pmnt = payment_receiver.blinded_value();
            p.push(pmnt.qty);
            p.push(pmnt.flv);

            let change = change_receiver_witness.receiver.blinded_value();
            p.push(change.qty);
            p.push(change.flv);

            p.cloak(spent_utxos.len(), 2);

            // Now the payment and the change are in the same order on the stack:
            // change is on top.
            p.push(change_receiver_witness.receiver.predicate.clone());
            p.output(1);

            p.push(payment_receiver.predicate.clone());
            p.output(1);

            // TBD: change the API to not require return of the `&mut program` from the closure.
            p
        });
        let header = TxHeader {
            version: 1u64,
            mintime_ms: 0u64,
            maxtime_ms: u64::max_value(),
        };

        // Build the UnverifiedTx
        Prover::build_tx(program, header, &bp_gens).unwrap()
    };

    // 5. Alice sends ReceiverReply to Bob with contract's anchor.
    // Determine the payment contract's anchor and send it to Bob via ReceiverReply

    // Collect all anchors for outputs.
    let mut iterator = utx.txlog.iter().filter_map(|e| match e {
        TxEntry::Output(contract) => Some(contract.anchor()),
        _ => None,
    });
    let change_anchor = iterator.next().unwrap();
    let payment_anchor = iterator.next().unwrap();

    let reply = ReceiverReply {
        receiver_id: payment_receiver.id(),
        anchor: payment_anchor,
    };

    // 6. Bob uses ReceiverReply to create PendingUtxo, replies with ACK.
    {
        // In real implementation we'd check reply.receiver_id == payment_receiver.id()
        let pending_utxo = PendingUtxo {
            receiver_witness: payment_receiver_witness,
            anchor: reply.anchor, // store anchor sent by Alice
        };

        bob.wallet.pending_utxos.push(pending_utxo);
    }

    // Alice receives ACK from Bob.

    // Alice signs the tx.
    let tx = {
        let mut signtx_transcript = Transcript::new(b"ZkVM.signtx");
        signtx_transcript.append_message(b"txid", &utx.txid.0);

        // Derive individual signing keys for each input, according to its sequence number.
        // In this example all inputs are coming from the same account (same xpub).
        let signing_keys = spent_utxos
            .iter()
            .map(|utxo| {
                Account::derive_signing_key(utxo.receiver_witness.sequence, &alice.wallet.xprv)
            })
            .collect::<Vec<_>>();

        let sig = Signature::sign_multi(
            &signing_keys[..],
            utx.signing_instructions.clone(),
            &mut signtx_transcript,
        )
        .unwrap();

        utx.sign(sig)
    };

    // 7. Alice stores similar PendingUtxo for her change output.
    let change_pending_utxo = PendingUtxo {
        receiver_witness: change_receiver_witness,
        anchor: change_anchor,
    };
    alice.wallet.pending_utxos.push(change_pending_utxo);

    // 8. Alice submits tx to the network.
    //    Network creates a block and returns it to Alice and Bob.
    let utxo_proofs = spent_utxos
        .iter()
        .map(|utxo| utxo.proof.clone())
        .collect::<Vec<_>>();
    let (block, _verified_block, _network_state2) = network_state
        .make_block(1, 1, Vec::new(), vec![tx], utxo_proofs, &bp_gens)
        .unwrap();

    // 9. Alice and Bob process the incoming block:
    process_block(&mut alice, &block, &bp_gens);
    process_block(&mut bob, &block, &bp_gens);
}

/// Processes a block
fn process_block(node: &mut Node, block: &Block, bp_gens: &BulletproofGens) {
    // 9. Alice/Bob process blockchain:
    //     a. SPV nodes:
    //        1. Network sends to Bob and Alice new blockheader and a changeset:
    //           - added utxo IDs,
    //           - merkle proof set (combined in one tree when optimized) for all deleted utxo ids.
    //        2. Alice/Bob apply changes, producing a new utreexo (and verifying it), and a catchup struct.
    //     b. Full nodes:
    //        1. Network sends to Bob and Alice new block
    //        2. Alice/Bob verify+apply changes, producing a catchup struct.
    let (verified_block, new_state) = node.blockchain.apply_block(&block, &bp_gens).unwrap();

    // In a real node utxos will be indexed by ContractID, so lookup will be more efficient.
    for entry in verified_block.entries() {
        match entry {
            TxEntry::Input(contract_id) => {
                // Delete confirmed utxos
                if let Some(i) = node
                    .wallet
                    .utxos
                    .iter()
                    .position(|utxo| utxo.contract_id() == *contract_id)
                {
                    node.wallet.utxos.remove(i);
                }
            }
            TxEntry::Output(contract) => {
                // Make pending utxos confirmed
                if let Some(i) = node
                    .wallet
                    .pending_utxos
                    .iter()
                    .position(|utxo| utxo.contract_id() == contract.id())
                {
                    let pending_utxo = node.wallet.pending_utxos.remove(i);
                    let proof = new_state
                        .catchup
                        .update_proof(&pending_utxo.contract_id(), None)
                        .unwrap();
                    node.wallet.utxos.push(pending_utxo.to_confirmed(proof));
                }
            }
            _ => {}
        }
    }

    // Catch up utxoproofs for all the confirmed utxos.
    let updated_proofs = node
        .wallet
        .utxos
        .iter()
        .map(|utxo| {
            new_state
                .catchup
                .update_proof(&utxo.contract_id(), Some(utxo.proof.clone()))
        })
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    // Once all proofs are succesfully updated, apply them to our storage.
    for (p, utxo) in updated_proofs.into_iter().zip(node.wallet.utxos.iter_mut()) {
        utxo.proof = p;
    }

    // Switch the node to the new state.
    node.blockchain = new_state;
}

impl Wallet {
    /// Creates a new user account with a privkey and pre-seeded collection of utxos
    fn new(seed: [u8; 32]) -> Self {
        let xprv = Xprv::random(&mut ChaChaRng::from_seed(seed));

        Self {
            xprv,
            account: Account::new(xprv.to_xpub()),
            utxos: Vec::new(),
            pending_utxos: Vec::new(),
        }
    }

    /// Generates a bunch of mock utxos
    fn generate_pending_utxos(&mut self, anchor_seed: [u8; 32]) -> Vec<PendingUtxo> {
        // Create some utxos
        let mut results = Vec::new();

        let mut anchor = Anchor::from_raw_bytes(anchor_seed);

        // Create a few contracts with values of different quantities and flavors {0, 1}.
        for flv_i in 0..2u64 {
            let flv = Scalar::from(flv_i);
            for q in 0..6u64 {
                // 1, 2, 4, 8, 16, 32
                let qty = 1u64 << q;
                // anchors are not unique, but it's irrelevant for this test
                anchor = anchor.ratchet();

                let receiver_witness = self.account.generate_receiver(ClearValue { qty, flv });

                results.push(PendingUtxo {
                    receiver_witness,
                    anchor,
                });
            }
        }

        results
    }
}

impl AsRef<ClearValue> for ConfirmedUtxo {
    fn as_ref(&self) -> &ClearValue {
        &self.receiver_witness.receiver.value
    }
}

impl PendingUtxo {
    /// Convert utxo to a Contract instance
    fn contract(&self) -> Contract {
        self.receiver_witness.receiver.contract(self.anchor)
    }

    /// Returns the UTXO ID
    fn contract_id(&self) -> ContractID {
        self.contract().id()
    }

    /// Converts pending utxo into stored utxo
    fn to_confirmed(self, proof: utreexo::Proof) -> ConfirmedUtxo {
        ConfirmedUtxo {
            receiver_witness: self.receiver_witness,
            anchor: self.anchor,
            proof,
        }
    }
}

impl ConfirmedUtxo {
    /// Convert utxo to a Contract instance
    fn contract(&self) -> Contract {
        self.receiver_witness.receiver.contract(self.anchor)
    }

    /// Returns the UTXO ID
    fn contract_id(&self) -> ContractID {
        self.contract().id()
    }
}
