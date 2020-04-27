use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use rand::RngCore;
use zkvm::bulletproofs::BulletproofGens;
use zkvm::VerifiedTx;

use super::*;
use zkvm::{
    Anchor, Commitment, Contract, ContractID, Multisignature, PortableItem, Predicate, Program,
    Prover, Signature, String, TxHeader, Value, VerificationKey,
};

fn make_predicate(privkey: impl Into<Scalar>) -> Predicate {
    Predicate::Key(VerificationKey::from_secret(&privkey.into()))
}

fn nonce_flavor() -> Scalar {
    Value::issue_flavor(&make_predicate(0u64), String::default())
}

fn make_nonce_contract(privkey: impl Into<Scalar>, qty: u64) -> Contract {
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
#[derive(Clone, Debug)]
struct UTXO {
    pub contract: Contract,
    pub proof: utreexo::Proof,
    pub privkey: Scalar,
}

/// Makes a tx that simply moves funds from one utxo to another.
fn dummy_tx(utxo: UTXO, bp_gens: &BulletproofGens) -> (BlockTx, UTXO) {
    let privkey = utxo.privkey;
    let utreexo_proof = utxo.proof;
    let contract = utxo.contract;
    let tx = {
        let program = Program::build(|p| {
            p.push(contract)
                .input()
                .signtx()
                .push(make_predicate(privkey))
                .output(1);
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

    let block_tx = BlockTx {
        tx: tx.clone(),
        proofs: vec![utreexo_proof],
    };

    let utxo = UTXO {
        contract: tx
            .precompute()
            .unwrap()
            .log
            .outputs()
            .next()
            .unwrap()
            .clone(),
        proof: utreexo::Proof::Transient,
        privkey: privkey,
    };

    (block_tx, utxo)
}

#[test]
fn test_state_machine() {
    let bp_gens = BulletproofGens::new(256, 1);
    let privkey = Scalar::from(1u64);
    let initial_contract = make_nonce_contract(1u64, 100);
    let (state, proofs) = BlockchainState::make_initial(0u64, vec![initial_contract.id()]);

    let utxo = UTXO {
        contract: initial_contract.clone(),
        proof: proofs[0].clone(),
        privkey,
    };
    let block_tx = dummy_tx(utxo, &bp_gens).0;

    let mut mempool = Mempool::new(state.clone(), 42);

    mempool
        .append(block_tx.clone(), &bp_gens)
        .expect("Tx must be valid");

    let (future_state, _catchup) = mempool.make_block();

    // Apply the block to the state
    let (new_state, _catchup, _vtxs) = state
        .apply_block(future_state.tip, &[block_tx], &bp_gens)
        .expect("Block application should succeed.");

    let hasher = utreexo::utreexo_hasher::<ContractID>();
    assert_eq!(
        new_state.utreexo.root(&hasher),
        future_state.utreexo.root(&hasher)
    );
}

#[test]
fn test_p2p_protocol() {
    use super::protocol::*;
    use async_trait::async_trait;
    use futures_executor::block_on;
    use starsig::{Signature, VerificationKey};
    use std::fmt;
    use std::sync::mpsc::{channel, Receiver, Sender};

    #[derive(Copy, Clone, Eq, PartialEq, Hash)]
    struct PID(u8);

    impl fmt::Debug for PID {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "Peer#{}", self.0)
        }
    }

    impl AsRef<[u8]> for PID {
        fn as_ref(&self) -> &[u8] {
            core::slice::from_ref(&self.0)
        }
    }

    struct MockNode {
        id: PID,
        state: BlockchainState,
        blocks: Vec<Block>,                   // i=0 -> height=1, etc
        mailbox: Sender<(PID, PID, Message)>, // from, to, msg
    }

    #[derive(Debug)]
    struct Mailbox {
        rx: Receiver<(PID, PID, Message)>, // from, to, msg
    }

    impl Mailbox {
        fn process(
            &self,
            nodes: &mut [&mut Node<MockNode>],
        ) -> Vec<(PID, Result<(), BlockchainError>)> {
            let mut r = Vec::new();
            while let Ok((pid_from, pid_to, msg)) = self.rx.try_recv() {
                dbg!((pid_from, pid_to, &msg));
                let result = block_on(nodes[pid_to.0 as usize].process_message(pid_from, msg));
                if let Err(e) = result {
                    panic!("Message processing failed: {:?}", e);
                }
                r.push((pid_to, result));
            }
            r
        }

        fn process_must_succeed(&self, nodes: &mut [&mut Node<MockNode>]) {
            let results = self.process(nodes);
            assert!(results.into_iter().all(|(_pid, r)| r.is_ok()));
        }
    }

    #[async_trait]
    impl Delegate for MockNode {
        type PeerIdentifier = PID;

        /// ID of our node.
        fn self_id(&self) -> Self::PeerIdentifier {
            self.id
        }

        /// Send a message to a given peer.
        async fn send(&mut self, pid_to: Self::PeerIdentifier, message: Message) {
            self.mailbox.send((self.id, pid_to, message)).unwrap();
        }

        /// Returns the signed tip of the blockchain
        fn tip(&self) -> (BlockHeader, Signature) {
            let last_block = self.blocks.last().unwrap();
            (last_block.header.clone(), last_block.signature)
        }

        /// Returns a block at a given height
        fn block_at_height(&self, height: u64) -> Option<Block> {
            if height < 1 {
                return None;
            }
            self.blocks.get((height - 1) as usize).map(|b| b.clone())
        }

        /// Blockchain state
        fn blockchain_state(&self) -> &BlockchainState {
            &self.state
        }

        /// Stores the new block and an updated state.
        fn store_block(
            &mut self,
            block: Block,
            new_state: BlockchainState,
            _catchup: utreexo::Catchup,
            _vtxs: Vec<VerifiedTx>,
        ) {
            // TODO: update all proofs in the wallet with a catchup structure.
            assert!(block.header.height == self.state.tip.height + 1);
            self.blocks.push(block);
            self.state = new_state;
        }
    }

    let bp_gens = BulletproofGens::new(256, 1);
    let network_signing_key = Scalar::from(9000u64);
    let network_pubkey = VerificationKey::from_secret(&network_signing_key);

    let wallet_privkey = Scalar::from(1u64);
    let initial_contract = make_nonce_contract(1u64, 100);
    let (state, block_sig, proofs) =
        Node::<MockNode>::new_network(network_signing_key, 0, vec![initial_contract.id()]);

    let utxo0 = UTXO {
        contract: initial_contract.clone(),
        proof: proofs[0].clone(),
        privkey: wallet_privkey,
    };

    let (mailbox_tx, mailbox_rx) = channel();
    let mailbox = Mailbox { rx: mailbox_rx };

    let mut nodes = (0..3)
        .map(|pid| MockNode {
            id: PID(pid),
            state: state.clone(),
            blocks: vec![Block {
                header: state.tip.clone(),
                signature: block_sig.clone(),
                txs: Vec::new(),
            }],
            mailbox: mailbox_tx.clone(),
        })
        .map(|mock| Node::new(network_pubkey, mock));

    // Now all the nodes have the same state and can make transactions.
    let mut node0 = nodes.next().unwrap().set_inventory_interval(0);
    let mut node1 = nodes.next().unwrap().set_inventory_interval(0);
    let mut node2 = nodes.next().unwrap().set_inventory_interval(0);

    // connect all the peers to each other
    block_on(node0.peer_connected(node1.id()));
    block_on(node1.peer_connected(node0.id()));

    block_on(node2.peer_connected(node1.id()));
    block_on(node1.peer_connected(node2.id()));

    block_on(node2.peer_connected(node0.id()));
    block_on(node0.peer_connected(node2.id()));

    mailbox.process_must_succeed(&mut [&mut node0, &mut node1, &mut node2]);

    block_on(node0.synchronize());
    block_on(node1.synchronize());
    block_on(node2.synchronize());

    mailbox.process_must_succeed(&mut [&mut node0, &mut node1, &mut node2]);

    let (tx1, _utxo1) = dummy_tx(utxo0, &bp_gens);

    node0.submit_tx(tx1).unwrap();

    // send out requests for inventory
    block_on(node1.synchronize());
    block_on(node2.synchronize());

    mailbox.process_must_succeed(&mut [&mut node0, &mut node1, &mut node2]);

    // send back the inventory
    block_on(node0.synchronize());

    mailbox.process_must_succeed(&mut [&mut node0, &mut node1, &mut node2]);

    block_on(node1.synchronize());
    block_on(node2.synchronize());

    mailbox.process_must_succeed(&mut [&mut node0, &mut node1, &mut node2]);

    block_on(node0.synchronize());
    block_on(node1.synchronize());
    block_on(node2.synchronize());

    mailbox.process_must_succeed(&mut [&mut node0, &mut node1, &mut node2]);

    block_on(node0.synchronize());
    block_on(node1.synchronize());
    block_on(node2.synchronize());

    mailbox.process_must_succeed(&mut [&mut node0, &mut node1, &mut node2]);

    node0.create_block(1u64, network_signing_key);

    dbg!("creating a block 2");

    block_on(node0.synchronize());
    block_on(node1.synchronize());
    block_on(node2.synchronize());

    mailbox.process_must_succeed(&mut [&mut node0, &mut node1, &mut node2]);

    block_on(node0.synchronize());
    block_on(node1.synchronize());
    block_on(node2.synchronize());

    mailbox.process_must_succeed(&mut [&mut node0, &mut node1, &mut node2]);

    block_on(node0.synchronize());
    block_on(node1.synchronize());
    block_on(node2.synchronize());

    mailbox.process_must_succeed(&mut [&mut node0, &mut node1, &mut node2]);
}
