use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use rand::RngCore;
use zkvm::bulletproofs::BulletproofGens;

use super::*;
use zkvm::{
    Anchor, Commitment, Contract, ContractID, Multisignature, PortableItem, Predicate, Program,
    Prover, Signature, String, TxHeader, Value, VerificationKey, VerifiedTx,
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
    let (state, proofs) = BlockchainState::make_initial(0u64, vec![initial_contract.id()]);

    let tx = {
        let program = Program::build(|p| {
            p.push(initial_contract.clone())
                .input()
                .signtx()
                .push(make_predicate(2u64))
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
        proofs: proofs.clone(),
    };

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
    use starsig::{Signature, SigningKey, VerificationKey};
    use std::cell::RefCell;
    use std::sync::{Arc, Mutex};

    type PID = [u8; 1];

    struct MockNode {
        id: PID,
        state: BlockchainState,
        blocks: Vec<Block>, // i=0 -> height=1, etc
        mailbox: Arc<Mutex<Mailbox>>,
    }

    #[derive(Debug)]
    struct Mailbox {
        msgs: Vec<(PID, Message)>,
    }

    impl Mailbox {
        fn process(
            &mut self,
            nodes: &mut [&mut Node<MockNode>],
        ) -> Vec<(PID, Result<(), BlockchainError>)> {
            let mut r = Vec::new();
            while let Some((pid, msg)) = self.msgs.pop() {
                dbg!((pid, &msg));
                let result = block_on(nodes[pid[0] as usize].process_message(pid, msg));
                r.push((pid, result));
            }
            r
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
        async fn send(&mut self, peer: Self::PeerIdentifier, message: Message) {
            self.mailbox.lock().unwrap().msgs.push((peer, message));
        }

        /// Returns the signed tip of the blockchain
        fn tip(&self) -> (BlockHeader, Signature) {
            (self.state.tip.clone(), self.blocks[0].signature.clone())
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
            self.blocks.push(block);
            self.state = new_state;
        }
    }

    let bp_gens = BulletproofGens::new(256, 1);
    let network_signing_key = Scalar::from(9000u64);
    let network_pubkey = VerificationKey::from_secret(&network_signing_key);

    let wallet_privkey = Scalar::from(1u64);
    let initial_contract = make_nonce_contract(1, 100);
    let (state, block_sig, proofs) =
        Node::<MockNode>::new_network(network_signing_key, 0, vec![initial_contract.id()]);

    let mailbox = Arc::new(Mutex::new(Mailbox { msgs: Vec::new() }));

    let mut nodes = (0..3)
        .map(|pid| MockNode {
            id: [pid],
            state: state.clone(),
            blocks: vec![Block {
                header: state.tip.clone(),
                signature: block_sig.clone(),
                txs: Vec::new(),
            }],
            mailbox: Arc::clone(&mailbox),
        })
        .map(|mock| Node::new(network_pubkey, mock));

    // Now all the nodes have the same state and can make transactions.
    let mut node0 = nodes.next().unwrap();
    let mut node1 = nodes.next().unwrap();
    let mut node2 = nodes.next().unwrap();

    // connect all the peers to each other
    block_on(node0.peer_connected(node1.id()));
    block_on(node1.peer_connected(node0.id()));

    block_on(node2.peer_connected(node1.id()));
    block_on(node1.peer_connected(node2.id()));

    block_on(node2.peer_connected(node0.id()));
    block_on(node0.peer_connected(node2.id()));

    let results = mailbox
        .lock()
        .unwrap()
        .process(&mut [&mut node0, &mut node1, &mut node2]);
    assert!(results.into_iter().all(|(pid, r)| r.is_ok()));
}
