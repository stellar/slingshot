//! Blockchain protocol implementation.
//! This is an implementation of a p2p protocol to synchronize
//! mempool transactions and blocks.

use async_trait::async_trait;
use core::convert::AsRef;
use core::hash::Hash;
use rand::{thread_rng, Rng};
use serde::{Deserialize, Serialize};
use starsig::{Signature, VerificationKey};
use std::collections::HashMap;
use std::time::{Duration, Instant};

use super::block::{BlockHeader, BlockID};
use super::shortid::{self, ShortID};
use super::state::Mempool;
use super::utreexo;
use zkvm::Tx;

const CURRENT_VERSION: u64 = 0;
const SHORTID_NONCE_TTL: usize = 50;

#[async_trait]
pub trait Network {
    type PeerIdentifier: Clone + AsRef<[u8]> + Eq + Hash;

    /// ID of our node.
    fn self_id(&self) -> Self::PeerIdentifier;

    /// Send a message to a given peer.
    async fn send(&mut self, peer: Self::PeerIdentifier, message: Message);
}

pub trait Storage {
    /// Returns the signed tip of the blockchain
    fn tip(&self) -> (BlockHeader, Signature);

    /// Returns a block header signature at a given height.
    fn block_signature_at_height(&self, height: u64) -> Signature;

    /// Returns a block at a given height
    fn block_at_height(&self, height: u64) -> BlockHeader;
}

pub enum ProtocolError {
    IncompatibleVersion,
}

pub struct Node<N: Network, S: Storage> {
    network_pubkey: VerificationKey,
    network: N,
    storage: S,
    target_tip: BlockHeader,
    peers: HashMap<N::PeerIdentifier, PeerInfo>,
    shortid_nonce: u64,
    shortid_nonce_ttl: usize,
    // TBD: add mempool in here
}

impl<N: Network, S: Storage> Node<N, S> {
    /// Create a new node.
    pub fn new(network_pubkey: VerificationKey, network: N, storage: S) -> Self {
        let tip = storage.tip().0;
        Node {
            network_pubkey,
            network,
            storage,
            target_tip: tip,
            peers: HashMap::new(),
            shortid_nonce: thread_rng().gen::<u64>(),
            shortid_nonce_ttl: SHORTID_NONCE_TTL,
        }
    }

    /// Called when a node receives a message from the peer.
    pub async fn process_message(
        &mut self,
        pid: N::PeerIdentifier,
        message: Message,
    ) -> Result<(), ProtocolError> {
        match message {
            Message::GetInventory(msg) => self.process_inventory_request(pid, msg).await?,
            Message::Inventory(msg) => self.receive_inventory(pid, msg).await,
            Message::GetBlock(msg) => self.send_block(pid, msg).await,
            Message::Block(msg) => self.receive_block(pid, msg).await,
            Message::GetMempoolTxs(msg) => self.send_txs(pid, msg).await,
            Message::MempoolTxs(msg) => self.receive_txs(pid, msg).await,
        }
        Ok(())
    }

    /// Called periodically (every 1-2 seconds).
    pub async fn synchronize(&mut self) {
        self.rotate_shortid_nonce_if_needed();

        let (tip_header, tip_signature) = self.storage.tip();

        for (pid, peer) in self.peers.iter().filter(|(_, p)| p.needs_our_inventory) {
            self.network
                .send(
                    pid.clone(),
                    Message::Inventory(Inventory {
                        version: CURRENT_VERSION,
                        tip: tip_header.clone(),
                        tip_signature: tip_signature.clone(),
                        shortid_nonce: peer.their_short_id_nonce,
                        shortid_list: self
                            .mempool_inventory_for_peer(pid, peer.their_short_id_nonce),
                    }),
                )
                .await;
        }

        for (pid, peer) in self.peers.iter_mut() {
            peer.needs_our_inventory = false;
        }

        if self.target_tip.id() != self.storage.tip().0.id() {
            self.synchronize_chain().await;
        } else {
            self.synchronize_mempool().await;
        }

        // For peers who have not sent inventory for over a minute, we request inventory again.
        let now = Instant::now();
        let interval_secs = 60;
        let invpids: Vec<_> = self
            .peers
            .iter()
            .filter(|(_, peer)| {
                now.duration_since(peer.last_inventory_received).as_secs() > interval_secs
            })
            .map(|(pid, _)| pid.clone())
            .collect();
        for pid in invpids.into_iter() {
            self.request_inventory(pid).await;
        }
    }

    /// Called when a peer connects.
    pub async fn peer_connected(&mut self, pid: N::PeerIdentifier) {
        self.peers.insert(
            pid.clone(),
            PeerInfo {
                tip: None,
                needs_our_inventory: false,
                their_short_id_nonce: 0,
                missing_shortids: Vec::new(),
                shortid_nonce: self.shortid_nonce,
                last_inventory_received: Instant::now(),
            },
        );

        self.request_inventory(pid).await;
    }

    /// Called when a peer disconnects.
    pub async fn peer_diconnected(&mut self, pid: N::PeerIdentifier) {
        self.peers.remove(&pid);
    }
}

impl<N: Network, S: Storage> Node<N, S> {
    async fn synchronize_chain(&mut self) {}

    async fn synchronize_mempool(&mut self) {
        // 3. **If the target tip is the latest**, the node walks all peers in round-robin and constructs lists of [short IDs](#short-id) to request from each peer,
        //    keeping track of already used IDs. Once all requests are constructed, the [`GetMempoolTxs`](#getmempooltxs) messages are sent out to respective peers.
    }

    async fn process_inventory_request(
        &mut self,
        pid: N::PeerIdentifier,
        request: GetInventory,
    ) -> Result<(), ProtocolError> {
        // FIXME: check the version across all messages
        if request.version != CURRENT_VERSION {
            return Err(ProtocolError::IncompatibleVersion);
        }
        self.peers.get_mut(&pid).map(|peer| {
            peer.needs_our_inventory = true;
            peer.their_short_id_nonce = request.shortid_nonce;
        });
        Ok(())
    }

    async fn request_inventory(&mut self, pid: N::PeerIdentifier) {
        self.network
            .send(
                pid,
                Message::GetInventory(GetInventory {
                    version: CURRENT_VERSION,
                    shortid_nonce: self.shortid_nonce,
                }),
            )
            .await;
    }

    async fn receive_inventory(&mut self, pid: N::PeerIdentifier, inventory: Inventory) {}

    async fn receive_block(&mut self, pid: N::PeerIdentifier, block_msg: Block) {}

    async fn receive_txs(&mut self, pid: N::PeerIdentifier, request: MempoolTxs) {}

    async fn send_block(&mut self, pid: N::PeerIdentifier, request: GetBlock) {}

    async fn send_txs(&mut self, pid: N::PeerIdentifier, request: GetMempoolTxs) {}

    fn rotate_shortid_nonce_if_needed(&mut self) {
        self.shortid_nonce_ttl -= 1;
        if self.shortid_nonce_ttl == 0 {
            self.shortid_nonce_ttl = SHORTID_NONCE_TTL;
            let new_nonce = thread_rng().gen::<u64>();
            self.shortid_nonce = new_nonce;
            for (pid, peer) in self.peers.iter_mut() {
                peer.shortid_nonce = new_nonce;
                peer.missing_shortids.clear();
            }
        }
    }

    fn mempool_inventory_for_peer(&self, pid: &N::PeerIdentifier, nonce: u64) -> Vec<u8> {
        // TBD: list txs in mempool and convert them into short ids.
        unimplemented!()
    }
}

/// Enumeration of all protocol messages
#[derive(Clone, Serialize, Deserialize)]
pub enum Message {
    GetInventory(GetInventory),
    Inventory(Inventory),
    GetBlock(GetBlock),
    Block(Block),
    GetMempoolTxs(GetMempoolTxs),
    MempoolTxs(MempoolTxs),
}

#[derive(Clone, Serialize, Deserialize)]
pub struct GetInventory {
    version: u64,
    shortid_nonce: u64,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Inventory {
    version: u64,
    tip: BlockHeader,
    tip_signature: Signature,
    shortid_nonce: u64,
    shortid_list: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct GetBlock {
    height: u64,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Block {
    header: BlockHeader,
    signature: Signature,
    txs: Vec<BlockTx>,
}

/// Transaction annotated with Utreexo proofs.
#[derive(Clone, Serialize, Deserialize)]
pub struct BlockTx {
    /// Utreexo proofs.
    pub proofs: Vec<utreexo::Proof>,
    /// ZkVM transaction.
    pub tx: Tx,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct GetMempoolTxs {
    shortid_nonce: u64,
    shortids: Vec<ShortID>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct MempoolTxs {
    tip: BlockID,
    txs: Vec<BlockTx>,
}

struct PeerInfo {
    tip: Option<BlockHeader>,
    needs_our_inventory: bool,
    their_short_id_nonce: u64,
    missing_shortids: Vec<ShortID>,
    shortid_nonce: u64,
    last_inventory_received: Instant,
}
