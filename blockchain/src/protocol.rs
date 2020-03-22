//! Blockchain protocol implementation.
//! This is an implementation of a p2p protocol to synchronize
//! mempool transactions and blocks.

use async_trait::async_trait;
use core::convert::AsRef;
use core::hash::Hash;
use rand::{thread_rng, Rng};
use serde::{Deserialize, Serialize};
use starsig::{Signature, SigningKey, VerificationKey};
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use super::block::{BlockHeader, BlockID, BlockTx};
use super::errors::BlockchainError;
use super::mempool::Mempool;
use super::shortid::{self, ShortID};
use super::state::BlockchainState;
use super::utreexo;
use merlin::Transcript;
use zkvm::bulletproofs::BulletproofGens;
use zkvm::{Tx, VerifiedTx};

const CURRENT_VERSION: u64 = 0;
const SHORTID_NONCE_TTL: usize = 50; // number of sync cycles

#[async_trait]
pub trait Network {
    type PeerIdentifier: Clone + AsRef<[u8]> + Eq + Hash;

    /// ID of our node.
    fn self_id(&self) -> Self::PeerIdentifier;

    /// Send a message to a given peer.
    async fn send(&mut self, peer: Self::PeerIdentifier, message: Message);

    /// Asks the network to disconnect the peer.
    /// Will receive `disconnect()` call as a result.
    async fn disconnect(&mut self, peer: Self::PeerIdentifier);
}

pub trait Storage {
    /// Returns current height of the chain.
    /// Default implementation calls `tip().0.height`.
    fn tip_height(&self) -> u64 {
        self.tip().0.height
    }

    /// Returns the signed tip of the blockchain
    fn tip(&self) -> (BlockHeader, Signature);

    /// Returns a block at a given height
    fn block_at_height(&self, height: u64) -> Option<Block>;

    /// Blockchain state
    fn blockchain_state(&self) -> &BlockchainState;

    /// Stores the new block and an updated state.
    fn store_block(
        &mut self,
        block: Block,
        new_state: BlockchainState,
        catchup: utreexo::Catchup,
        vtxs: Vec<VerifiedTx>,
    );
}

pub struct Node<N: Network, S: Storage> {
    network_pubkey: VerificationKey,
    network: N,
    storage: S,
    target_tip: BlockHeader,
    peers: HashMap<N::PeerIdentifier, PeerInfo>,
    shortid_nonce: u64,
    shortid_nonce_ttl: usize,
    mempool: Mempool,
    bp_gens: BulletproofGens,
}

impl<N: Network, S: Storage> Node<N, S> {
    /// Create a new node.
    pub fn new(network_pubkey: VerificationKey, network: N, storage: S) -> Self {
        let state = storage.blockchain_state().clone();
        let tip = state.tip.clone();
        Node {
            network_pubkey,
            network,
            storage,
            mempool: Mempool::new(state, tip.timestamp_ms),
            target_tip: tip,
            bp_gens: BulletproofGens::new(256, 1),
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
    ) -> Result<(), BlockchainError> {
        // TODO: represent ban scenarios with subcategory of errors and ban here.
        match message {
            Message::GetInventory(request) => self.process_inventory_request(pid, request).await?,
            Message::Inventory(inventory) => self.receive_inventory(pid, inventory).await?,
            Message::GetBlock(request) => self.send_block(pid, request).await?,
            Message::Block(block_msg) => self.receive_block(pid, block_msg).await?,
            Message::GetMempoolTxs(request) => self.send_txs(pid, request).await,
            Message::MempoolTxs(request) => self.receive_txs(pid, request).await,
        }
        Ok(())
    }

    /// Called periodically (every 1-2 seconds).
    pub async fn synchronize(&mut self) {
        self.rotate_shortid_nonce_if_needed();

        let (tip_header, tip_signature) = self.storage.tip();

        for (pid, peer) in self.peers.iter().filter(|(_, p)| p.needs_our_inventory) {
            let msg = Message::Inventory(Inventory {
                version: CURRENT_VERSION,
                tip: tip_header.clone(),
                tip_signature: tip_signature.clone(),
                shortid_nonce: peer.their_short_id_nonce,
                shortid_list: self
                    .mempool_inventory_for_peer(pid.clone(), peer.their_short_id_nonce),
            });
            self.network.send(pid.clone(), msg).await;
        }

        for (_pid, peer) in self.peers.iter_mut() {
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
                shortid_nonce: self.shortid_nonce,
                shortid_list: Vec::new(),
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
    async fn synchronize_chain(&mut self) {
        use rand::seq::IteratorRandom;

        // Request the next block from a random peer.
        // This is highly inefficient from the point of view of the node,
        // but spreads the load on the network that prioritizes synchronizing
        // recent transactions and blocks.
        if let Some((pid, _peer)) = self.peers.iter().choose(&mut thread_rng()) {
            self.network
                .send(
                    pid.clone(),
                    Message::GetBlock(GetBlock {
                        height: self.storage.tip_height() + 1,
                    }),
                )
                .await;
        }
    }

    async fn synchronize_mempool(&mut self) {
        // **If the target tip is the latest**, the node walks all peers in round-robin and constructs lists of [short IDs](#short-id) to request from each peer,
        // keeping track of already used IDs. Once all requests are constructed, the [`GetMempoolTxs`](#getmempooltxs) messages are sent out to respective peers.

        let current_nonce = self.shortid_nonce;
        let mut assigned_shortids = HashSet::new();
        let mut shortener =
            shortid::Transform::new(self.shortid_nonce, self.network.self_id().as_ref());

        // First, add all the mempool entries to the assigned set
        // FIXME: keep this set around and update per-tx, so we don't recalculate it on every sync.
        for entry in self.mempool.entries() {
            let id = shortener.apply(entry.txid().as_ref());
            assigned_shortids.insert(id);
        }
        // Then, walk all the peers and assign shortids to fetch using round-robin.
        let mut requests = HashMap::new();
        for offset in 0..1_000_000 {
            let mut done = true;
            for (pid, peer) in self.peers.iter_mut() {
                if let Some(id) = ShortID::at_position(offset, &peer.shortid_list) {
                    done = false;
                    if assigned_shortids.insert(id) {
                        let req = requests
                            .entry(pid.clone())
                            .or_insert_with(|| GetMempoolTxs {
                                shortid_nonce: current_nonce,
                                shortid_list: Vec::with_capacity(10 * shortid::SHORTID_LEN),
                            });
                        req.shortid_list.extend_from_slice(&id.to_bytes()[..]);
                    }
                }
            }
            if done {
                // no more ids left in any peer, so we proceed to sending out requests.
                break;
            }
        }

        for (pid, req) in requests.into_iter() {
            self.network.send(pid, Message::GetMempoolTxs(req)).await;
        }
    }

    async fn process_inventory_request(
        &mut self,
        pid: N::PeerIdentifier,
        request: GetInventory,
    ) -> Result<(), BlockchainError> {
        // FIXME: check the version across all messages
        if request.version != CURRENT_VERSION {
            return Err(BlockchainError::IncompatibleVersion);
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

    async fn receive_inventory(
        &mut self,
        pid: N::PeerIdentifier,
        inventory: Inventory,
    ) -> Result<(), BlockchainError> {
        let Inventory {
            version,
            tip,
            tip_signature,
            shortid_nonce,
            shortid_list,
        } = inventory;

        // FIXME: check the version across all messages
        if version != CURRENT_VERSION {
            return Err(BlockchainError::IncompatibleVersion);
        }

        if tip.height > self.target_tip.height {
            // check the signature and update the target tip
            if !verify_block_signature(&tip, &tip_signature, self.network_pubkey) {
                return Err(BlockchainError::InvalidBlockSignature);
            }
            self.target_tip = tip;
        }

        // store the inventory until we figure out what we are missing per-peer in `synchronize_mempool`.
        self.peers.get_mut(&pid).map(|peer| {
            peer.shortid_nonce = shortid_nonce;
            peer.shortid_list = shortid_list;
        });

        Ok(())
    }

    async fn send_block(
        &mut self,
        pid: N::PeerIdentifier,
        request: GetBlock,
    ) -> Result<(), BlockchainError> {
        let block = self
            .storage
            .block_at_height(request.height)
            .ok_or(BlockchainError::BlockNotFound(request.height))?;
        self.network.send(pid, Message::Block(block)).await;
        Ok(())
    }

    async fn receive_block(
        &mut self,
        pid: N::PeerIdentifier,
        block_msg: Block,
    ) -> Result<(), BlockchainError> {
        // Quick check: is this actually a block that we want?
        if block_msg.header.height != self.storage.tip_height() + 1 {
            // Silently ignore the irrelevant block - maybe we received it too late.
            return Err(BlockchainError::BlockNotRelevant(block_msg.header.height));
        }

        // Check the block signature.
        if !verify_block_signature(&block_msg.header, &block_msg.signature, self.network_pubkey) {
            return Err(BlockchainError::InvalidBlockSignature);
        }

        // Now the block header is authenticated, so we can do a more expensive validation.

        let state = self.storage.blockchain_state();
        let (new_state, catchup, vtxs) =
            state.apply_block(block_msg.header.clone(), &block_msg.txs, &self.bp_gens)?;

        // Update the mempool.
        self.mempool.update_state(new_state.clone(), &catchup);

        // Store the block
        self.storage
            .store_block(block_msg, new_state, catchup, vtxs);

        Ok(())
    }

    async fn send_txs(&mut self, pid: N::PeerIdentifier, request: GetMempoolTxs) {
        unimplemented!()
    }

    async fn receive_txs(&mut self, pid: N::PeerIdentifier, request: MempoolTxs) {
        unimplemented!()
    }

    fn rotate_shortid_nonce_if_needed(&mut self) {
        self.shortid_nonce_ttl -= 1;
        if self.shortid_nonce_ttl == 0 {
            self.shortid_nonce_ttl = SHORTID_NONCE_TTL;
            let new_nonce = thread_rng().gen::<u64>();
            self.shortid_nonce = new_nonce;
            for (_pid, peer) in self.peers.iter_mut() {
                peer.shortid_nonce = new_nonce;
                peer.shortid_list.clear();
            }
        }
    }

    fn mempool_inventory_for_peer(&self, pid: N::PeerIdentifier, nonce: u64) -> Vec<u8> {
        let mut result = Vec::with_capacity(self.mempool.len() * shortid::SHORTID_LEN);
        let shortener = shortid::Transform::new(nonce, &pid.as_ref());
        for entry in self.mempool.entries() {
            let shortid = shortener.apply(&entry.txid());
            result.extend_from_slice(&shortid.to_bytes()[..]);
        }
        result
    }

    fn ban<T>(
        &mut self,
        pid: N::PeerIdentifier,
        error: BlockchainError,
    ) -> Result<T, BlockchainError> {
        // TODO: mark the peer as banned, remove from the list
        Err(error)
    }
}

/// Status of the peer.
struct PeerInfo {
    tip: Option<BlockHeader>,
    needs_our_inventory: bool,
    their_short_id_nonce: u64,
    shortid_nonce: u64,
    shortid_list: Vec<u8>,
    last_inventory_received: Instant,
}

/// Signs a block.
fn create_block_signature(header: &BlockHeader, privkey: SigningKey) -> Signature {
    let mut t = Transcript::new(b"ZkVM.stubnet1");
    t.append_message(b"block_id", &header.id());
    Signature::sign(&mut t, privkey)
}

fn verify_block_signature(
    header: &BlockHeader,
    signature: &Signature,
    pubkey: VerificationKey,
) -> bool {
    let mut t = Transcript::new(b"ZkVM.stubnet1");
    t.append_message(b"block_id", &header.id());
    signature.verify(&mut t, pubkey).is_ok()
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

#[derive(Clone, Serialize, Deserialize)]
pub struct GetMempoolTxs {
    shortid_nonce: u64,
    shortid_list: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct MempoolTxs {
    tip: BlockID,
    txs: Vec<BlockTx>,
}
