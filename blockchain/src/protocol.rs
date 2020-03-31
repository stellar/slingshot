//! Blockchain protocol implementation.
//! This is an implementation of a p2p protocol to synchronize
//! mempool transactions and blocks.

use core::convert::AsRef;
use core::hash::Hash;
use std::collections::hash_map::RandomState;
use std::collections::{HashMap, HashSet};
use std::fmt::Debug;
use std::time::Instant;

use async_trait::async_trait;
use merlin::Transcript;
use rand::{thread_rng, Rng};
use serde::{Deserialize, Serialize};
use starsig::{Signature, SigningKey, VerificationKey};
use zkvm::bulletproofs::BulletproofGens;
use zkvm::{ContractID, VerifiedTx};

use super::block::{BlockHeader, BlockID, BlockTx};
use super::errors::BlockchainError;
use super::mempool::Mempool;
use super::shortid::{self, ShortIDVec};
use super::state::BlockchainState;
use super::utreexo;

const CURRENT_VERSION: u64 = 0;
const SHORTID_NONCE_TTL: usize = 50; // number of sync cycles

#[async_trait]
pub trait Delegate {
    type PeerIdentifier: Clone + AsRef<[u8]> + Eq + Hash + Debug;

    /// ID of our node.
    fn self_id(&self) -> Self::PeerIdentifier;

    /// Send a message to a given peer.
    async fn send(&mut self, peer: Self::PeerIdentifier, message: Message);

    /// Returns current height of the chain.
    /// Default implementation calls `tip().0.height`.
    fn tip_height(&self) -> u64 {
        self.tip().0.height
    }

    /// Returns ID of the current tip.
    fn tip_id(&self) -> BlockID {
        self.tip().0.id()
    }

    /// Returns the signed tip of the blockchain
    fn tip(&self) -> (BlockHeader, Signature);

    /// Returns a block at a given height
    fn block_at_height(&self, height: u64) -> Option<Block>;

    /// Blockchain state
    fn blockchain_state(&self) -> &BlockchainState;

    /// Stores a new block and an updated state.
    /// Guaranteed to be called monotonically for blocks with height=2, then 3, etc.
    fn store_block(
        &mut self,
        block: Block,
        new_state: BlockchainState,
        catchup: utreexo::Catchup,
        vtxs: Vec<VerifiedTx>,
    );
}

pub struct Node<D: Delegate> {
    network_pubkey: VerificationKey,
    delegate: D,
    target_tip: BlockHeader,
    peers: HashMap<D::PeerIdentifier, PeerInfo>,
    shortid_nonce: u64,
    shortid_nonce_ttl: usize,
    mempool: Mempool,
    bp_gens: BulletproofGens,
    inventory_interval_secs: u64,
}

impl<D: Delegate> Node<D> {
    /// Create a new node.
    pub fn new(network_pubkey: VerificationKey, delegate: D) -> Self {
        let state = delegate.blockchain_state().clone();
        let tip = state.tip.clone();
        Node {
            network_pubkey,
            delegate,
            mempool: Mempool::new(state, tip.timestamp_ms),
            target_tip: tip,
            bp_gens: BulletproofGens::new(256, 1),
            peers: HashMap::new(),
            shortid_nonce: thread_rng().gen::<u64>(),
            shortid_nonce_ttl: SHORTID_NONCE_TTL,
            inventory_interval_secs: 60,
        }
    }

    /// Sets the interval (in seconds) to request inventory from the peers.
    /// If set to zero, the inventory is requested on every invocation of `synchronize`.
    pub fn set_inventory_interval(mut self, secs: u64) -> Self {
        self.inventory_interval_secs = secs;
        self
    }

    /// Creates a new network.
    pub fn new_network<I>(
        network_signing_key: SigningKey,
        timestamp_ms: u64,
        utxos: I,
    ) -> (BlockchainState, Signature, Vec<utreexo::Proof>)
    where
        I: IntoIterator<Item = ContractID> + Clone,
    {
        let (state, proofs) = BlockchainState::make_initial(timestamp_ms, utxos);
        let signature = create_block_signature(&state.tip, network_signing_key);
        (state, signature, proofs)
    }

    /// Called when a node receives a message from the peer.
    pub async fn process_message(
        &mut self,
        pid: D::PeerIdentifier,
        message: Message,
    ) -> Result<(), BlockchainError> {
        // TODO: represent ban scenarios with subcategory of errors and ban here.
        match message {
            Message::GetInventory(request) => self.process_inventory_request(pid, request).await?,
            Message::Inventory(inventory) => self.receive_inventory(pid, inventory).await?,
            Message::GetBlock(request) => self.send_block(pid, request).await?,
            Message::Block(block_msg) => self.receive_block(block_msg)?,
            Message::GetMempoolTxs(request) => self.send_txs(pid, request).await,
            Message::MempoolTxs(request) => self.receive_txs(request).await?,
        }
        Ok(())
    }

    /// Called periodically (every 1-2 seconds).
    pub async fn synchronize(&mut self) {
        self.rotate_shortid_nonce_if_needed();

        let (tip_header, tip_signature) = self.delegate.tip();

        for (pid, peer) in self.peers.iter().filter(|(_, p)| p.needs_our_inventory) {
            let msg = Message::Inventory(Inventory {
                version: CURRENT_VERSION,
                tip: tip_header.clone(),
                tip_signature: tip_signature.clone(),
                shortid_nonce: peer.their_short_id_nonce,
                shortid_list: self
                    .mempool_inventory_for_peer(pid.clone(), peer.their_short_id_nonce),
            });
            self.delegate.send(pid.clone(), msg).await;
        }

        for (_pid, peer) in self.peers.iter_mut() {
            peer.needs_our_inventory = false;
        }

        if self.target_tip.id() != self.delegate.tip_id() {
            self.synchronize_chain().await;
        } else {
            self.synchronize_mempool().await;
        }

        // For peers who have not sent inventory for over a minute, we request inventory again.
        let now = Instant::now();
        let interval_secs = self.inventory_interval_secs;
        let invpids: Vec<_> = self
            .peers
            .iter()
            .filter(|(_, peer)| {
                now.duration_since(peer.last_inventory_received).as_secs() >= interval_secs
            })
            .map(|(pid, _)| pid.clone())
            .collect();
        for pid in invpids.into_iter() {
            self.request_inventory(pid).await;
        }
    }

    /// Called when a peer connects.
    pub async fn peer_connected(&mut self, pid: D::PeerIdentifier) {
        self.peers.insert(
            pid.clone(),
            PeerInfo {
                tip: None,
                needs_our_inventory: false,
                their_short_id_nonce: 0,
                shortid_nonce: self.shortid_nonce,
                shortid_list: ShortIDVec(Vec::new()),
                last_inventory_received: Instant::now(),
            },
        );

        self.request_inventory(pid).await;
    }

    /// Called when a peer disconnects.
    pub async fn peer_diconnected(&mut self, pid: D::PeerIdentifier) {
        self.peers.remove(&pid);
    }

    /// Adds transaction to the mempool.
    pub fn submit_tx(&mut self, tx: BlockTx) -> Result<(), BlockchainError> {
        let _ = self.mempool.append(tx, &self.bp_gens)?;
        Ok(())
    }

    /// Creates and signs block, and updates the state.
    /// The API makes sure that the node state is update with the new block,
    /// so the user cannot accidentally sign two conflicting blocks.
    /// Obviously, a multi-party signing, SCP or any other decentralized consensus algorithm
    /// would have a different API.
    pub fn create_block(&mut self, timestamp_ms: u64, signing_key: SigningKey) {
        // Note: we don't need to do that if all tx.maxtime's are 1-2 blocks away.
        // TODO: rethink whether we actually need the maxtime at all. It is not needed for relative timelocks in paychans,
        // and it is not helping with clearing up the mempool spam.
        let timestamp_ms = core::cmp::max(timestamp_ms, self.delegate.tip().0.timestamp_ms);
        self.mempool.update_timestamp(timestamp_ms);

        // Note: we currently assume that the entire mempool is converted into a block,
        // so we convert all the entries into the transactions.
        let (new_state, catchup) = self.mempool.make_block();

        let signature = create_block_signature(&new_state.tip, signing_key);

        let block = Block {
            header: new_state.tip.clone(),
            signature,
            txs: self
                .mempool
                .entries()
                .map(|e| e.block_tx())
                .cloned()
                .collect::<Vec<_>>(),
        };

        let vtxs = self
            .mempool
            .entries()
            .map(|e| e.verified_tx())
            .cloned()
            .collect::<Vec<_>>();

        // Update the mempool
        self.mempool.update_state(new_state.clone(), &catchup);

        // Store the block
        self.delegate.store_block(block, new_state, catchup, vtxs);
    }

    /// Returns the ID of this node.
    pub fn id(&self) -> D::PeerIdentifier {
        self.delegate.self_id()
    }
}

impl<D: Delegate> Node<D> {
    async fn synchronize_chain(&mut self) {
        use rand::seq::IteratorRandom;

        // Request the next block from a random peer.
        // This is highly inefficient from the point of view of the node,
        // but spreads the load on the network that prioritizes synchronizing
        // recent transactions and blocks.
        if let Some((pid, _peer)) = self.peers.iter().choose(&mut thread_rng()) {
            self.delegate
                .send(
                    pid.clone(),
                    Message::GetBlock(GetBlock {
                        height: self.delegate.tip_height() + 1,
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
        let shortener =
            shortid::Transform::new(self.shortid_nonce, self.delegate.self_id().as_ref());

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
                if let Some(id) = peer.shortid_list.get(offset) {
                    done = false;
                    if assigned_shortids.insert(id) {
                        let req = requests
                            .entry(pid.clone())
                            .or_insert_with(|| GetMempoolTxs {
                                shortid_nonce: current_nonce,
                                shortid_list: ShortIDVec::with_capacity(10),
                            });
                        req.shortid_list.0.extend_from_slice(&id.to_bytes()[..]);
                    }
                }
            }
            if done {
                // no more ids left in any peer, so we proceed to sending out requests.
                break;
            }
        }

        for (pid, req) in requests.into_iter() {
            self.delegate.send(pid, Message::GetMempoolTxs(req)).await;
        }
    }

    async fn process_inventory_request(
        &mut self,
        pid: D::PeerIdentifier,
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

    async fn request_inventory(&mut self, pid: D::PeerIdentifier) {
        self.delegate
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
        pid: D::PeerIdentifier,
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
            self.target_tip = tip.clone();
        }

        // store the inventory until we figure out what we are missing per-peer in `synchronize_mempool`.
        self.peers.get_mut(&pid).map(|peer| {
            peer.tip = Some(tip);
            peer.shortid_nonce = shortid_nonce;
            peer.shortid_list = shortid_list;
        });

        Ok(())
    }

    async fn send_block(
        &mut self,
        pid: D::PeerIdentifier,
        request: GetBlock,
    ) -> Result<(), BlockchainError> {
        let block = self
            .delegate
            .block_at_height(request.height)
            .ok_or(BlockchainError::BlockNotFound(request.height))?;
        self.delegate.send(pid, Message::Block(block)).await;
        Ok(())
    }

    fn receive_block(&mut self, block_msg: Block) -> Result<(), BlockchainError> {
        // Quick check: is this actually a block that we want?
        if block_msg.header.height != self.delegate.tip_height() + 1 {
            // Silently ignore the irrelevant block - maybe we received it too late.
            return Err(BlockchainError::BlockNotRelevant(block_msg.header.height));
        }

        // Check the block signature.
        if !verify_block_signature(&block_msg.header, &block_msg.signature, self.network_pubkey) {
            return Err(BlockchainError::InvalidBlockSignature);
        }

        // Now the block header is authenticated, so we can do a more expensive validation.

        let state = self.delegate.blockchain_state();
        let (new_state, catchup, vtxs) =
            state.apply_block(block_msg.header.clone(), &block_msg.txs, &self.bp_gens)?;

        // Update the mempool.
        self.mempool.update_state(new_state.clone(), &catchup);

        // Store the block
        self.delegate
            .store_block(block_msg, new_state, catchup, vtxs);

        Ok(())
    }

    async fn send_txs(&mut self, pid: D::PeerIdentifier, request: GetMempoolTxs) {
        use core::iter::FromIterator;

        let shortener = shortid::Transform::new(request.shortid_nonce, pid.as_ref());
        let requested_shortids = HashSet::<_, RandomState>::from_iter(request.shortid_list.iter());

        let mut response = MempoolTxs {
            tip: self.delegate.tip_id(),
            txs: Vec::with_capacity(request.shortid_list.len()),
        };

        for entry in self.mempool.entries() {
            let id = shortener.apply(entry.txid().as_ref());
            if requested_shortids.contains(&id) {
                response.txs.push(entry.block_tx().clone());
            }
        }

        self.delegate.send(pid, Message::MempoolTxs(response)).await;
    }

    async fn receive_txs(&mut self, request: MempoolTxs) -> Result<(), BlockchainError> {
        if request.tip != self.delegate.tip_id() {
            return Err(BlockchainError::StaleMempoolState(request.tip));
        }

        for tx in request.txs.into_iter() {
            let result = self.mempool.append(tx, &self.bp_gens);
            if let Err(err) = result {
                if let BlockchainError::UtreexoError(_) = err {
                    // Two nodes may have sent us double-spends, w/o being aware of them.
                    // that's not their fault.
                } else {
                    // Stop processing all remaining txs - the node is sending us garbage.
                    return Err(err);
                }
            }
        }

        Ok(())
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

    fn mempool_inventory_for_peer(&self, pid: D::PeerIdentifier, nonce: u64) -> ShortIDVec {
        let mut result = ShortIDVec::with_capacity(self.mempool.len());
        let shortener = shortid::Transform::new(nonce, &pid.as_ref());
        for entry in self.mempool.entries() {
            let shortid = shortener.apply(&entry.txid());
            result.push(shortid);
        }
        result
    }
}

/// Status of the peer.
struct PeerInfo {
    tip: Option<BlockHeader>,
    needs_our_inventory: bool,
    their_short_id_nonce: u64,
    shortid_nonce: u64,
    shortid_list: ShortIDVec,
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
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Message {
    GetInventory(GetInventory),
    Inventory(Inventory),
    GetBlock(GetBlock),
    Block(Block),
    GetMempoolTxs(GetMempoolTxs),
    MempoolTxs(MempoolTxs),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GetInventory {
    version: u64,
    shortid_nonce: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Inventory {
    version: u64,
    tip: BlockHeader,
    tip_signature: Signature,
    shortid_nonce: u64,
    shortid_list: ShortIDVec,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GetBlock {
    height: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Block {
    pub(crate) header: BlockHeader,
    pub(crate) signature: Signature,
    pub(crate) txs: Vec<BlockTx>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GetMempoolTxs {
    shortid_nonce: u64,
    shortid_list: ShortIDVec,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MempoolTxs {
    tip: BlockID,
    txs: Vec<BlockTx>,
}
