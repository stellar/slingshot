//! Blockchain protocol implementation.
//! This is an implementation of a p2p protocol to synchronize mempool transactions
//! and blocks.

use async_trait::async_trait;
use core::convert::AsRef;
use serde::{Deserialize, Serialize};
use starsig::Signature;

use super::block::{Block, BlockHeader, BlockID, BlockTx};
use super::shortid::{self, ShortID};
use super::utreexo;
use zkvm::Tx;

/// Stubnet signed block header.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedBlockHeader {
    pub header: BlockHeader,
    pub signature: Signature,
}

/// Storage interface to retrieve blocks
pub trait Storage {
    /// Returns the signed tip of the blockchain
    fn signed_tip(&self) -> SignedBlockHeader;

    /// Returns a block at a given height
    fn block_at_height(&self, height: u64) -> BlockHeader;

    /// Returns a tip of the blockchain
    fn tip(&self) -> BlockHeader {
        self.signed_tip().header
    }
}

#[async_trait]
pub trait Network {
    type ID: Clone + AsRef<[u8]>;

    /// Send a message to a given peer
    async fn send(peer: Self::ID, message: Message);
}

/// Enumeration of all protocol messages
pub enum Message {
    GetInventory(GetInventory),
    Inventory(Inventory),
    GetBlocks(GetBlocks),
    Blocks(Blocks),
    GetMempoolTxs(GetMempoolTxs),
    MempoolTxs(MempoolTxs),
}

pub struct GetInventory {
    version: u64,
    shortid_nonce: u64,
}

pub struct Inventory {
    version: u64,
    tip: SignedBlockHeader,
    shortid_nonce: u64,
    mempool: Vec<ShortID>,
}

pub struct GetBlocks {
    tip: BlockID,
    height: u64,
}

pub struct Blocks {
    blocks: Vec<Block>,
}

pub struct GetMempoolTxs {
    shortid_nonce: u64,
    shortids: Vec<ShortID>,
}

pub struct MempoolTxs {
    tip: BlockID,
    txs: Vec<BlockTx>,
}
