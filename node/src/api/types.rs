use serde::{Deserialize, Serialize};

use accounts::Receiver;

use super::serde_utils::BigArray;
use blockchain::BlockTx;
use std::convert::TryFrom;
use std::str::FromStr;
use zkvm::encoding::Encodable;

/// Stats about unconfirmed transactions.
#[derive(Serialize)]
pub struct MempoolStatus {
    /// Total number of transactions
    pub count: u64,
    /// Total size of all transactions in the mempool
    pub size: u64,
    /// Lowest feerate for inclusing in the block
    pub feerate: u64,
}

#[derive(Serialize)]
pub struct BlockHeader {
    pub version: u64,       // Network version.
    pub height: u64,        // Serial number of the block, starting with 1.
    pub prev: [u8; 32],     // ID of the previous block. Initial block uses the all-zero string.
    pub timestamp_ms: u64,  // Integer timestamp of the block in milliseconds since the Unix epoch
    pub txroot: [u8; 32], // 32-byte Merkle root of the transaction witness hashes (`BlockTx::witness_hash`) in the block.
    pub utxoroot: [u8; 32], // 32-byte Merkle root of the Utreexo state.
    pub ext: Vec<u8>,     // Extra data for the future extensions.
}

#[derive(Deserialize)]
pub struct TxHeader {
    pub version: u64,
    pub mintime_ms: u64,
    pub maxtime_ms: u64,
}

#[derive(Serialize)]
pub struct Block {
    pub header: BlockHeader,
    pub txs: Vec<BlockTx>,
}

#[derive(Serialize)]
pub struct Tx {
    pub id: [u8; 32],  // canonical tx id
    pub wid: [u8; 32], // witness hash of the tx (includes signatures and proofs)
    pub raw: String,
    pub fee: u64,  // fee paid by the tx
    pub size: u64, // size in bytes of the encoded tx
}

/// Description of the current blockchain state.
#[derive(Serialize)]
pub struct State {
    // Block header
    pub tip: BlockHeader,
    // The utreexo state
    #[serde(with = "BigArray")]
    pub utreexo: [Option<[u8; 32]>; 64],
}

/// Description of a connected peer.
#[derive(Serialize)]
pub struct Peer {
    pub id: [u8; 32],
    pub since: u64,
    /// ipv6 address format
    pub addr: [u8; 16],
    pub priority: u64,
}

#[derive(Serialize)]
pub enum AnnotatedAction {
    Issue(IssueAction),
    Spend(SpendAction),
    Receive(ReceiveAction),
    Retire(RetireAction),
    Memo(MemoAction),
}

#[derive(Serialize)]
pub struct IssueAction {
    // Index of the txlog entry
    pub entry: u32,
    pub qty: u64,
    pub flv: [u8; 32],
}

#[derive(Serialize)]
pub struct SpendAction {
    // Index of the txlog entry
    pub entry: u32,
    pub qty: u64,
    pub flv: [u8; 32],
    // Identifier of the account sending funds
    pub account: [u8; 32],
}

#[derive(Serialize)]
pub struct ReceiveAction {
    // Index of the txlog entry
    pub entry: u32,
    pub qty: u64,
    pub flv: [u8; 32],
    // Identifier of the account receiving funds (if known)
    pub account: Option<[u8; 32]>,
}

#[derive(Serialize)]
pub struct RetireAction {
    // Index of the txlog entry
    pub entry: u32,
    pub qty: u64,
    pub flv: [u8; 32],
}

#[derive(Serialize)]
pub struct MemoAction {
    pub entry: u32,
    pub data: Vec<u8>,
}

/// Description of the current blockchain state.
#[derive(Serialize)]
pub struct AnnotatedTx {
    /// Raw tx
    pub tx: Tx,
    pub actions: Vec<AnnotatedAction>,
}

#[derive(Clone, Serialize, Deserialize)]
pub enum BuildTxAction {
    IssueToAddress([u8; 32], u64, String),
    IssueToReceiver(Receiver),
    TransferToAddress([u8; 32], u64, String),
    TransferToReceiver(Receiver),
    Memo(Vec<u8>),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Cursor {
    pub cursor: String,
    pub count: Option<u32>,
}

impl Cursor {
    const DEFAULT_ELEMENTS_PER_PAGE: u32 = 20;
    pub fn count(&self) -> u32 {
        self.count.unwrap_or(Self::DEFAULT_ELEMENTS_PER_PAGE)
    }
}

#[derive(Deserialize)]
pub struct HexId([u8; 32]);

impl FromStr for HexId {
    type Err = serde_json::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let array = serde_json::from_str(s)?;
        Ok(Self(array))
    }
}

impl From<blockchain::BlockHeader> for BlockHeader {
    fn from(header: blockchain::BlockHeader) -> Self {
        let blockchain::BlockHeader {
            version,
            height,
            prev,
            timestamp_ms,
            txroot,
            utxoroot,
            ext,
        } = header;
        Self {
            version,
            height,
            prev: prev.0,
            timestamp_ms,
            txroot: txroot.0,
            utxoroot: utxoroot.0,
            ext,
        }
    }
}

impl TryFrom<BlockTx> for Tx {
    type Error = zkvm::VMError;

    fn try_from(tx: BlockTx) -> Result<Self, Self::Error> {
        let wid = tx.witness_hash().0;
        let precomputed = tx.tx.precompute()?;
        let id = (precomputed.id.0).0;
        let fee = precomputed.feerate.fee();
        let size = precomputed.feerate.size() as u64;
        Ok(Tx {
            id,
            wid,
            raw: hex::encode(tx.encode_to_vec()),
            fee,
            size,
        })
    }
}
