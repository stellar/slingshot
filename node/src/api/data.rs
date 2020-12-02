use serde::{Serialize, Deserialize};

use accounts::Receiver;

use super::serde_utils::BigArray;
use std::str::FromStr;
use zkvm::TxHeader;
use blockchain::BlockTx;

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
    pub version: u64,      // Network version.
    pub height: u64,       // Serial number of the block, starting with 1.
    pub prev: [u8; 32], // ID of the previous block. Initial block uses the all-zero string.
    pub timestamp_ms: u64, // Integer timestamp of the block in milliseconds since the Unix epoch
    pub txroot: [u8; 32],   // 32-byte Merkle root of the transaction witness hashes (`BlockTx::witness_hash`) in the block.
    pub utxoroot: [u8; 32], // 32-byte Merkle root of the Utreexo state.
    pub ext: Vec<u8>,       // Extra data for the future extensions.
}

#[derive(Serialize)]
pub struct Block {
    pub header: BlockHeader,
    pub txs: Vec<BlockTx>
}

#[derive(Serialize)]
pub struct RawTx {
    pub header: TxHeader,
    pub program: Vec<u8>,
    pub signature: [u8; 64],
    pub r1cs_proof: Vec<u8>,
    pub utreexo_proofs: Vec<Vec<u8>>,
}

#[derive(Serialize)]
pub struct Tx {
    pub id: [u8; 32],     // canonical tx id
    pub wid: [u8; 32],    // witness hash of the tx (includes signatures and proofs)
    pub raw: RawTx,
    pub fee: u64,         // fee paid by the tx
    pub size: u64,        // size in bytes of the encoded tx
}

/// Description of the current blockchain state.
#[derive(Serialize)]
pub struct State {
    // Block header
    pub tip: BlockHeader,
    // The utreexo state
    #[serde(with = "BigArray")]
    pub utreexo: [Option<[u8; 32]>; 64]
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
    pub actions: Vec<AnnotatedAction>
}

#[derive(Serialize, Deserialize)]
pub enum BuildTxAction {
    IssueToAddress([u8; 32], u64, String),
    IssueToReceiver(Receiver),
    TransferToAddress([u8; 32], u64, String),
    TransferToReceiver(Receiver),
    Memo(Vec<u8>),
}

#[derive(Debug, Deserialize)]
pub struct Cursor {
    pub cursor: String,
}

impl Cursor {
    pub const DEFAULT_ELEMENTS_PER_PAGE: u32 = 20;
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
