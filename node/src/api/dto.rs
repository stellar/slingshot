use serde::{Deserialize, Serialize};

use accounts::Receiver;

use super::serde_utils::BigArray;
use blockchain::BlockTx;
use std::str::FromStr;
use zkvm::TxHeader;

/// Stats about unconfirmed transactions.
#[derive(Serialize)]
pub struct MempoolStatusDTO {
    /// Total number of transactions
    pub count: u64,
    /// Total size of all transactions in the mempool
    pub size: u64,
    /// Lowest feerate for inclusing in the block
    pub feerate: u64,
}

#[derive(Serialize)]
pub struct BlockHeaderDTO {
    pub version: u64,       // Network version.
    pub height: u64,        // Serial number of the block, starting with 1.
    pub prev: [u8; 32],     // ID of the previous block. Initial block uses the all-zero string.
    pub timestamp_ms: u64,  // Integer timestamp of the block in milliseconds since the Unix epoch
    pub txroot: [u8; 32], // 32-byte Merkle root of the transaction witness hashes (`BlockTx::witness_hash`) in the block.
    pub utxoroot: [u8; 32], // 32-byte Merkle root of the Utreexo state.
    pub ext: Vec<u8>,     // Extra data for the future extensions.
}

#[derive(Deserialize)]
pub struct TxHeaderDTO {
    pub version: u64,
    pub mintime_ms: u64,
    pub maxtime_ms: u64,
}

#[derive(Serialize)]
pub struct BlockDTO {
    pub header: BlockHeaderDTO,
    pub txs: Vec<BlockTx>,
}

#[derive(Serialize)]
pub struct TxDTO {
    pub id: [u8; 32],  // canonical tx id
    pub wid: [u8; 32], // witness hash of the tx (includes signatures and proofs)
    pub raw: String,
    pub fee: u64,  // fee paid by the tx
    pub size: u64, // size in bytes of the encoded tx
}

/// Description of the current blockchain state.
#[derive(Serialize)]
pub struct StateDTO {
    // Block header
    pub tip: BlockHeaderDTO,
    // The utreexo state
    #[serde(with = "BigArray")]
    pub utreexo: [Option<[u8; 32]>; 64],
}

/// Description of a connected peer.
#[derive(Serialize)]
pub struct PeerDTO {
    pub id: [u8; 32],
    pub since: u64,
    /// ipv6 address format
    pub addr: [u8; 16],
    pub priority: u64,
}

#[derive(Serialize)]
pub enum AnnotatedActionDTO {
    Issue(IssueActionDTO),
    Spend(SpendActionDTO),
    Receive(ReceiveActionDTO),
    Retire(RetireActionDTO),
    Memo(MemoActionDTO),
}

#[derive(Serialize)]
pub struct IssueActionDTO {
    // Index of the txlog entry
    pub entry: u32,
    pub qty: u64,
    pub flv: [u8; 32],
}

#[derive(Serialize)]
pub struct SpendActionDTO {
    // Index of the txlog entry
    pub entry: u32,
    pub qty: u64,
    pub flv: [u8; 32],
    // Identifier of the account sending funds
    pub account: [u8; 32],
}

#[derive(Serialize)]
pub struct ReceiveActionDTO {
    // Index of the txlog entry
    pub entry: u32,
    pub qty: u64,
    pub flv: [u8; 32],
    // Identifier of the account receiving funds (if known)
    pub account: Option<[u8; 32]>,
}

#[derive(Serialize)]
pub struct RetireActionDTO {
    // Index of the txlog entry
    pub entry: u32,
    pub qty: u64,
    pub flv: [u8; 32],
}

#[derive(Serialize)]
pub struct MemoActionDTO {
    pub entry: u32,
    pub data: Vec<u8>,
}

/// Description of the current blockchain state.
#[derive(Serialize)]
pub struct AnnotatedTxDTO {
    /// Raw tx
    pub tx: TxDTO,
    pub actions: Vec<AnnotatedActionDTO>,
}

#[derive(Clone, Serialize, Deserialize)]
pub enum BuildTxActionDTO {
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

impl From<blockchain::BlockHeader> for BlockHeaderDTO {
    fn from(header: blockchain::BlockHeader) -> Self {
        let blockchain::BlockHeader { version, height, prev, timestamp_ms, txroot, utxoroot, ext } = header;
        Self {
            version,
            height,
            prev: prev.0,
            timestamp_ms,
            txroot: txroot.0,
            utxoroot: utxoroot.0,
            ext
        }
    }
}

impl From<BlockTx> for TxDTO {
    fn from(tx: BlockTx) -> Self {
        unimplemented!()
    }
}
