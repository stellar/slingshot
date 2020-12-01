use serde::{Serialize, Deserialize};

use zkvm::Tx;
use blockchain::BlockHeader;
use accounts::Receiver;

use super::serde_utils::BigArray;
use std::str::FromStr;

/// Stats about unconfirmed transactions.
#[derive(Serialize)]
pub struct MempoolStatus {
    /// Total number of transactions
    count: u64,
    /// Total size of all transactions in the mempool
    size: u64,
    /// Lowest feerate for inclusing in the block
    feerate: u64,
}

/// Description of the current blockchain state.
#[derive(Serialize)]
pub struct State {
    // Block header
    tip: BlockHeader,
    // The utreexo state
    #[serde(with = "BigArray")]
    utreexo: [Option<[u8; 32]>; 64]
}

/// Description of a connected peer.
#[derive(Serialize)]
pub struct Peer {
    id: [u8; 32],
    since: u64,
    /// ipv6 address format
    addr: [u8; 16],
    priority: u64,
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
    entry: u32,
    qty: u64,
    flv: [u8; 32],
}

#[derive(Serialize)]
pub struct SpendAction {
    // Index of the txlog entry
    entry: u32,
    qty: u64,
    flv: [u8; 32],
    // Identifier of the account sending funds
    account: [u8; 32],
}

#[derive(Serialize)]
pub struct ReceiveAction {
    // Index of the txlog entry
    entry: u32,
    qty: u64,
    flv: [u8; 32],
    // Identifier of the account receiving funds (if known)
    account: Option<[u8; 32]>,
}

#[derive(Serialize)]
pub struct RetireAction {
    // Index of the txlog entry
    entry: u32,
    qty: u64,
    flv: [u8; 32],
}

#[derive(Serialize)]
pub struct MemoAction {
    entry: u32,
    data: Vec<u8>,
}

/// Description of the current blockchain state.
#[derive(Serialize)]
pub struct AnnotatedTx {
    /// Raw tx
    tx: Tx,
    actions: Vec<AnnotatedAction>
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
    cursor: u64,
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
