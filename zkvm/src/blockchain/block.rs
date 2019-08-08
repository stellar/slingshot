use merlin::Transcript;
use serde::{Deserialize, Serialize};

use super::super::utreexo;
use crate::{MerkleTree, Tx, TxEntry, TxID, VerifiedTx};

/// Identifier of the block, computed as a hash of the `BlockHeader`.
#[derive(Clone, Copy, PartialEq, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct BlockID(pub [u8; 32]);

/// BlockHeader contains the metadata for the block of transactions,
/// committing to them, but not containing the actual transactions.
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct BlockHeader {
    /// Network version.
    pub version: u64,
    /// Serial number of the block, starting with 1.
    pub height: u64,
    /// ID of the previous block. Initial block uses the all-zero string.
    pub prev: BlockID,
    /// Integer timestamp of the block in milliseconds since the Unix epoch:
    /// 00:00:00 UTC Jan 1, 1970.
    pub timestamp_ms: u64,
    /// 32-byte Merkle root of the transactions in the block.
    pub txroot: [u8; 32],
    /// 32-byte Merkle root of the Utreexo state.
    pub utxoroot: [u8; 32],
    /// Extra data for the future extensions.
    pub ext: Vec<u8>,
}

/// Block is a collection of transactions.
#[derive(Clone, Serialize, Deserialize)]
pub struct Block {
    /// Block header.
    pub header: BlockHeader,
    /// List of transactions.
    pub txs: Vec<Tx>, // no Debug impl for R1CSProof yet
    /// UTXO proofs
    pub all_utxo_proofs: Vec<utreexo::Proof>,
}

/// VerifiedBlock contains a list of VerifiedTx.
#[derive(Clone)]
pub struct VerifiedBlock {
    /// Block header.
    pub header: BlockHeader,
    /// List of transactions.
    pub txs: Vec<VerifiedTx>,
}

impl BlockHeader {
    /// Computes the ID of the block header.
    pub fn id(&self) -> BlockID {
        let mut t = Transcript::new(b"ZkVM.blockheader");
        t.append_u64(b"version", self.version);
        t.append_u64(b"height", self.height);
        t.append_message(b"previd", &self.prev.0);
        t.append_u64(b"timestamp_ms", self.timestamp_ms);
        t.append_message(b"txroot", &self.txroot);
        t.append_message(b"utxoroot", &self.utxoroot);
        t.append_message(b"ext", &self.ext);

        let mut result = [0u8; 32];
        t.challenge_bytes(b"id", &mut result);
        BlockID(result)
    }

    /// Creates an initial block header.
    pub fn make_initial(timestamp_ms: u64, utxoroot: [u8; 32]) -> BlockHeader {
        BlockHeader {
            version: 1,
            height: 1,
            prev: BlockID([0; 32]),
            timestamp_ms,
            txroot: MerkleTree::root::<TxID>(b"ZkVM.txroot", &[]),
            utxoroot,
            ext: Vec::new(),
        }
    }
}

impl Block {
    /// Returns an iterator of all utxo proofs for all transactions in a block.
    /// This interface allows us to optimize the representation of utxo proofs,
    /// while not affecting the validation logic.
    pub fn utxo_proofs(&self) -> impl IntoIterator<Item = &utreexo::Proof> {
        self.all_utxo_proofs.iter()
    }
}

impl VerifiedBlock {
    /// Returns an iterator over all transaction log entries for all transactions in the block.
    pub fn entries(&self) -> impl Iterator<Item = &TxEntry> {
        self.txs.iter().flat_map(|tx| tx.log.iter())
    }
}
