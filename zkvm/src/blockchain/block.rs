use core::borrow::Borrow;
use merlin::Transcript;

use super::super::utreexo;
use crate::{MerkleTree, Tx, TxID};

/// Identifier of the block, computed as a hash of the `BlockHeader`.
#[derive(Clone, Copy, PartialEq)]
pub struct BlockID(pub [u8; 32]);

/// BlockHeader contains the metadata for the block of transactions,
/// committing to them, but not containing the actual transactions.
#[derive(Clone, PartialEq)]
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
#[derive(Clone)]
pub struct Block {
    /// Block header.
    pub header: BlockHeader,
    /// List of transactions.
    pub txs: Vec<Tx>,
    /// UTXO proofs
    pub all_utxo_proofs: Vec<utreexo::Proof>,
}

impl BlockHeader {
    /// Computes the ID of the block header.
    pub fn id(&self) -> BlockID {
        let mut t = Transcript::new(b"ZkVM.blockheader");
        t.commit_u64(b"version", self.version);
        t.commit_u64(b"height", self.height);
        t.commit_bytes(b"previd", &self.prev.0);
        t.commit_u64(b"timestamp_ms", self.timestamp_ms);
        t.commit_bytes(b"txroot", &self.txroot);
        t.commit_bytes(b"utxoroot", &self.utxoroot);
        t.commit_bytes(b"ext", &self.ext);

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
