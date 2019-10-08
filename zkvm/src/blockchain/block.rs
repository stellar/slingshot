use merlin::Transcript;
use serde::{Deserialize, Serialize};

use crate::{Hash, MerkleTree, Tx};

/// Identifier of the block, computed as a hash of the `BlockHeader`.
#[derive(Clone, Copy, PartialEq, Default, Debug)]
pub struct BlockID(pub [u8; 32]);
serialize_bytes32!(BlockID);

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
    pub txroot: Hash,
    /// 32-byte Merkle root of the Utreexo state.
    pub utxoroot: Hash,
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
}

impl BlockHeader {
    /// Computes the ID of the block header.
    pub fn id(&self) -> BlockID {
        let mut t = Transcript::new(b"ZkVM.blockheader");
        t.append_u64(b"version", self.version);
        t.append_u64(b"height", self.height);
        t.append_message(b"previd", &self.prev.0);
        t.append_u64(b"timestamp_ms", self.timestamp_ms);
        t.append_message(b"txroot", &self.txroot.0);
        t.append_message(b"utxoroot", &self.utxoroot.0);
        t.append_message(b"ext", &self.ext);

        let mut result = [0u8; 32];
        t.challenge_bytes(b"id", &mut result);
        BlockID(result)
    }

    /// Creates an initial block header.
    pub fn make_initial(timestamp_ms: u64, utxoroot: Hash) -> BlockHeader {
        BlockHeader {
            version: 1,
            height: 1,
            prev: BlockID([0; 32]),
            timestamp_ms,
            txroot: MerkleTree::empty_root(b"ZkVM.txroot"),
            utxoroot,
            ext: Vec::new(),
        }
    }
}

impl AsRef<[u8]> for BlockID {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl core::ops::Deref for BlockID {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
