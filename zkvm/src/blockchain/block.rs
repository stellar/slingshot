use bulletproofs::BulletproofGens;
use merlin::Transcript;

use super::super::utreexo;
use super::errors::BlockchainError;
use super::state::BlockchainState;
use crate::{ContractID, MerkleTree, Tx, TxID, TxLog, Verifier};


#[derive(Clone, PartialEq)]
pub struct BlockID(pub [u8; 32]);

#[derive(Clone)]
pub struct BlockHeader {
    pub version: u64,
    pub height: u64,
    pub prev: BlockID,
    pub timestamp_ms: u64,
    pub txroot: [u8; 32],
    pub utxoroot: [u8; 32],
    pub ext: Vec<u8>,
}

#[derive(Clone)]
pub struct Block {
    pub header: BlockHeader,
    pub txs: Vec<Tx>,
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

    /// Returns an interator of all utxo proofs for all transactions in a block.
    /// This interface allows us to optimize the representation of utxo proofs,
    /// while not affecting the validation logic.
    pub fn utxo_proofs(&self) -> impl Iterator<Item=utreexo::Proof> {
        unimplemented!()
    }
}
