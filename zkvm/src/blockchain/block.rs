use bulletproofs::BulletproofGens;
use merlin::Transcript;

use super::errors::BCError;
use crate::{MerkleTree, Tx, TxID, TxLog, Verifier};

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
    pub nonceroot: [u8; 32],
    pub refscount: u64,
    pub ext: Box<[u8]>,
}

impl BlockHeader {
    pub fn id(&self) -> BlockID {
        let mut t = Transcript::new(b"ZkVM.blockheader");
        t.commit_u64(b"version", self.version);
        t.commit_u64(b"height", self.height);
        t.commit_bytes(b"previd", &self.prev.0);
        t.commit_u64(b"timestamp_ms", self.timestamp_ms);
        t.commit_bytes(b"txroot", &self.txroot);
        t.commit_bytes(b"utxoroot", &self.utxoroot);
        t.commit_bytes(b"nonceroot", &self.nonceroot);
        t.commit_u64(b"refscount", self.refscount);
        t.commit_bytes(b"ext", &self.ext);

        let mut result = [0u8; 32];
        t.challenge_bytes(b"id", &mut result);
        BlockID(result)
    }

    pub fn make_initial(timestamp_ms: u64, refscount: u64) -> BlockHeader {
        BlockHeader {
            version: 1,
            height: 1,
            prev: BlockID([0; 32]),
            timestamp_ms: timestamp_ms,
            txroot: [0; 32],
            utxoroot: [0; 32],
            nonceroot: [0; 32],
            refscount: refscount,
            ext: Box::new([]),
        }
    }
}

pub struct Block {
    pub header: BlockHeader,
    pub txs: Vec<Tx>,
}

impl Block {
    pub fn validate(&self, prev: &BlockHeader) -> Result<Vec<TxLog>, BCError> {
        if self.header.version < prev.version {
            return Err(BCError::VersionReversion);
        }
        if self.header.version == 1 && self.header.ext.len() != 0 {
            return Err(BCError::IllegalExtension);
        }
        if self.header.height != prev.height + 1 {
            return Err(BCError::BadHeight);
        }
        if self.header.prev != prev.id() {
            return Err(BCError::MismatchedPrev);
        }
        if self.header.timestamp_ms <= prev.timestamp_ms {
            return Err(BCError::BadBlockTimestamp);
        }
        if self.header.refscount > prev.refscount + 1 {
            return Err(BCError::BadRefscount);
        }

        let mut txlogs: Vec<TxLog> = Vec::new();
        let mut txids: Vec<TxID> = Vec::new();

        for tx in self.txs.iter() {
            if tx.header.mintime_ms > self.header.timestamp_ms
                || self.header.timestamp_ms > tx.header.maxtime_ms
            {
                return Err(BCError::BadTxTimestamp);
            }
            if self.header.version == 1 && tx.header.version != 1 {
                return Err(BCError::BadTxVersion);
            }

            // TODO(bobg): The API currently requires anticipating how many multipliers (generators) are needed,
            // _before_ knowing what's in the transaction.
            // The value is 64 for each range proof,
            // and there are at least as many range proofs as outputs in the tx.
            // Guessing a value should _not_ be part of the tx-verifying API.
            // Related: https://github.com/dalek-cryptography/bulletproofs/pull/263
            let bp_gens = BulletproofGens::new(64 * 64, 1);

            match Verifier::verify_tx(tx, &bp_gens) {
                Ok(verified) => {
                    let txid = TxID::from_log(&verified.log);
                    txids.push(txid);
                    txlogs.push(verified.log);
                }
                Err(err) => return Err(BCError::TxValidation(err)),
            }
        }

        let merkle_tree = MerkleTree::build(b"transaction_ids", &txids[..]);
        let txroot = merkle_tree.hash();
        if &self.header.txroot != txroot {
            return Err(BCError::TxrootMismatch);
        }

        Ok(txlogs)
    }
}
