use super::{MerkleTree,TxLog,VMError};
use merlin::Transcript;

pub struct BlockID(pub [u8; 32]);

pub struct BlockHeader {
    pub version: u64,
    pub height: u64,
    pub prev: BlockID,
    pub timestamp_ms: u64,
    pub txroot: [u8; 32],
    pub utxoroot: [u8; 32],
    pub nonceroot: [u8; 32],
    pub refscount: u64,
    pub ext: [u8]
}

impl BlockHeader {
    pub fn id(&self) -> BlockID {
        let t = Transcript::new("ZkVM.blockheader");
        t.commit_u64(b"version", self.version);
        t.commit_u64(b"height", self.height);
        t.commit_bytes(b"previd", &self.prev);
        t.commit_u64(b"timestamp_ms", self.timestamp_ms);
        t.commit_bytes(b"txroot", &self.txroot);
        t.commit_bytes(b"utxoroot", &self.utxoroot);
        t.commit_bytes(b"nonceroot", &self.nonceroot);
        t.commit_u64(b"refscount", self.refscount);
        t.commit_bytes(b"ext", &self.ext);
        
        let result: [u8; 32];
        t.challenge_bytes(b"id", &mut result);
        BlockID(result)
    }
}

pub struct Block {
    pub header: BlockHeader,
    pub txs: Vec<Tx>
}

impl Block {
    pub fn make_initial(timestamp_ms: u64, refscount: u64) -> Block {
        Block {
            version: 1,
            height: 1,
            prev: BlockID([0; 32]),
            timestamp_ms: timestamp_ms,
            txroot: [0; 32],
            utxoroot: [0; 32],
            nonceroot: [0; 32],
            refscount: refscount,
            ext: []
        }
    }

    pub fn validate(&self, prev: &BlockHeader) -> Result<Vec<TxLog>, VMError> {
        if self.header.version < prev.version {
            return Err(xxx);
        }
        if self.header.version == 1 {
            // xxx check self.header.ext is empty
        }
        if self.header.height != prev.height+1 {
            return Err(xxx);
        }
        if self.header.prev != prev.id() {
            return Err(xxx);
        }
        if self.header.timestamp_ms <= prev.timestamp_ms {
            return Err(xxx);
        }
        if self.header.refscount > prev.refscount+1 {
            return Err(xxx);
        }

        let mut txlogs: Vec<TxLog> = Vec::new();
        let mut txids: Vec<TxID> = Vec::new();

        for tx in self.txs.iter() {
            if tx.mintime_ms > self.header.timestamp_ms || self.header.timestamp_ms > tx.maxtime_ms {
                return Err(xxx);
            }
            if self.header.version == 1 && tx.header.version != 1 {
                return Err(xxx);
            }
            let txlog = Verifier::verify_tx(tx, bp_gens)?;
            txlogs.push(txlog);
            let txid = tx.id(txlog);
            txids.push(txid);
        }

        let merkle_tree = MerkleTree::build(b"transaction_ids", &txids[..]);
        let txroot = merkle_tree.hash();
        if self.header.txroot != txroot {
            return Err(xxx);
        }

        Ok(txlogs)
    }
}
