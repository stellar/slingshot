use zkvm::blockchain::MempoolItem;
use zkvm::utreexo;
use zkvm::{Encodable, Tx, VerifiedTx};

/// Mempool item
pub struct MempoolTx {
    pub tx: Tx,
    pub verified_tx: VerifiedTx,
    pub proofs: Vec<utreexo::Proof>,
}

impl MempoolItem for MempoolTx {
    fn verified_tx(&self) -> &VerifiedTx {
        &self.verified_tx
    }

    fn utreexo_proofs(&self) -> &[utreexo::Proof] {
        &self.proofs
    }
}

/// Our concrete instance of mempool
pub type Mempool = zkvm::blockchain::Mempool<MempoolTx>;

// Estimated cost of a memory occupied by transactions in the mempool.
pub fn estimated_memory_cost(mempool: &Mempool) -> usize {
    let txbytes: usize = mempool
        .items()
        .map(|item| item.tx.encoded_length())
        .sum();

    let utxoproofsbytes: usize = mempool
        .items()
        .flat_map(|i| i.proofs.iter().map(|p| utreexo_proof_memory_cost(p)))
        .sum();
    txbytes + utxoproofsbytes
}

fn utreexo_proof_memory_cost(proof: &utreexo::Proof) -> usize {
    match proof {
        utreexo::Proof::Transient => 1,
        utreexo::Proof::Committed(path) => 1 + path.encoded_length(),
    }
}
