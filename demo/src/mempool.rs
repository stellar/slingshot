use zkvm::{Encodable, Tx, VerifiedTx};

/// Mempool item
pub struct MempoolItem {
    pub tx: Tx,
    pub verified_tx: VerifiedTx,
}

/// Our concrete instance of mempool
pub type Mempool = zkvm::blockchain::Mempool<MempoolItem>;

impl AsRef<VerifiedTx> for MempoolItem {
    fn as_ref(&self) -> &VerifiedTx {
        &self.verified_tx
    }
}

// Estimated cost of a memory occupied by transactions in the mempool.
pub fn estimated_memory_cost(mempool: &Mempool) -> usize {
    let txbytes: usize = mempool
        .items()
        .map(|item| item.tx.serialized_length())
        .sum();
    let utxoproofsbytes: usize = mempool.utxo_proofs().map(|p| p.serialized_length()).sum();
    txbytes + utxoproofsbytes
}
