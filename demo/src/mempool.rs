use blockchain::{self};
use zkvm::Encodable;

/// Our concrete instance of mempool
pub type Mempool = blockchain::Mempool;

// Estimated cost of a memory occupied by transactions in the mempool.
pub fn estimated_memory_cost(mempool: &Mempool) -> usize {
    mempool
        .entries()
        .map(|entry| entry.block_tx().encoded_length())
        .sum()
}
