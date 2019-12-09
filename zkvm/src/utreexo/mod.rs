//! Implementation of a utxo accumulator inspired by Tadge Dryja's Utreexo design,
//! with small differences in normalization algorithm.
mod forest;
mod heap;
mod path;

#[cfg(test)]
mod tests;

// Public API
pub use self::forest::{Catchup, Forest, UtreexoError, WorkForest};
pub use self::path::Proof;
pub use super::merkle::Hasher;

/// Utreexo-labeled hasher for the merkle tree nodes.
pub fn utreexo_hasher<T: super::merkle::MerkleItem>() -> Hasher<T> {
    Hasher::new(b"ZkVM.utreexo")
}
