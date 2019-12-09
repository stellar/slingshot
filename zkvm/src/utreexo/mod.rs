//! Implementation of a utxo accumulator inspired by Tadge Dryja's Utreexo design,
//! with small differences in normalization algorithm.
mod forest;
mod heap;

#[cfg(test)]
mod tests;

// Public API
pub use self::forest::{Catchup, Forest, Proof, UtreexoError, WorkForest};
pub use super::merkle::Hasher;

/// Utreexo-labeled hasher for the merkle tree nodes.
pub fn utreexo_hasher<T: super::merkle::MerkleItem>() -> Hasher<T> {
    Hasher::new(b"ZkVM.utreexo")
}
