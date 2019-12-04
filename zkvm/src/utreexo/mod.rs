//! Implementation of a utxo accumulator inspired by Tadge Dryja's Utreexo design,
//! with small differences in normalization algorithm.
mod forest;
mod path;
mod serialization;

#[cfg(test)]
mod tests;

// Public API
pub use self::forest::{Catchup, Forest, UtreexoError, WorkForest};
pub use self::path::{NodeHasher, Path, Position, Proof};
