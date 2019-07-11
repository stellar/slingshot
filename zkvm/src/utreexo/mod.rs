//! Implementation of a utxo accumulator inspired by Tadge Dryja's Utreexo design,
//! with small differences in normalization algorithm.
mod forest;
mod nodes;
mod path;

#[cfg(test)]
mod tests;

// Public API
pub use self::forest::{Catchup, Forest, UtreexoError, WorkForest};
pub use self::nodes::Hash;
pub use self::path::{Path, Position, Proof};
