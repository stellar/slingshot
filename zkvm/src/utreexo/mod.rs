//! Implementation of a utxo accumulator inspired by Tadge Dryja's Utreexo design,
//! with small differences in normalization algorithm.
mod bitarray;
mod nodes;
mod path;
mod insertions;
mod forest;

#[cfg(test)]
mod tests;

// Public API
pub use self::nodes::{Hash};
pub use self::path::{Proof,Path,Position};
pub use self::forest::{Forest,Metrics,Catchup,UtreexoError};
