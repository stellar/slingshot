//! Implementation of a utxo accumulator inspired by Tadge Dryja's Utreexo design,
//! with small differences in normalization algorithm.
mod nodes;
mod path;
mod forest;

#[cfg(test)]
mod tests;

// Public API
pub use self::nodes::{Hash};
pub use self::path::{Proof,Path,Position};
pub use self::forest::{Utreexo,WorkForest,Catchup,UtreexoError};
