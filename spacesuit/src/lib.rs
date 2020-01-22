//! Spacesuit is a pure-Rust implementation of Cloak protocol by Interstellar.
//! Cloak is a protocol for confidential assets based on the
//! [Bulletproofs](https://crypto.stanford.edu/bulletproofs/) zero-knowledge proof system.
//! _Cloaked transactions_ exchange values of different “asset types” (which we call flavors).
//! See the [Cloak specification](https://github.com/interstellar/slingshot/blob/main/spacesuit/spec.md) for details.
#![deny(missing_docs)]

mod bit_range;
mod cloak;
mod mix;
mod range_proof;
mod shuffle;
mod signed_integer;
mod value;

pub use crate::bit_range::BitRange;
pub use crate::cloak::cloak;
pub use crate::range_proof::range_proof;
pub use crate::signed_integer::SignedInteger;
pub use crate::value::{AllocatedValue, CommittedValue, Value};

// TBD: figure out if we need to export these at all
pub use crate::value::{ProverCommittable, VerifierCommittable};
