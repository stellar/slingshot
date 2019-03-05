//! Spacesuit is a pure-Rust implementation of Cloak protocol by Interstellar.
//! Cloak is a protocol for confidential assets based on the
//! [Bulletproofs](https://crypto.stanford.edu/bulletproofs/) zero-knowledge proof system.
//! _Cloaked transactions_ exchange values of different “asset types” (which we call flavors).
//! See the [Cloak specification](https://github.com/interstellar/slingshot/blob/main/spacesuit/spec.md) for details.
#![deny(missing_docs)]

extern crate bulletproofs;
extern crate core;
extern crate curve25519_dalek;
extern crate merlin;
extern crate rand;
extern crate subtle;

mod bit_range;
mod cloak;
mod mix;
mod range_proof;
mod shuffle;
mod signed_integer;
mod value;

pub use bit_range::BitRange;
pub use cloak::cloak;
pub use range_proof::range_proof;
pub use signed_integer::SignedInteger;
pub use value::{AllocatedValue, CommittedValue, Value};

// TBD: figure out if we need to export these at all
pub use value::{ProverCommittable, VerifierCommittable};
