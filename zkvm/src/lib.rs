extern crate byteorder;
extern crate core;
extern crate rand;

extern crate bulletproofs;
extern crate curve25519_dalek;
extern crate merlin;
extern crate spacesuit;
extern crate subtle;

#[macro_use]
extern crate failure;

mod encoding;
mod errors;
mod ops;
mod point_ops;
mod predicate;
mod prover;
mod signature;
mod transcript;
mod txlog;
mod types;
mod verifier;
mod vm;

pub use self::errors::VMError;
pub use self::prover::Prover;
pub use self::txlog::{Entry, TxID, UTXO};
pub use self::verifier::Verifier;
pub use self::vm::{Tx, VerifiedTx};
