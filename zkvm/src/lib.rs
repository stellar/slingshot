#![deny(missing_docs)]
//! ZkVM implementation.

#[macro_use]
extern crate failure;

mod constraints;
mod contract;
mod encoding;
mod errors;
mod ops;
mod point_ops;
mod predicate;
mod prover;
mod scalar_witness;
mod signature;
mod transcript;
mod txlog;
mod types;
mod verifier;
mod vm;

pub use self::constraints::{Commitment, Constraint, Expression, Variable};
pub use self::contract::Input;
pub use self::errors::VMError;
pub use self::ops::{Instruction, Opcode, Program};
pub use self::predicate::Predicate;
pub use self::prover::Prover;
pub use self::signature::{Signature, VerificationKey};
pub use self::transcript::TranscriptProtocol;
pub use self::txlog::{Entry, TxID, UTXO};
pub use self::types::{Data, Item, Value, WideValue};
pub use self::verifier::Verifier;
pub use self::vm::{Tx, TxHeader, VerifiedTx};
