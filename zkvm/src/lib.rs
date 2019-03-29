#![deny(missing_docs)]
//! ZkVM implementation.

#[macro_use]
extern crate failure;
extern crate serde;

mod constraints;
mod contract;
mod encoding;
mod errors;
mod merkle;
mod ops;
mod point_ops;
mod predicate;
mod program;
mod prover;
mod scalar_witness;
mod transcript;
mod txlog;
mod types;
mod verifier;
mod vm;

pub use self::constraints::{Commitment, Constraint, Expression, Variable};
pub use self::contract::{Anchor, Contract, ContractID, Output, PortableItem};
pub use self::errors::VMError;
pub use self::merkle::{MerkleItem, MerkleNeighbor, MerkleTree};
pub use self::ops::{Instruction, Opcode};
pub use self::predicate::Predicate;
pub use self::program::Program;
pub use self::prover::Prover;
pub use self::scalar_witness::ScalarWitness;
pub use self::transcript::TranscriptProtocol;
pub use self::txlog::{Entry, TxID, TxLog, UTXO};
pub use self::types::{Data, Item, Value, WideValue};
pub use self::verifier::Verifier;
pub use self::vm::{Tx, TxHeader, VerifiedTx};
pub use musig::{Signature, VerificationKey};
