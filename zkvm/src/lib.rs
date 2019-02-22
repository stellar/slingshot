#[macro_use]
extern crate failure;

mod contract;
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

pub use self::contract::{Contract, FrozenContract, FrozenItem, FrozenValue, Input, PortableItem};
pub use self::errors::VMError;
pub use self::ops::{Instruction, Opcode};
pub use self::predicate::{Predicate, PredicateWitness};
pub use self::prover::Prover;
pub use self::signature::VerificationKey;
pub use self::transcript::TranscriptProtocol;
pub use self::txlog::{Entry, TxID, UTXO};
pub use self::types::{
    Commitment, CommitmentWitness, Data, DataWitness, Item, ScalarWitness, Value, WideValue,
};
pub use self::verifier::Verifier;
pub use self::vm::{Tx, VerifiedTx};
