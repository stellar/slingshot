#![deny(missing_docs)]
//! ZkVM (_zero-knowledge virtual machine_): a transaction format for a shared, multi-asset, cryptographic ledger.
//!
//! * [ZkVM whitepaper](https://github.com/stellar/slingshot/blob/main/zkvm/docs/zkvm-design.md) — technology overview.
//! * [ZkVM specification](https://github.com/stellar/slingshot/blob/main/zkvm/docs/zkvm-spec.md) — transaction validation rules.
//! * [Blockchain specification](https://github.com/stellar/slingshot/blob/main/zkvm/docs/zkvm-blockchain.md) — blockchain state machine specification.
//! * [ZkVM API](https://github.com/stellar/slingshot/blob/main/zkvm/docs/zkvm-api.md) — how to create transactions with ZkVM.

#[macro_use]
extern crate failure;
extern crate serde;

#[macro_use]
mod serialization;
pub mod blockchain;
mod constraints;
mod contract;
mod debug;
mod encoding;
mod errors;
mod fees;
mod merkle;
mod ops;
mod predicate;
mod program;
mod prover;
mod scalar_witness;
mod transcript;
mod tx;
mod types;
pub mod utreexo;
mod verifier;
mod vm;

pub use self::constraints::{Commitment, CommitmentWitness, Constraint, Expression, Variable};
pub use self::contract::{Anchor, Contract, ContractID, PortableItem};
pub use self::encoding::Encodable;
pub use self::errors::VMError;
pub use self::merkle::{Hash, MerkleItem, MerkleTree};
pub use self::ops::{Instruction, Opcode};
pub use self::predicate::{Predicate, PredicateTree};
pub use self::program::{Program, ProgramItem};
pub use self::prover::Prover;
pub use self::scalar_witness::ScalarWitness;
pub use self::transcript::TranscriptProtocol;
pub use self::tx::{Tx, TxEntry, TxHeader, TxID, TxLog, UnsignedTx, VerifiedTx};
pub use self::types::{ClearValue, Item, String, Value, WideValue};
pub use self::verifier::Verifier;

pub use self::blockchain::*;

pub use musig::{Multikey, Multisignature, Signature, VerificationKey};
