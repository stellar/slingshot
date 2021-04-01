#![deny(missing_docs)]
//! ZkVM (_zero-knowledge virtual machine_): a transaction format for a shared, multi-asset, cryptographic ledger.
//!
//! * [ZkVM whitepaper](https://github.com/stellar/slingshot/blob/main/zkvm/docs/zkvm-design.md) — technology overview.
//! * [ZkVM specification](https://github.com/stellar/slingshot/blob/main/zkvm/docs/zkvm-spec.md) — transaction validation rules.
//! * [Blockchain specification](https://github.com/stellar/slingshot/blob/main/zkvm/docs/zkvm-blockchain.md) — blockchain state machine specification.
//! * [ZkVM API](https://github.com/stellar/slingshot/blob/main/zkvm/docs/zkvm-api.md) — how to create transactions with ZkVM.

extern crate alloc;
pub extern crate bulletproofs;
pub extern crate curve25519_dalek;
pub extern crate merkle;
extern crate serde;

#[macro_use]
mod serialization;
mod constraints;
mod contract;
mod debug;
pub mod encoding;
mod errors;
mod fees;
mod ops;
mod predicate;
mod program;
mod prover;
mod scalar_witness;
mod transcript;
mod tx;
mod types;
mod verifier;
mod vm;

pub use self::constraints::{Commitment, CommitmentWitness, Constraint, Expression, Variable};
pub use self::contract::{Anchor, Contract, ContractID, PortableItem};
pub use self::errors::VMError;
pub use self::fees::{fee_flavor, CheckedFee, FeeRate, MAX_FEE};
pub use self::ops::{Instruction, Opcode};
pub use self::predicate::{Predicate, PredicateTree, PredicateWitness};
pub use self::program::{Program, ProgramItem};
pub use self::prover::Prover;
pub use self::scalar_witness::ScalarWitness;
pub use self::transcript::TranscriptProtocol;
pub use self::tx::{Tx, TxEntry, TxHeader, TxID, TxLog, UnsignedTx, VerifiedTx};
pub use self::types::{ClearValue, Item, String, Value, WideValue};
pub use self::verifier::Verifier;
pub use merkle::{Hash, Hasher, MerkleItem, MerkleTree};

pub use musig::{Multikey, Multisignature, Signature, VerificationKey};
