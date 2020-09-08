//! Errors related to proving and verifying proofs.
use bulletproofs::r1cs::R1CSError;

use thiserror::Error;

/// Represents an error in proof creation, verification, or parsing.
#[derive(Error, Clone, Debug, Eq, PartialEq)]
pub enum VMError {
    /// This error occurs when an individual point operation failed.
    #[error("Point operation failed.")]
    PointOperationFailed,

    /// This error occurs when a point is not a valid compressed Ristretto point
    #[error("Point decoding failed.")]
    InvalidPoint,

    /// This error occurs when data is malformed
    #[error("Format in invalid")]
    InvalidFormat,

    /// This error occurs when there are trailing bytes left unread by the parser.
    #[error("Invalid trailing bytes.")]
    TrailingBytes,

    /// This error occurs when data is malformed
    #[error("Transaction version does not permit extension instructions.")]
    ExtensionsNotAllowed,

    /// This error occurs when an instruction requires a copyable type, but a linear type is encountered.
    #[error("Item is not a copyable type.")]
    TypeNotCopyable,

    /// This error occurs when an instruction requires a droppable type, but a non-droppable type is encountered.
    #[error("Item is not a droppable type.")]
    TypeNotDroppable,

    /// This error occurs when an instruction requires a portable type, but a non-portable type is encountered.
    #[error("Item is not a portable type.")]
    TypeNotPortable,

    /// This error occurs when an instruction requires a string.
    #[error("Item is not a string.")]
    TypeNotString,

    /// This error occurs when an instruction requires a contract type.
    #[error("Item is not a contract.")]
    TypeNotContract,

    /// This error occurs when an instruction requires a variable type.
    #[error("Item is not a variable.")]
    TypeNotVariable,

    /// This error occurs when an instruction requires an expression type.
    #[error("Item is not an expression.")]
    TypeNotExpression,

    /// This error occurs when an instruction requires a predicate string.
    #[error("Item is not a predicate.")]
    TypeNotPredicate,

    /// This error occurs when an instruction requires a commitment string.
    #[error("Item is not a commitment.")]
    TypeNotCommitment,

    /// This error occurs when an instruction requires an output string.
    #[error("Item is not an output.")]
    TypeNotOutput,

    /// This error occurs whn an instruction requires a call proof string.
    #[error("Item is not a call proof.")]
    TypeNotCallProof,

    /// This error occurs when an instruction requires a constraint type.
    #[error("Item is not a constraint.")]
    TypeNotConstraint,

    /// This error occurs when an instruction requires a scalar string.
    #[error("Item is not a scalar.")]
    TypeNotScalar,

    /// This error occurs when an instruction requires a u64 integer.
    #[error("Item is not a LE64 integer.")]
    TypeNotU64,

    /// This error occurs when an instruction requires a u32 integer.
    #[error("Item is not a LE32 integer.")]
    TypeNotU32,

    /// This error occurs when an instruction expects a predicate tree type.
    #[error("Item is not a predicate tree.")]
    TypeNotPredicateTree,

    /// This error occurs when an instruction expects a key type.
    #[error("Item is not a key.")]
    TypeNotKey,

    /// This error occurs when a prover is supposed to provide signed integer.
    #[error("Item is not a signed integer.")]
    TypeNotSignedInteger,

    /// This error occurs when a prover is supposed to provide a program.
    #[error("Item is not a program")]
    TypeNotProgram,

    /// This error occurs when a prover has an inconsistent combination of witness data
    #[error("Witness data is inconsistent.")]
    InconsistentWitness,

    /// This error occurs when an instruction requires a value type.
    #[error("Item is not a value.")]
    TypeNotValue,

    /// This error occurs when an instruction requires a value or a wide value.
    #[error("Item is not a wide value.")]
    TypeNotWideValue,

    /// This error occurs when VM does not have enough items on the stack
    #[error("Stack does not have enough items")]
    StackUnderflow,

    /// This error occurs when VM is left with some items on the stack
    #[error("Stack is not cleared by the program")]
    StackNotClean,

    /// This error occurs when VM's anchor remains unset.
    #[error("VM anchor is not set via `input`")]
    AnchorMissing,

    /// This error occurs when VM's deferred schnorr checks fail
    #[error("Deferred batch signature verification failed")]
    BatchSignatureVerificationFailed,

    /// This error occurs when R1CS proof verification failed.
    #[error("R1CS proof is invalid")]
    InvalidR1CSProof,

    /// This error occurs when R1CS gadget reports and error due to inconsistent input
    #[error("R1CS detected inconsistent input")]
    R1CSInconsistency,

    /// This error occurs when an R1CSError is returned from the ConstraintSystem.
    #[error("R1CSError returned when trying to build R1CS instance")]
    R1CSError(R1CSError),

    /// This error occurs when a prover expects some witness data, but it is missing.
    #[error("Item misses witness data.")]
    WitnessMissing,

    /// This error occurs when we supply a number not in the range [1,64]
    #[error("Bitrange for rangeproof is not between 1 and 64")]
    InvalidBitrange,

    /// This error occurs when a Merkle proof of inclusion is invalid.
    #[error("Invalid Merkle proof.")]
    InvalidMerkleProof,

    /// This error occurs when the predicate tree cannot be constructed.
    #[error("Invalid predicate tree.")]
    InvalidPredicateTree,

    /// This error occurs when a function is called with bad arguments.
    #[error("Bad arguments")]
    BadArguments,

    /// This error occurs when an input is invalid.
    #[error("Input is invalid")]
    InvalidInput,

    /// This error occurs when a false cleartext constraint is verified.
    #[error("Cleartext constraint is false")]
    CleartextConstraintFalse,

    /// This error occurs when tx attempts to add a fee beyond the limit.
    #[error("Fee is too high")]
    FeeTooHigh,
}
