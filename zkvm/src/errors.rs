//! Errors related to proving and verifying proofs.
use bulletproofs::r1cs::R1CSError;

/// Represents an error in proof creation, verification, or parsing.
#[derive(Fail, Clone, Debug, Eq, PartialEq)]
pub enum VMError {
    /// This error occurs when an individual point operation failed.
    #[fail(display = "Point operation failed.")]
    PointOperationFailed,

    /// This error occurs when a point is not a valid compressed Ristretto point
    #[fail(display = "Point decoding failed.")]
    InvalidPoint,

    /// This error occurs when data is malformed
    #[fail(display = "Format in invalid")]
    FormatError,

    /// This error occurs when there are trailing bytes left unread by the parser.
    #[fail(display = "Invalid trailing bytes.")]
    TrailingBytes,

    /// This error occurs when data is malformed
    #[fail(display = "Transaction version does not permit extension instructions.")]
    ExtensionsNotAllowed,

    /// This error occurs when an instruction requires a copyable type, but a linear type is encountered.
    #[fail(display = "Item is not a copyable type.")]
    TypeNotCopyable,

    /// This error occurs when an instruction requires a portable type, but a non-portable type is encountered.
    #[fail(display = "Item is not a portable type.")]
    TypeNotPortable,

    /// This error occurs when an instruction requires a data type.
    #[fail(display = "Item is not a data string.")]
    TypeNotData,

    /// This error occurs when an instruction requires a contract type.
    #[fail(display = "Item is not a contract.")]
    TypeNotContract,

    /// This error occurs when an instruction requires a variable type.
    #[fail(display = "Item is not a variable.")]
    TypeNotVariable,

    /// This error occurs when an instruction requires an expression type.
    #[fail(display = "Item is not an expression.")]
    TypeNotExpression,

    /// This error occurs when an instruction requires a predicate data type.
    #[fail(display = "Item is not a predicate.")]
    TypeNotPredicate,

    /// This error occurs when an instruction requires a commitment data type.
    #[fail(display = "Item is not a commitment.")]
    TypeNotCommitment,

    /// This error occurs when an instruction requires an output data type.
    #[fail(display = "Item is not an output.")]
    TypeNotOutput,

    /// This error occurs when an instruction requires a constraint type.
    #[fail(display = "Item is not a constraint.")]
    TypeNotConstraint,

    /// This error occurs when an instruction requires a scalar data type.
    #[fail(display = "Item is not a scalar.")]
    TypeNotScalar,

    /// This errors occurs when an instruction expects a predicate disjunction type.
    #[fail(display = "Item is not a disjunction.")]
    TypeNotDisjunction,

    /// This error occurs when an instruction expects a key type.
    #[fail(display = "Item is not a key.")]
    TypeNotKey,

    /// This error occurs when a prover is supposed to provide signed integer.
    #[fail(display = "Item is not a signed integer.")]
    TypeNotSignedInteger,

    /// This error occurs when a prover is supposed to provide a program.
    #[fail(display = "Item is not a program")]
    TypeNotProgram,

    /// This error occurs when a prover has an inconsistent combination of witness data
    #[fail(display = "Witness data is inconsistent.")]
    InconsistentWitness,

    /// This error occurs when an instruction requires a value type.
    #[fail(display = "Item is not a value.")]
    TypeNotValue,

    /// This error occurs when an instruction requires a value or a wide value.
    #[fail(display = "Item is not a wide value.")]
    TypeNotWideValue,

    /// This error occurs when VM does not have enough items on the stack
    #[fail(display = "Stack does not have enough items")]
    StackUnderflow,

    /// This error occurs when VM is left with some items on the stack
    #[fail(display = "Stack is not cleared by the program")]
    StackNotClean,

    /// This error occurs when VM's anchor remains unset.
    #[fail(display = "VM anchor is not set via `input` or `nonce`")]
    AnchorMissing,

    /// This error occurs when VM's deferred schnorr checks fail
    #[fail(display = "Deferred point operations failed")]
    PointOperationsFailed,

    /// This error occurs when a MuSig signature share fails to verify
    #[fail(display = "Share #{:?} failed to verify correctly", pubkey)]
    MuSigShareError {
        /// The pubkey corresponding to the MuSig share that failed fo verify correctly
        pubkey: [u8; 32],
    },

    /// This error occurs when R1CS proof verification failed.
    #[fail(display = "R1CS proof is invalid")]
    InvalidR1CSProof,

    /// This error occurs when R1CS gadget reports and error due to inconsistent input
    #[fail(display = "R1CS detected inconsistent input")]
    R1CSInconsistency,

    /// This error occurs when an R1CSError is returned from the ConstraintSystem.
    #[fail(display = "R1CSError returned when trying to build R1CS instance")]
    R1CSError(R1CSError),

    /// This error occurs when a prover expects some witness data, but it is missing.
    #[fail(display = "Item misses witness data.")]
    WitnessMissing,

    /// This error occurs when we supply a number not in the range [1,64]
    #[fail(display = "Bitrange for rangeproof is not between 1 and 64")]
    InvalidBitrange,

    /// This error occurs when a Merkle proof of inclusion is invalid.
    #[fail(display = "Invalid Merkle proof.")]
    InvalidMerkleProof,

    /// This error occurs when the an index of a selected predicate is invalid.
    #[fail(display = "Predicate index out of bounds")]
    PredicateIndexInvalid,
}
