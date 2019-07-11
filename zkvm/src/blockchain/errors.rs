use crate::errors::VMError;
use crate::utreexo::UtreexoError;

/// Blockchain state machine error conditions.
#[derive(Debug, Fail)]
pub enum BlockchainError {
    /// Occurs when the header contains inconsistent data.
    #[fail(display = "Inconsistent data in the block header.")]
    InconsistentHeader,

    /// Occurs when extension field is non-empty in v1 blocks.
    #[fail(display = "Extension field must be empty in v1 blocks.")]
    IllegalExtension,

    /// Occurs when block timestamp is outside the tx time bounds.
    #[fail(display = "Block timestamp is outside the transaction time bounds.")]
    BadTxTimestamp,

    /// Occurs when tx version is not consistent with the block version.
    #[fail(display = "Transaction version must be 1 for block version 1.")]
    BadTxVersion,

    /// Occurs when ZkVM failed executing the transaction.
    #[fail(display = "Transaction validation failed in ZkVM.")]
    TxValidation(VMError),

    /// Occurs when utreexo proof is missing.
    #[fail(display = "Utreexo proof is missing.")]
    UtreexoProofMissing,

    /// Occurs when utreexo operation failed.
    #[fail(display = "Utreexo operation failed.")]
    UtreexoError(UtreexoError),
}
