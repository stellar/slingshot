use crate::utreexo::UtreexoError;
use crate::BlockID;
use thiserror::Error;
use zkvm::VMError;

/// Blockchain state machine error conditions.
#[derive(Debug, Error)]
pub enum BlockchainError {
    /// Occurs when the header contains inconsistent data.
    #[error("Inconsistent data in the block header.")]
    InconsistentHeader,

    /// Occurs when extension field is non-empty in v1 blocks.
    #[error("Extension field must be empty in v1 blocks.")]
    IllegalExtension,

    /// Occurs when block timestamp is outside the tx time bounds.
    #[error("Block timestamp is outside the transaction time bounds.")]
    BadTxTimestamp,

    /// Occurs when tx version is not consistent with the block version.
    #[error("Transaction version must be 1 for block version 1.")]
    BadTxVersion,

    /// Occurs when ZkVM failed executing the transaction.
    #[error("Transaction validation failed in ZkVM.")]
    VMError(VMError),

    /// Occurs when utreexo proof is missing.
    #[error("Utreexo proof is missing.")]
    UtreexoProofMissing,

    /// Occurs when utreexo operation failed.
    #[error("Utreexo operation failed.")]
    UtreexoError(UtreexoError),

    /// Block signature is invalid.
    #[error("Block signature is invalid.")]
    InvalidBlockSignature,

    /// Incompatible protocol version.
    #[error("Incompatible protocol version.")]
    IncompatibleVersion,

    /// Block not found.
    #[error("Block not found at a height {0}")]
    BlockNotFound(u64),

    /// Received block is either too old or an orphan.
    #[error("Block at height {0} is not relevant")]
    BlockNotRelevant(u64),

    /// Received block is either too old or an orphan.
    #[error("Received mempool txs at an irrelevant state")]
    StaleMempoolState(BlockID),
}

impl From<UtreexoError> for BlockchainError {
    fn from(e: UtreexoError) -> BlockchainError {
        BlockchainError::UtreexoError(e)
    }
}

impl From<VMError> for BlockchainError {
    fn from(e: VMError) -> BlockchainError {
        BlockchainError::VMError(e)
    }
}
