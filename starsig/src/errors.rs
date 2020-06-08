use thiserror::Error;
/// Represents an error in key aggregation, signing, or verification.
#[derive(Error, Clone, Debug, Eq, PartialEq)]
pub enum StarsigError {
    /// This error occurs when a point is not a valid compressed Ristretto point
    #[error("Signature verification failed")]
    InvalidSignature,

    /// This error occurs when a set of signatures failed to verify as a batch
    #[error("Batch signature verification failed")]
    InvalidBatch,
}
