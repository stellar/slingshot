/// Represents an error in key aggregation, signing, or verification.
#[derive(Fail, Clone, Debug, Eq, PartialEq)]
pub enum StarsigError {
    /// This error occurs when a point is not a valid compressed Ristretto point
    #[fail(display = "Signature verification failed")]
    InvalidSignature,

    /// This error occurs when a set of signatures failed to verify as a batch
    #[fail(display = "Batch signature verification failed")]
    InvalidBatch,
}
