use thiserror::Error;

/// Represents an error in key aggregation, signing, or verification.
#[derive(Error, Clone, Debug, Eq, PartialEq)]
pub enum MusigError {
    /// This error occurs when a point is not a valid compressed Ristretto point
    #[error("Point decoding failed")]
    InvalidPoint,

    /// This error occurs when a signature share fails to verify
    #[error("Share #{pubkey:?} failed to verify correctly")]
    ShareError {
        /// The pubkey corresponding to the share that failed fo verify correctly
        pubkey: [u8; 32],
    },

    /// This error occurs when an individual point operation failed.
    #[error("Point operation failed")]
    PointOperationFailed,

    /// This error occurs when a function is called with bad arguments.
    #[error("Bad arguments")]
    BadArguments,
}
