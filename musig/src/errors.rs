/// Represents an error in key aggregation, signing, or verification.
#[derive(Fail, Clone, Debug, Eq, PartialEq)]
pub enum MuSigError {
    /// This error occurs when a point is not a valid compressed Ristretto point
    #[fail(display = "Point decoding failed.")]
    InvalidPoint,

    /// This error occurs when a signature share fails to verify
    #[fail(display = "Share #{:?} failed to verify correctly", pubkey)]
    ShareError {
        /// The pubkey corresponding to the share that failed fo verify correctly
        pubkey: [u8; 32],
    },

    /// This error occurs when an individual point operation failed.
    #[fail(display = "Point operation failed.")]
    PointOperationFailed,

    /// This error occurs when a function is called with bad arguments.
    #[fail(display = "Bad arguments")]
    BadArguments,
}
