/// Represents an error in key aggregation, signing, or verification.
#[derive(Fail, Clone, Debug, Eq, PartialEq)]
pub enum SchnorrError {
    /// This error occurs when a point is not a valid compressed Ristretto point
    #[fail(display = "Signature verification failed")]
    InvalidSignature,
}
