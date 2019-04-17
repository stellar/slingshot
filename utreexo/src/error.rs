#[derive(Fail, Clone, Debug, Eq, PartialEq)]
pub enum UError {
    /// This error indicates an invalid proof.
    #[fail(display = "Invalid proof.")]
    Invalid,
}
