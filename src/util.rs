use bulletproofs::r1cs::{Assignment, Variable, R1CSError};

#[derive(Clone, Debug)]
pub struct Value {
    pub q: (Variable, Assignment), // quantity
    pub a: (Variable, Assignment), // issuer
    pub t: (Variable, Assignment), // tag
}

/// Represents an error during the proof creation of verification for a KShuffle or KValueShuffle gadget.
#[derive(Fail, Copy, Clone, Debug, Eq, PartialEq)]
pub enum SpacesuitError {
    /// Error in the constraint system creation process
    #[fail(display = "Invalid KShuffle constraint system construction")]
    InvalidR1CSConstruction,
    /// Occurs when there are insufficient generators for the proof.
    #[fail(display = "Invalid generators size, too few generators for proof")]
    InvalidGeneratorsLength,
    /// Occurs when verification of an [`R1CSProof`](::r1cs::R1CSProof) fails.
    #[fail(display = "R1CSProof did not verify correctly.")]
    VerificationError,
}

impl From<R1CSError> for SpacesuitError {
    fn from(e: R1CSError) -> SpacesuitError {
        match e {
            R1CSError::InvalidGeneratorsLength => SpacesuitError::InvalidGeneratorsLength,
            R1CSError::MissingAssignment => SpacesuitError::InvalidR1CSConstruction,
            R1CSError::VerificationError => SpacesuitError::VerificationError,
        }
    }
}
