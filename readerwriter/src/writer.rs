
/// Interface for writing binary data.
pub trait Writer {
    /// An error returned when there is not enough space left.
    pub type Error: Display;
}