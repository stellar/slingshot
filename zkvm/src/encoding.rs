//! Encoding utils for ZkVM
//! All methods err using VMError::FormatError for convenience.

use byteorder::{ByteOrder, LittleEndian};
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
pub use readerwriter::{ReadError, Reader, WriteError, Writer};

use crate::errors::VMError;

/// A trait for consensus-sensitive encoding format for ZkVM data structures.
/// Note: serde is not used for consesus-sensitive operations.
pub trait Encodable {
    /// Encodes receiver into bytes appending them to a provided buffer.
    fn encode(&self, w: &mut impl Writer) -> Result<(), WriteError>;
    /// Returns precise length in bytes for the serialized representation of the receiver.
    fn encoded_length(&self) -> usize;
    /// Encodes the receiver into a newly allocated vector of bytes.
    fn encode_to_vec(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.encoded_length());
        self.encode(&mut buf).expect("Writing to a Vec never fails.");
        buf
    }
}

/// Extension to the Reader interface for Ristretto points and scalars.
pub trait ReaderExt: Reader {
    /// Reads a u32-LE number used for encoding length prefixes in ZkVM.
    fn read_size(&mut self) -> Result<usize, ReadError> {
        Ok(self.read_u32()? as usize)
    }

    /// Reads a compressed Ristretto255 point (32 bytes).
    fn read_point(&mut self) -> Result<CompressedRistretto, ReadError> {
        let buf = self.read_u8x32()?;
        Ok(CompressedRistretto(buf))
    }

    /// Reads a Ristretto255 scalar (32 bytes).
    fn read_scalar(&mut self) -> Result<Scalar, ReadError> {
        let buf = self.read_u8x32()?;
        Scalar::from_canonical_bytes(buf).ok_or(ReadError::InvalidFormat)
    }
}

/// Extension to the Writer interface for Ristretto points and scalars.
pub trait WriterExt: Writer {
    /// Writes a u32-LE number used for encoding length prefixes in ZkVM.
    fn write_size(&mut self, label: &'static [u8], x: usize) -> Result<(), WriteError> {
        self.write_u32(label, x as u32)
    }

    /// Writes a compressed Ristretto255 point.
    fn write_point(&mut self, label: &'static [u8], x: &CompressedRistretto) -> Result<(), WriteError> {
        self.write(label, &x.as_bytes())
    }

    /// Writes a Ristretto255 scalar.
    fn write_scalar(&mut self, label: &'static [u8], x: &Scalar) -> Result<(), WriteError> {
        self.write(label, &x.as_bytes())
    }
}

impl<T> ReaderExt for T where T: Reader {}
impl<T> WriterExt for T where T: Writer {}

impl From<ReadError> for VMError {
    fn from(_: ReadError) -> VMError {
        VMError::FormatError
    }
}

impl From<WriteError> for VMError {
    fn from(_: WriteError) -> VMError {
        VMError::FormatError
    }
}
