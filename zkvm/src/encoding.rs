//! Encoding utils for ZkVM
//! All methods err using VMError::FormatError for convenience.

use byteorder::{ByteOrder, LittleEndian};
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
pub use readerwriter::{ReadError, Reader, WriteError, Writer};

use crate::errors::VMError;

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

impl From<ReadError> for VMError {
    fn from(_: ReadError) -> VMError {
        VMError::FormatError
    }
}

impl<T> ReaderExt for T where T: Reader {}

// Writing API
// This currently writes into the Vec, but later can be changed to support Arenas to minimize allocations

/// Writes a single byte.
pub fn write_u8<'a>(x: u8, target: &mut Vec<u8>) {
    target.push(x);
}

/// Writes a LE32-encoded integer.
pub fn write_u32<'a>(x: u32, target: &mut Vec<u8>) {
    let mut buf = [0u8; 4];
    LittleEndian::write_u32(&mut buf, x);
    target.extend_from_slice(&buf);
}

/// Writes a LE64-encoded integer.
pub fn write_u64<'a>(x: u64, target: &mut Vec<u8>) {
    let mut buf = [0u8; 8];
    LittleEndian::write_u64(&mut buf, x);
    target.extend_from_slice(&buf);
}

/// Writes a usize as a LE32-encoded integer.
pub fn write_size<'a>(x: usize, target: &mut Vec<u8>) {
    write_u32(x as u32, target);
}

/// Writes a 32-byte array and returns the subsequent slice.
pub fn write_bytes(x: &[u8], target: &mut Vec<u8>) {
    target.extend_from_slice(&x);
}

/// Writes a compressed point
pub fn write_point(x: &CompressedRistretto, target: &mut Vec<u8>) {
    write_bytes(x.as_bytes(), target);
}

/// A trait for consensus-critical encoding format for ZkVM data structures.
/// Note: serde is not used for consesus-critical operations.
pub trait Encodable {
    /// Encodes receiver into bytes appending them to a provided buffer.
    fn encode(&self, buf: &mut Vec<u8>);
    /// Returns precise length in bytes for the serialized representation of the receiver.
    fn encoded_length(&self) -> usize;
    /// Encodes the receiver into a newly allocated vector of bytes.
    fn encode_to_vec(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.encoded_length());
        self.encode(&mut buf);
        buf
    }
}
