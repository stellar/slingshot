//! Encoding utils for ZkVM
//! All methods err using VMError::FormatError for convenience.

use byteorder::{ByteOrder, LittleEndian};
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;

use crate::errors::VMError;

#[derive(Debug)]
pub struct SliceReader<'a> {
    whole: &'a [u8],
    start: usize,
    end: usize,
}

impl<'a> SliceReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        SliceReader {
            start: 0,
            end: data.len(),
            whole: data,
        }
    }

    pub fn len(&self) -> usize {
        self.end - self.start
    }

    pub fn slice<F, T>(&mut self, slice_fn: F) -> Result<(T, &[u8]), VMError>
    where
        F: FnOnce(&mut Self) -> Result<T, VMError>,
    {
        let start = self.start;
        let result = slice_fn(self)?;
        let end = self.start;
        Ok((result, &self.whole[start..end]))
    }

    pub fn parse<F, T>(data: &'a [u8], parse_fn: F) -> Result<T, VMError>
    where
        F: FnOnce(&mut Self) -> Result<T, VMError>,
    {
        let mut reader = Self::new(data);
        let result = parse_fn(&mut reader)?;
        if reader.len() != 0 {
            return Err(VMError::TrailingBytes);
        }
        Ok(result)
    }

    pub fn skip_trailing_bytes(&mut self) -> usize {
        let trailing = self.end - self.start;
        self.start = self.end;
        trailing
    }

    /// Returns a slice of the first `prefix_size` of bytes and advances
    /// the internal offset.
    pub fn read_bytes(&mut self, prefix_size: usize) -> Result<&[u8], VMError> {
        if prefix_size > self.len() {
            return Err(VMError::FormatError);
        }
        let prefix = &self.whole[self.start..(self.start + prefix_size)];
        self.start += prefix_size;
        Ok(prefix)
    }

    pub fn read_u8(&mut self) -> Result<u8, VMError> {
        let bytes = self.read_bytes(1)?;
        Ok(bytes[0])
    }

    pub fn read_u32(&mut self) -> Result<u32, VMError> {
        let bytes = self.read_bytes(4)?;
        let x = LittleEndian::read_u32(&bytes);
        Ok(x)
    }

    // returns a 32-byte "size" type used in ZkVM
    pub fn read_size(&mut self) -> Result<usize, VMError> {
        let n = self.read_u32()?;
        Ok(n as usize)
    }

    pub fn read_u8x32(&mut self) -> Result<[u8; 32], VMError> {
        let mut buf = [0u8; 32];
        let bytes = self.read_bytes(32)?;
        buf[..].copy_from_slice(&bytes);
        Ok(buf)
    }

    pub fn read_u8x64(&mut self) -> Result<[u8; 64], VMError> {
        let mut buf = [0u8; 64];
        let bytes = self.read_bytes(64)?;
        buf[..].copy_from_slice(&bytes);
        Ok(buf)
    }

    pub fn read_point(&mut self) -> Result<CompressedRistretto, VMError> {
        let buf = self.read_u8x32()?;
        Ok(CompressedRistretto(buf))
    }

    pub fn read_scalar(&mut self) -> Result<Scalar, VMError> {
        let buf = self.read_u8x32()?;
        Scalar::from_canonical_bytes(buf).ok_or(VMError::FormatError)
    }
}

// Writing API
// This currently writes into the Vec, but later can be changed to support Arenas to minimize allocations

// Writes a single byte
pub(crate) fn write_u8<'a>(x: u8, target: &mut Vec<u8>) {
    target.push(x);
}

// Writes a LE32-encoded integer
pub(crate) fn write_u32<'a>(x: u32, target: &mut Vec<u8>) {
    let mut buf = [0u8; 4];
    LittleEndian::write_u32(&mut buf, x);
    target.extend_from_slice(&buf);
}

/// Writes a 32-byte array and returns the subsequent slice
pub(crate) fn write_bytes(x: &[u8], target: &mut Vec<u8>) {
    target.extend_from_slice(&x);
}

/// Writes a compressed point
pub(crate) fn write_point(x: &CompressedRistretto, target: &mut Vec<u8>) {
    write_bytes(x.as_bytes(), target);
}
