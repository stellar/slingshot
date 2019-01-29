//! Encoding utils for ZkVM
//! All methods err using VMError::FormatError for convenience.

use byteorder::{ByteOrder, LittleEndian};
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;

use crate::errors::VMError;

/// Reads a byte and returns the subsequent slice
pub fn read_u8<'a>(slice: &'a [u8]) -> Result<(u8, &'a [u8]), VMError> {
    if slice.len() < 1 {
        return Err(VMError::FormatError);
    }
    Ok((slice[0], &slice[1..]))
}

/// Reads the LE32-encoded integer and returns the subsequent slice
pub fn read_u32<'a>(slice: &'a [u8]) -> Result<(u32, &'a [u8]), VMError> {
    if slice.len() < 4 {
        return Err(VMError::FormatError);
    }
    let x = LittleEndian::read_u32(slice);
    Ok((x, &slice[4..]))
}

/// Reads the LE32-encoded integer as `usize` and returns the subsequent slice
pub fn read_usize<'a>(slice: &'a [u8]) -> Result<(usize, &'a [u8]), VMError> {
    let (n, rest) = read_u32(slice)?;
    Ok((n as usize, rest))
}

/// Reads a 32-byte array and returns the subsequent slice
pub fn read_u8x32<'a>(slice: &'a [u8]) -> Result<([u8; 32], &'a [u8]), VMError> {
    if slice.len() < 32 {
        return Err(VMError::FormatError);
    }
    let mut buf = [0u8; 32];
    let (a, rest) = slice.split_at(32);
    buf[..].copy_from_slice(a);
    Ok((buf, rest))
}

/// Reads a N-byte slice and returns the subsequent slice
pub fn read_bytes<'a>(n: usize, slice: &'a [u8]) -> Result<(&'a [u8], &'a [u8]), VMError> {
    if slice.len() < n {
        return Err(VMError::FormatError);
    }
    Ok(slice.split_at(n))
}

/// Reads the Compressed Ristretto point (32-byte string) w/o attempting to decode it.
pub fn read_point<'a>(slice: &'a [u8]) -> Result<(CompressedRistretto, &'a [u8]), VMError> {
    let (buf, rest) = read_u8x32(slice)?;
    Ok((CompressedRistretto(buf), rest))
}

/// Reads the Scalar (encoded as 32-byte little-endian integer)
/// and checks if it is canonically encoded (`x == x mod |G|`).
pub fn read_scalar<'a>(slice: &'a [u8]) -> Result<(Scalar, &'a [u8]), VMError> {
    let (buf, rest) = read_u8x32(slice)?;
    Ok((
        Scalar::from_canonical_bytes(buf).ok_or(VMError::FormatError)?,
        rest,
    ))
}

// Writing API
// This currently writes into the Vec, but later can be changed to support Arenas to minimize allocations

// Writes a single byte
pub fn write_u8<'a>(x: u8, target: &mut Vec<u8>) {
    target.push(x);
}

// Writes a LE32-encoded integer
pub fn write_u32<'a>(x: u32, target: &mut Vec<u8>) {
    let mut buf = [0u8; 4];
    LittleEndian::write_u32(&mut buf, x);
    target.extend_from_slice(&buf);
}

/// Reads a 32-byte array and returns the subsequent slice
pub fn write_bytes(x: &[u8], target: &mut Vec<u8>) {
    target.extend_from_slice(&x);
}

/// Reads a compressed point
pub fn write_point(x: &CompressedRistretto, target: &mut Vec<u8>) {
    write_bytes(x.as_bytes(), target);
}

/// Reads a scalar
pub fn write_scalar(x: &Scalar, target: &mut Vec<u8>) {
    write_bytes(x.as_bytes(), target);
}
