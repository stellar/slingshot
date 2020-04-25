use byteorder::{ByteOrder, LittleEndian};
use core::mem;

pub enum WriteError {
    InsufficientCapacity,
}

/// Interface for writing binary data.
pub trait Writer {
    /// Writes bytes with the given label. If there is no sufficient capacity,
    /// performs no modifications and returns WriteError::InsufficientCapacity.
    fn write(&mut self, label: &'static [u8], src: &[u8]) -> Result<(), WriteError>;

    /// Remaining number of bytes that can be written.
    fn remaining_capacity(&self) -> usize;

    /// Writes a single byte.
    #[inline]
    fn write_u8(&mut self, label: &'static [u8], x: u8) -> Result<(), WriteError> {
        self.write(label, &[x])
    }

    /// Writes a LE32-encoded integer.
    #[inline]
    fn write_u32(&mut self, label: &'static [u8], x: u32) -> Result<(), WriteError> {
        let mut buf = [0u8; 4];
        LittleEndian::write_u32(&mut buf, x);
        self.write(label, &buf)
    }

    /// Writes a LE64-encoded integer.
    #[inline]
    fn write_u64(&mut self, label: &'static [u8], x: u64) -> Result<(), WriteError> {
        let mut buf = [0u8; 8];
        LittleEndian::write_u64(&mut buf, x);
        self.write(label, &buf)
    }
}

impl Writer for Vec<u8> {
    #[inline]
    fn write(&mut self, _label: &'static [u8], src: &[u8]) -> Result<(), WriteError> {
        self.extend_from_slice(src);
        Ok(())
    }

    #[inline]
    fn remaining_capacity(&self) -> usize {
        usize::max_value()
    }
}

impl Writer for &mut [u8] {
    #[inline]
    fn write(&mut self, _label: &'static [u8], src: &[u8]) -> Result<(), WriteError> {
        let n = src.len();
        if n <= self.remaining_capacity() {
            let (a, b) = mem::replace(self, &mut []).split_at_mut(n);
            a.copy_from_slice(&src[..n]);
            *self = b;
            Ok(())
        } else {
            Err(WriteError::InsufficientCapacity)
        }
    }

    #[inline]
    fn remaining_capacity(&self) -> usize {
        self.len()
    }
}
