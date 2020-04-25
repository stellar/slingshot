//! Reader implementation for Bytes and Buf.
//! Writer implementation for BytesMut and BufMut.

use crate::{ReadError, Reader, WriteError, Writer};
use bytes::{Buf, BufMut, Bytes, BytesMut};

impl Reader for Bytes {
    #[inline]
    fn read(&mut self, dst: &mut [u8]) -> Result<(), ReadError> {
        let n = dst.len();
        if n <= self.remaining_bytes() {
            self.copy_to_slice(dst);
            Ok(())
        } else {
            Err(ReadError::InsufficientBytes)
        }
    }

    #[inline]
    fn read_u8(&mut self) -> Result<u8, ReadError> {
        if self.remaining_bytes() > 0 {
            Ok(self.get_u8())
        } else {
            Err(ReadError::InsufficientBytes)
        }
    }

    #[inline]
    fn advance(&mut self, n: usize) -> Result<(), ReadError> {
        if n <= self.remaining_bytes() {
            <Self as Buf>::advance(self, n);
            Ok(())
        } else {
            Err(ReadError::InsufficientBytes)
        }
    }

    #[inline]
    fn remaining_bytes(&self) -> usize {
        self.remaining()
    }
}

impl Reader for BytesMut {
    #[inline]
    fn read(&mut self, dst: &mut [u8]) -> Result<(), ReadError> {
        let n = dst.len();
        if n <= self.remaining_bytes() {
            self.copy_to_slice(dst);
            Ok(())
        } else {
            Err(ReadError::InsufficientBytes)
        }
    }

    #[inline]
    fn read_u8(&mut self) -> Result<u8, ReadError> {
        if self.remaining_bytes() > 0 {
            Ok(self.get_u8())
        } else {
            Err(ReadError::InsufficientBytes)
        }
    }

    #[inline]
    fn advance(&mut self, n: usize) -> Result<(), ReadError> {
        if n <= self.remaining_bytes() {
            <Self as Buf>::advance(self, n);
            Ok(())
        } else {
            Err(ReadError::InsufficientBytes)
        }
    }

    #[inline]
    fn remaining_bytes(&self) -> usize {
        self.remaining()
    }
}

impl Writer for BytesMut {
    #[inline]
    fn write(&mut self, _label: &'static [u8], src: &[u8]) -> Result<(), WriteError> {
        self.extend_from_slice(src);
        Ok(())
    }

    #[inline]
    fn write_u8(&mut self, _label: &'static [u8], x: u8) -> Result<(), WriteError> {
        if self.remaining_mut() == 0 {
            self.reserve(1);
        }
        self.put_u8(x);
        Ok(())
    }

    #[inline]
    fn remaining_capacity(&self) -> usize {
        usize::max_value()
    }
}
