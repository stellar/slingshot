/// Error kinds returns by the reader.
#[derive(Debug, Clone, PartialEq)]
pub enum ReadError {
    InsufficientBytes,
    TrailingBytes,
}

/// An interface for reading binary data.
pub trait Reader {
    /// Copies bytes into a slice. If there is not enough bytes available,
    /// does not consume any byte and returns ReadError::InsufficientBytes.
    fn read(&mut self, dst: &mut [u8]) -> Result<(), ReadError>;

    /// Advances the internal cursor by the number of bytes.
    /// If there is not enough bytes, does nothing and returns ReadError::InsufficientBytes.
    fn advance(&mut self, cnt: usize) -> Result<(), ReadError>;

    /// Returns remaining number of bytes available for reading.
    fn remaining_bytes(&self) -> usize;

    /// Wraps the reading logic in a block that checks that all bytes have been read.
    /// If some are left unread, returns `Err(From<ReadError::TrailingBytes>)`.
    /// Use method `skip_trailing_bytes` to ignore trailing bytes.
    #[inline]
    fn parse<F, T, E>(&mut self, parse_fn: F) -> Result<T, E>
    where
        F: FnOnce(&mut Self) -> Result<T, E>,
        E: From<ReadError>,
    {
        let result = parse_fn(self)?;
        if self.remaining_bytes() != 0 {
            return Err(ReadError::TrailingBytes.into());
        }
        Ok(result)
    }

    /// Marks remaining unread bytes as read so that `parse` does not fail.
    /// After calling this method, no more bytes can be read.
    #[inline]
    fn skip_trailing_bytes(&mut self) -> usize {
        let rem = self.remaining_bytes();
        self.advance(rem)
            .expect("Reader::advance(remaining()) should never fail");
        rem
    }

    /// Reads a single byte.
    #[inline]
    fn read_u8(&mut self) -> Result<u8, ReadError> {
        let mut buf = [0u8; 1];
        self.read(&mut buf)?;
        Ok(buf[0])
    }

    /// Reads a 4-byte LE32 integer.
    #[inline]
    fn read_u32(&mut self) -> Result<u32, ReadError> {
        let mut buf = [0u8; 4];
        self.read(&mut buf)?;
        Ok(u32::from_le_bytes(buf))
    }

    /// Reads an 8-byte LE64 integer.
    #[inline]
    fn read_u64(&mut self) -> Result<u64, ReadError> {
        let mut buf = [0u8; 8];
        self.read(&mut buf)?;
        Ok(u64::from_le_bytes(buf))
    }

    /// Reads a 32-byte string.
    #[inline]
    fn read_u8x32(&mut self) -> Result<[u8; 32], ReadError> {
        let mut buf = [0u8; 32];
        self.read(&mut buf)?;
        Ok(buf)
    }

    /// Reads a 64-byte string.
    #[inline]
    fn read_u8x64(&mut self) -> Result<[u8; 64], ReadError> {
        let mut buf = [0u8; 64];
        self.read(&mut buf)?;
        Ok(buf)
    }
}

impl Reader for &[u8] {
    #[inline]
    fn read(&mut self, dst: &mut [u8]) -> Result<(), ReadError> {
        let n = dst.len();
        if self.len() >= n {
            let (a, b) = self.split_at(n);
            if n == 1 {
                dst[0] = a[0];
            } else {
                dst.copy_from_slice(a);
            }
            *self = b;
            Ok(())
        } else {
            Err(ReadError::InsufficientBytes)
        }
    }

    #[inline]
    fn advance(&mut self, n: usize) -> Result<(), ReadError> {
        if self.len() >= n {
            let (_, b) = self.split_at(n);
            *self = b;
            Ok(())
        } else {
            Err(ReadError::InsufficientBytes)
        }
    }

    #[inline]
    fn remaining_bytes(&self) -> usize {
        self.len()
    }
}
