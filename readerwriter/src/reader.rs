/// Error kinds returns by the reader.
#[derive(Debug,Display,Clone,PartialEq)]
pub enum ReadError {
    EOF,
    TrailingBytes,
}

/// An interface for reading binary data.
pub trait Reader {
    /// Copies bytes into a slice. If there is not enough bytes available,
    /// does not consume any byte and returns ReadError::EOF.
    fn read(&mut self, dst: &mut [u8]) -> Result<(), ReadError>;

    /// Advances the internal cursor by the number of bytes.
    /// If there is not enough bytes, does nothing and returns ReadError::EOF.
    fn advance(&mut self, cnt: usize) -> Result<(), ReadError>;

    /// Returns remaining number of bytes available for reading.
    fn remaining(&self) -> usize;

    /// Wraps the reading logic in a block that checks that all bytes have been read.
    /// If some are left unread, returns `Err(From<ReadError::TrailingBytes>)`.
    /// Use method `skip_trailing_bytes` to ignore trailing bytes.
    pub fn parse<F, T, E>(&mut self, parse_fn: F) -> Result<T, E>
    where
        F: FnOnce(&mut Self) -> Result<T, E>,
        E: From<ReadError>
    {
        let result = parse_fn(self)?;
        if self.remaining() != 0 {
            return Err(ReadError::TrailingBytes.into());
        }
        Ok(result)
    }

    /// Marks remaining unread bytes as read so that `parse` does not fail.
    /// After calling this method, no more bytes can be read.
    pub fn skip_trailing_bytes(&mut self) -> usize {
        let rem = self.remaining();
        self.advance(rem).expect("Reader::advance(remaining()) should never fail");
        rem
    }
}
