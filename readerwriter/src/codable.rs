use crate::{Reader, Writer};

/// A trait for encoding structures using the [Writer] trait.
///
/// [Writer]: readerwriter::Writer
pub trait Encodable {
    type Error: std::error::Error;
    /// Encodes receiver into bytes appending them to a provided buffer.
    fn encode(&self, w: &mut impl Writer) -> Result<(), Self::Error>;
    /// Returns precise length in bytes for the serialized representation of the receiver.
    fn encoded_length(&self) -> usize;
    /// Encodes the receiver into a newly allocated vector of bytes.
    fn encode_to_vec(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.encoded_length());
        self.encode(&mut buf)
            .expect("Writing to a Vec never fails.");
        buf
    }
}

/// A trait for decoding bytes into structure using the [Reader] trait.
///
/// [Reader]: readerwriter::Reader
pub trait Decodable: Sized {
    type Error: std::error::Error;
    /// Decodes bytes into self by reading bytes from reader.
    fn decode(buf: &mut impl Reader) -> Result<Self, Self::Error>;
}

/// Trait which implements for structures which implement both [Decodable] and [Encodable] traits.
pub trait Codable: Encodable + Decodable {
    type Error: std::error::Error;
}

impl<T: Decodable<Error = E> + Encodable<Error = E>, E: std::error::Error> Codable for T {
    type Error = E;
}
