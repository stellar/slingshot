use crate::{ReadError, Reader, WriteError, Writer};

/// A trait for encoding structures using the [Writer] trait.
///
/// [Writer]: readerwriter::Writer
pub trait Encodable {
    /// Encodes receiver into bytes appending them to a provided buffer.
    fn encode(&self, w: &mut impl Writer) -> Result<(), WriteError>;
    /// If possible, returns an encoded size as a hint for allocating appropriate buffer.
    /// Default implementation returns None.
    fn encoded_size_hint(&self) -> Option<usize> {
        None
    }

    /// Encodes the receiver into a newly allocated vector of bytes.
    fn encode_to_vec(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.encoded_size_hint().unwrap_or(0));
        self.encode(&mut buf)
            .expect("Writing to a Vec never fails.");
        buf
    }
}

pub trait ExactSizeEncodable: Encodable {
    /// Exact encoded size in bytes of the object.
    fn encoded_size(&self) -> usize;

    fn encoded_size_hint(&self) -> Option<usize> {
        Some(self.encoded_size())
    }
}

/// A trait for decoding bytes into structure using the [Reader] trait.
///
/// [Reader]: readerwriter::Reader
pub trait Decodable: Sized {
    /// Decodes bytes into self by reading bytes from reader.
    fn decode(buf: &mut impl Reader) -> Result<Self, ReadError>;
}

/// Trait which implements for structures which implement both [Decodable] and [Encodable] traits.
pub trait Codable: Encodable + Decodable {}

impl<T: Decodable + Encodable> Codable for T {}
