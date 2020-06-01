mod codable;
mod reader;
mod writer;

pub use codable::{Codable, Decodable, Encodable, ExactSizeEncodable};
pub use reader::{ReadError, Reader};
pub use writer::{WriteError, Writer};

#[cfg(feature = "merlin")]
mod merlin_support;
#[cfg(feature = "merlin")]
pub use merlin_support::*;

#[cfg(feature = "bytes")]
mod bytes_support;
#[cfg(feature = "bytes")]
pub use bytes_support::*;
