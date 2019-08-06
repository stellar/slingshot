//! Utilities to support serialization into arbitrary data formats, such as JSON.
//! Consensus-critical logic of ZkVM uses separate encoding mechanism
//! specified via `encoding` module.
//! 
//! This module contains:
//! 1. Adapter types that contain redundant fields (such as IDs)
//!    that are computed from the rest of the data.
//! 2. Adapter for hex-encoding of the binary strings such as IDs, proofs and signatures.
//!    Hex encoding is only performed with human-readable serializers (such as JSON).
use std::{str::from_utf8_unchecked, fmt};
//use core::{convert::TryFrom, marker::PhantomData};
use serde::{de::Visitor};
use serde::{self, Deserializer, Serializer, Deserialize, Serialize};
use subtle_encoding::hex;
//use crate::{Predicate,Anchor,PortableItem,ContractID};


// /// Contract annotated with its ID
// #[derive(Clone, Debug, Serialize, Deserialize)]
// pub struct ContractWithID {
//     /// Computed ID of the contract.
//     pub id: ContractID,

//     /// Predicate that guards access to the contract’s payload.
//     pub predicate: Predicate,

//     /// List of payload items.
//     pub payload: Vec<PortableItem>,

//     /// Anchor string which makes the contract unique.
//     pub anchor: Anchor,
// }

// impl From<ContractID> for OpaqueBinary32 {
//     fn from(cid: ContractID) -> OpaqueBinary32 {
//         OpaqueBinary32(cid.0)
//     }
// }

/// Trait for types serializable as opaque 32-byte strings (such as IDs),
/// hex-encoded in human-readable representations.
pub trait AsHex32: From<[u8; 32]> + Into<[u8;32]>{}

impl<T> Serialize for T where T: AsHex32 {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            // We know that hex::encode returns only [0-9a-f] ascii characters that are valid UTF-8.
            serializer.serialize_str(unsafe{ from_utf8_unchecked(hex::encode(&self.into()).as_ref()) } )
        } else {
            serializer.serialize_bytes(&self.0)
        }
    }
}

impl<'de, T> Deserialize<'de> for T where T: AsHex32 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error as DeserError;

        struct HexVisitor;

        impl<'de> Visitor<'de> for HexVisitor {
            type Value = T;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("hex-encoded byte array")
            }

            fn visit_str<E: DeserError>(self, value: &str) -> Result<Self::Value, E> {
                let v = hex::decode(value).map_err(E::custom)?;
                self.visit_bytes(v.as_ref())
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
                where E: serde::de::Error
            {
                if v.len() == 32 {
                    let mut buf = [0u8; 32];
                    buf[0..32].copy_from_slice(v);
                    Ok(buf.into())
                } else {
                    Err(DeserError::invalid_length(v.len(), &self))
                }
            }
        }

        struct BinaryVisitor;

        impl<'de> Visitor<'de> for BinaryVisitor {
            type Value = Vec<u8>;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("byte array")
            }

            fn visit_bytes<E: DeserError>(self, value: &[u8]) -> Result<Self::Value, E> {
                Ok(value.to_vec())
            }
        }

        if deserializer.is_human_readable() {
            deserializer.deserialize_str(HexVisitor)
        } else {
            deserializer.deserialize_bytes(BinaryVisitor)
        }.map(|bytes| Self(bytes.to_vec()) ).map_err(D::Error::custom)
    }
}



/// Helper type for serializing opaque binary strings in hex or binary,
/// depending on the serializer.
/// Containers could use `#[serde(into=OpaqueBinary, try_from=OpaqueBinary)]`,
/// with Into<OpaqueBinary> implemented automatically for anything that implements `AsRef<[u8]>`,
/// while TryFrom<OpaqueBinary> is implemented for `From<[u8;32]>`, `From<[u8;64]>`, `Vec<u8>` and a few specific types.
pub struct OpaqueBinary(Vec<u8>);

/// Helper type for serializing 32-byte binary strings in hex.
pub struct OpaqueBinary32([u8; 32]);

/// Helper type for serializing 64-byte binary strings in hex.
pub struct OpaqueBinary64([u8; 64]);

impl Serialize for OpaqueBinary {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            // We know that hex::encode returns only [0-9a-f] ascii characters that are valid UTF-8.
            serializer.serialize_str(unsafe{ from_utf8_unchecked(hex::encode(&self.0).as_ref()) } )
        } else {
            serializer.serialize_bytes(&self.0)
        }
    }
}

impl Serialize for OpaqueBinary32 {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            // We know that hex::encode returns only [0-9a-f] ascii characters that are valid UTF-8.
            serializer.serialize_str(unsafe{ from_utf8_unchecked(hex::encode(&self.0).as_ref()) } )
        } else {
            serializer.serialize_bytes(&self.0)
        }
    }
}

impl Serialize for OpaqueBinary64 {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            // We know that hex::encode returns only [0-9a-f] ascii characters that are valid UTF-8.
            serializer.serialize_str(unsafe{ from_utf8_unchecked(hex::encode(&self.0[..]).as_ref()) } )
        } else {
            serializer.serialize_bytes(&self.0[..])
        }
    }
}

impl<'de> Deserialize<'de> for OpaqueBinary {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error as DeserError;

        struct HexVisitor;

        impl<'de> Visitor<'de> for HexVisitor {
            type Value = Vec<u8>;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("hex-encoded byte array")
            }

            fn visit_str<E: DeserError>(self, value: &str) -> Result<Self::Value, E> {
                hex::decode(value).map_err(E::custom)
            }

            // See the `deserializing_flattened_field` test for an example why this is needed.
            fn visit_bytes<E: DeserError>(self, value: &[u8]) -> Result<Self::Value, E> {
                Ok(value.to_vec())
            }
        }

        struct BinaryVisitor;

        impl<'de> Visitor<'de> for BinaryVisitor {
            type Value = Vec<u8>;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("byte array")
            }

            fn visit_bytes<E: DeserError>(self, value: &[u8]) -> Result<Self::Value, E> {
                Ok(value.to_vec())
            }
        }

        if deserializer.is_human_readable() {
            deserializer.deserialize_str(HexVisitor)
        } else {
            deserializer.deserialize_bytes(BinaryVisitor)
        }.map(|bytes| Self(bytes.to_vec()) ).map_err(D::Error::custom)
    }
}

// TBD: add deserialize for 32- and 64-byte buffers
