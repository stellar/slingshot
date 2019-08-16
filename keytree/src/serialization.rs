//! Serde support for Xprv/Xpub types.

use super::{Xprv, Xpub};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

impl Serialize for Xprv {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&self.to_bytes()[..])
    }
}

impl<'de> Deserialize<'de> for Xprv {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct BytesVisitor;

        impl<'de> serde::de::Visitor<'de> for BytesVisitor {
            type Value = Xprv;

            fn expecting(&self, formatter: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                formatter.write_str("a valid 64-byte string")
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Xprv, E>
            where
                E: serde::de::Error,
            {
                if v.len() == 64 {
                    Xprv::from_bytes(v).ok_or(serde::de::Error::custom("decoding failed"))
                } else {
                    Err(serde::de::Error::invalid_length(v.len(), &self))
                }
            }
        }

        deserializer.deserialize_bytes(BytesVisitor)
    }
}

impl Serialize for Xpub {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&self.to_bytes()[..])
    }
}

impl<'de> Deserialize<'de> for Xpub {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct BytesVisitor;

        impl<'de> serde::de::Visitor<'de> for BytesVisitor {
            type Value = Xpub;

            fn expecting(&self, formatter: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                formatter.write_str("a valid 64-byte string")
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Xpub, E>
            where
                E: serde::de::Error,
            {
                if v.len() == 64 {
                    Xpub::from_bytes(v).ok_or(serde::de::Error::custom("decompression failed"))
                } else {
                    Err(serde::de::Error::invalid_length(v.len(), &self))
                }
            }
        }

        deserializer.deserialize_bytes(BytesVisitor)
    }
}
