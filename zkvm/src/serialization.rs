//! Utilities to support serialization needs

/// Implements `serde::Serialize` and `serde::Deserialize` for a tuple-struct that wraps `[u8;32]`.
#[macro_export]
macro_rules! serialize_bytes32 {
    ($type_name:ident) => {
        impl serde::Serialize for $type_name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                serializer.serialize_bytes(&self.0)
            }
        }

        impl<'de> serde::Deserialize<'de> for $type_name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                struct BytesVisitor;

                impl<'de> serde::de::Visitor<'de> for BytesVisitor {
                    type Value = $type_name;

                    fn expecting(
                        &self,
                        formatter: &mut ::core::fmt::Formatter,
                    ) -> ::core::fmt::Result {
                        formatter.write_str("a valid 32-byte string")
                    }

                    fn visit_bytes<E>(self, v: &[u8]) -> Result<$type_name, E>
                    where
                        E: serde::de::Error,
                    {
                        if v.len() == 32 {
                            let mut buf = [0u8; 32];
                            buf[0..32].copy_from_slice(v);
                            Ok($type_name(buf))
                        } else {
                            Err(serde::de::Error::invalid_length(v.len(), &self))
                        }
                    }
                }

                deserializer.deserialize_bytes(BytesVisitor)
            }
        }
    };
}
