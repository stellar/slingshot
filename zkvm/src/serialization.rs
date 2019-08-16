//! Utilities to support serialization needs

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

/// Serde adaptor for 64-item array
pub mod array64 {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<T, S>(value: &[T; 64], serializer: S) -> Result<S::Ok, S::Error>
    where
        T: Serialize + Clone,
        S: Serializer,
    {
        value.to_vec().serialize(serializer)
    }

    pub fn deserialize<'de, D, T>(deserializer: D) -> Result<[T; 64], D::Error>
    where
        D: Deserializer<'de>,
        T: Deserialize<'de> + Default,
    {
        let mut vec = Vec::<T>::deserialize(deserializer)?;
        if vec.len() != 64 {
            return Err(serde::de::Error::invalid_length(
                vec.len(),
                &"a 64-item array",
            ));
        }
        let mut buf: [T; 64] = [
            T::default(),
            T::default(),
            T::default(),
            T::default(),
            T::default(),
            T::default(),
            T::default(),
            T::default(),
            T::default(),
            T::default(),
            T::default(),
            T::default(),
            T::default(),
            T::default(),
            T::default(),
            T::default(),
            T::default(),
            T::default(),
            T::default(),
            T::default(),
            T::default(),
            T::default(),
            T::default(),
            T::default(),
            T::default(),
            T::default(),
            T::default(),
            T::default(),
            T::default(),
            T::default(),
            T::default(),
            T::default(),
            T::default(),
            T::default(),
            T::default(),
            T::default(),
            T::default(),
            T::default(),
            T::default(),
            T::default(),
            T::default(),
            T::default(),
            T::default(),
            T::default(),
            T::default(),
            T::default(),
            T::default(),
            T::default(),
            T::default(),
            T::default(),
            T::default(),
            T::default(),
            T::default(),
            T::default(),
            T::default(),
            T::default(),
            T::default(),
            T::default(),
            T::default(),
            T::default(),
            T::default(),
            T::default(),
            T::default(),
            T::default(),
        ];
        for i in 0..64 {
            buf[63 - i] = vec.pop().unwrap();
        }
        Ok(buf)
    }
}
