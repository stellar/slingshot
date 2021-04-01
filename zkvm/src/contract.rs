use core::convert::TryFrom;
use serde::{Deserialize, Serialize};

use crate::constraints::Commitment;
use crate::encoding::*;
use crate::merkle::MerkleItem;
use crate::predicate::Predicate;
use crate::program::ProgramItem;
use crate::transcript::TranscriptProtocol;
use crate::types::{String, Value};
use crate::VMError;
use merlin::Transcript;
use musig::VerificationKey;

/// Prefix for the string type in the Output Structure
pub const STRING_TYPE: u8 = 0x00;

/// Prefix for the program type in the Output Structure
pub const PROG_TYPE: u8 = 0x01;

/// Prefix for the value type in the Output Structure
pub const VALUE_TYPE: u8 = 0x02;

/// A unique identifier for an anchor
#[derive(Clone, Copy, PartialEq, Default)]
pub struct Anchor(pub [u8; 32]);
serialize_bytes32!(Anchor);

/// A unique identifier for a contract.
#[derive(Copy, Clone, Eq, Hash, Debug, PartialEq, Default)]
pub struct ContractID(pub [u8; 32]);
serialize_bytes32!(ContractID);

/// A ZkVM contract that holds a _payload_ (a list of portable items) protected by a _predicate_.
#[derive(Clone, PartialEq, Deserialize, Serialize)]
pub struct Contract {
    /// Predicate that guards access to the contract’s payload.
    pub predicate: Predicate,

    /// List of payload items.
    pub payload: Vec<PortableItem>,

    /// Anchor string which makes the contract unique.
    pub anchor: Anchor,
}

/// Representation of items that can be stored within outputs and contracts.
#[derive(Clone, PartialEq, Deserialize, Serialize)]
pub enum PortableItem {
    /// Plain data payload
    String(String),

    /// Program payload
    Program(ProgramItem),

    /// Value payload
    Value(Value),
}

impl Contract {
    /// Returns the contract's ID
    pub fn id(&self) -> ContractID {
        let mut t = Transcript::new(b"ZkVM.contractid");
        self.encode(&mut t)
            .expect("Writing to Transcript never fails.");
        ContractID(t.challenge_u8x32(b"id"))
    }
}

impl Encodable for Contract {
    fn encode(&self, w: &mut impl Writer) -> Result<(), WriteError> {
        w.write(b"anchor", &self.anchor.0)?;
        w.write_point(b"predicate", &self.predicate.to_point())?;
        w.write_size(b"k", self.payload.len())?;
        for item in self.payload.iter() {
            item.encode(w)?;
        }
        Ok(())
    }
}

impl ExactSizeEncodable for Contract {
    fn encoded_size(&self) -> usize {
        let mut size = 32 + 32 + 4;
        for item in self.payload.iter() {
            size += item.encoded_size();
        }
        size
    }
}

impl Decodable for Contract {
    /// Parses a contract from an output object
    fn decode<'a>(reader: &mut impl Reader) -> Result<Self, ReadError> {
        //    Output  =  Anchor  ||  Predicate  ||  LE32(k)  ||  Item[0]  || ... ||  Item[k-1]
        //    Anchor  =  <32 bytes>
        // Predicate  =  <32 bytes>
        //      Item  =  enum { String, Program, Value }
        //    String  =  0x00  ||  LE32(len)  ||  <bytes>
        //    Program =  0x01  ||  LE32(len)  ||  <bytes>
        //     Value  =  0x02  ||  <32 bytes> ||  <32 bytes>

        let anchor = Anchor(reader.read_u8x32()?);
        let predicate = Predicate::new(VerificationKey::from_compressed(reader.read_point()?));
        let k = reader.read_size()?;
        let payload: Vec<PortableItem> = reader.read_vec(k, |r| PortableItem::decode(r))?;
        Ok(Contract {
            anchor,
            predicate,
            payload,
        })
    }
}

impl AsRef<[u8]> for ContractID {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl Anchor {
    /// Provides a view into the anchor’s bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Converts raw bytes into an Anchor.
    ///
    /// WARNING: This is intended to be used for testing only.
    /// TBD: add an API later which is tailored to
    /// (a) specifying initial utxo set, and/or
    /// (b) per-block minted utxos.
    pub fn from_raw_bytes(raw_bytes: [u8; 32]) -> Self {
        Self(raw_bytes)
    }

    /// Ratchet the anchor into a new anchor
    pub fn ratchet(mut self) -> Self {
        let mut t = Transcript::new(b"ZkVM.ratchet-anchor");
        t.append_message(b"old", &self.0);
        t.challenge_bytes(b"new", &mut self.0);
        self
    }
}

impl ContractID {
    /// Provides a view into the contract ID's bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Re-wraps contract ID bytes into Anchor
    pub(crate) fn to_anchor(self) -> Anchor {
        Anchor(self.0)
    }
}

impl Encodable for PortableItem {
    fn encode(&self, w: &mut impl Writer) -> Result<(), WriteError> {
        match self {
            // String = 0x00 || LE32(len) || <bytes>
            PortableItem::String(d) => {
                w.write_u8(b"type", STRING_TYPE)?;
                w.write_size(b"n", d.encoded_size())?;
                d.encode(w)?;
            }
            // Program = 0x01 || LE32(len) || <bytes>
            PortableItem::Program(p) => {
                w.write_u8(b"type", PROG_TYPE)?;
                w.write_size(b"n", p.encoded_size())?;
                p.encode(w)?;
            }
            // Value = 0x02 || <32 bytes> || <32 bytes>
            PortableItem::Value(v) => {
                w.write_u8(b"type", VALUE_TYPE)?;
                v.encode(w)?;
            }
        }
        Ok(())
    }
}

impl ExactSizeEncodable for PortableItem {
    fn encoded_size(&self) -> usize {
        match self {
            PortableItem::String(d) => 1 + 4 + d.encoded_size(),
            PortableItem::Program(p) => 1 + 4 + p.encoded_size(),
            PortableItem::Value(_) => 1 + 64,
        }
    }
}

impl Decodable for PortableItem {
    fn decode<'a>(reader: &mut impl Reader) -> Result<Self, ReadError> {
        match reader.read_u8()? {
            STRING_TYPE => {
                let len = reader.read_size()?;
                let bytes = reader.read_bytes(len)?;
                Ok(PortableItem::String(String::Opaque(bytes)))
            }
            PROG_TYPE => {
                let len = reader.read_size()?;
                let bytes = reader.read_bytes(len)?;
                Ok(PortableItem::Program(ProgramItem::Bytecode(bytes)))
            }
            VALUE_TYPE => {
                let qty = Commitment::Closed(reader.read_point()?);
                let flv = Commitment::Closed(reader.read_point()?);
                Ok(PortableItem::Value(Value { qty, flv }))
            }
            _ => Err(ReadError::InvalidFormat),
        }
    }
}
impl PortableItem {
    /// Attempts to cast the item as a Value type.
    pub fn as_value(&self) -> Option<&Value> {
        match self {
            PortableItem::Value(v) => Some(v),
            _ => None,
        }
    }
}

impl MerkleItem for ContractID {
    fn commit(&self, t: &mut Transcript) {
        t.append_message(b"contract", self.as_bytes());
    }
}

// Parsing contracts

impl TryFrom<PortableItem> for String {
    type Error = VMError;

    fn try_from(value: PortableItem) -> Result<Self, Self::Error> {
        match value {
            PortableItem::String(x) => Ok(x),
            _ => Err(VMError::TypeNotString),
        }
    }
}

impl TryFrom<PortableItem> for Value {
    type Error = VMError;

    fn try_from(value: PortableItem) -> Result<Self, Self::Error> {
        match value {
            PortableItem::Value(x) => Ok(x),
            _ => Err(VMError::TypeNotValue),
        }
    }
}

impl TryFrom<PortableItem> for ProgramItem {
    type Error = VMError;

    fn try_from(value: PortableItem) -> Result<Self, Self::Error> {
        match value {
            PortableItem::Program(x) => Ok(x),
            _ => Err(VMError::TypeNotProgram),
        }
    }
}

impl<'a> TryFrom<&'a PortableItem> for &'a String {
    type Error = VMError;

    fn try_from(value: &'a PortableItem) -> Result<Self, Self::Error> {
        match value {
            PortableItem::String(x) => Ok(x),
            _ => Err(VMError::TypeNotString),
        }
    }
}

impl<'a> TryFrom<&'a PortableItem> for &'a Value {
    type Error = VMError;

    fn try_from(value: &'a PortableItem) -> Result<Self, Self::Error> {
        match value {
            PortableItem::Value(x) => Ok(x),
            _ => Err(VMError::TypeNotValue),
        }
    }
}

impl<'a> TryFrom<&'a PortableItem> for &'a ProgramItem {
    type Error = VMError;

    fn try_from(value: &'a PortableItem) -> Result<Self, Self::Error> {
        match value {
            PortableItem::Program(x) => Ok(x),
            _ => Err(VMError::TypeNotProgram),
        }
    }
}

impl Contract {
    /// Extracts a single item from the contract's payload with a given type.
    pub fn extract<'a, T1>(&'a self) -> Option<T1>
    where
        T1: TryFrom<&'a PortableItem>,
    {
        if self.payload.len() != 1 {
            return None;
        }
        T1::try_from(self.payload.get(0)?).ok()
    }

    /// Extracts two payload items with the given types.
    pub fn extract2<'a, T1, T2>(&'a self) -> Option<(T1, T2)>
    where
        T1: TryFrom<&'a PortableItem>,
        T2: TryFrom<&'a PortableItem>,
    {
        if self.payload.len() != 2 {
            return None;
        }
        Some((
            T1::try_from(self.payload.get(0)?).ok()?,
            T2::try_from(self.payload.get(1)?).ok()?,
        ))
    }

    /// Extracts three payload items with the given types.
    pub fn extract3<'a, T1, T2, T3>(&'a self) -> Option<(T1, T2, T3)>
    where
        T1: TryFrom<&'a PortableItem>,
        T2: TryFrom<&'a PortableItem>,
        T3: TryFrom<&'a PortableItem>,
    {
        if self.payload.len() != 3 {
            return None;
        }
        Some((
            T1::try_from(self.payload.get(0)?).ok()?,
            T2::try_from(self.payload.get(1)?).ok()?,
            T3::try_from(self.payload.get(2)?).ok()?,
        ))
    }

    /// Extracts four payload items with the given types.
    pub fn extract4<'a, T1, T2, T3, T4>(&'a self) -> Option<(T1, T2, T3, T4)>
    where
        T1: TryFrom<&'a PortableItem>,
        T2: TryFrom<&'a PortableItem>,
        T3: TryFrom<&'a PortableItem>,
        T4: TryFrom<&'a PortableItem>,
    {
        if self.payload.len() != 4 {
            return None;
        }
        Some((
            T1::try_from(self.payload.get(0)?).ok()?,
            T2::try_from(self.payload.get(1)?).ok()?,
            T3::try_from(self.payload.get(2)?).ok()?,
            T4::try_from(self.payload.get(3)?).ok()?,
        ))
    }

    /// Extracts five payload items with the given types.
    pub fn extract5<'a, T1, T2, T3, T4, T5>(&'a self) -> Option<(T1, T2, T3, T4, T5)>
    where
        T1: TryFrom<&'a PortableItem>,
        T2: TryFrom<&'a PortableItem>,
        T3: TryFrom<&'a PortableItem>,
        T4: TryFrom<&'a PortableItem>,
        T5: TryFrom<&'a PortableItem>,
    {
        if self.payload.len() != 5 {
            return None;
        }
        Some((
            T1::try_from(self.payload.get(0)?).ok()?,
            T2::try_from(self.payload.get(1)?).ok()?,
            T3::try_from(self.payload.get(2)?).ok()?,
            T4::try_from(self.payload.get(3)?).ok()?,
            T5::try_from(self.payload.get(4)?).ok()?,
        ))
    }

    /// Extracts six payload items with the given types.
    pub fn extract6<'a, T1, T2, T3, T4, T5, T6>(&'a self) -> Option<(T1, T2, T3, T4, T5, T6)>
    where
        T1: TryFrom<&'a PortableItem>,
        T2: TryFrom<&'a PortableItem>,
        T3: TryFrom<&'a PortableItem>,
        T4: TryFrom<&'a PortableItem>,
        T5: TryFrom<&'a PortableItem>,
        T6: TryFrom<&'a PortableItem>,
    {
        if self.payload.len() != 6 {
            return None;
        }
        Some((
            T1::try_from(self.payload.get(0)?).ok()?,
            T2::try_from(self.payload.get(1)?).ok()?,
            T3::try_from(self.payload.get(2)?).ok()?,
            T4::try_from(self.payload.get(3)?).ok()?,
            T5::try_from(self.payload.get(4)?).ok()?,
            T6::try_from(self.payload.get(5)?).ok()?,
        ))
    }

    /// Extracts seven payload items with the given types.
    pub fn extract7<'a, T1, T2, T3, T4, T5, T6, T7>(
        &'a self,
    ) -> Option<(T1, T2, T3, T4, T5, T6, T7)>
    where
        T1: TryFrom<&'a PortableItem>,
        T2: TryFrom<&'a PortableItem>,
        T3: TryFrom<&'a PortableItem>,
        T4: TryFrom<&'a PortableItem>,
        T5: TryFrom<&'a PortableItem>,
        T6: TryFrom<&'a PortableItem>,
        T7: TryFrom<&'a PortableItem>,
    {
        if self.payload.len() != 7 {
            return None;
        }
        Some((
            T1::try_from(self.payload.get(0)?).ok()?,
            T2::try_from(self.payload.get(1)?).ok()?,
            T3::try_from(self.payload.get(2)?).ok()?,
            T4::try_from(self.payload.get(3)?).ok()?,
            T5::try_from(self.payload.get(4)?).ok()?,
            T6::try_from(self.payload.get(5)?).ok()?,
            T7::try_from(self.payload.get(6)?).ok()?,
        ))
    }

    /// Extracts eight payload items with the given types.
    pub fn extract8<'a, T1, T2, T3, T4, T5, T6, T7, T8>(
        &'a self,
    ) -> Option<(T1, T2, T3, T4, T5, T6, T7, T8)>
    where
        T1: TryFrom<&'a PortableItem>,
        T2: TryFrom<&'a PortableItem>,
        T3: TryFrom<&'a PortableItem>,
        T4: TryFrom<&'a PortableItem>,
        T5: TryFrom<&'a PortableItem>,
        T6: TryFrom<&'a PortableItem>,
        T7: TryFrom<&'a PortableItem>,
        T8: TryFrom<&'a PortableItem>,
    {
        if self.payload.len() != 8 {
            return None;
        }
        Some((
            T1::try_from(self.payload.get(0)?).ok()?,
            T2::try_from(self.payload.get(1)?).ok()?,
            T3::try_from(self.payload.get(2)?).ok()?,
            T4::try_from(self.payload.get(3)?).ok()?,
            T5::try_from(self.payload.get(4)?).ok()?,
            T6::try_from(self.payload.get(5)?).ok()?,
            T7::try_from(self.payload.get(6)?).ok()?,
            T8::try_from(self.payload.get(7)?).ok()?,
        ))
    }
}
