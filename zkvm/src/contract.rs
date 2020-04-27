use serde::{Deserialize, Serialize};

use crate::constraints::Commitment;
use crate::encoding::*;
use crate::errors::VMError;
use crate::merkle::MerkleItem;
use crate::predicate::Predicate;
use crate::program::ProgramItem;
use crate::types::{String, Value};
use merlin::Transcript;

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

impl Encodable for Contract {
    /// Serializes the contract to a byte array
    fn encode(&self, w: &mut impl Writer) -> Result<(), WriteError> {
        w.write(b"anchor", &self.anchor.0)?;
        w.write_point(b"predicate", &self.predicate.to_point())?;
        w.write_size(b"k", self.payload.len())?;
        for item in self.payload.iter() {
            item.encode(w)?;
        }
        Ok(())
    }
    /// Precise length of a serialized output
    fn encoded_length(&self) -> usize {
        let mut size = 32 + 32 + 4;
        for item in self.payload.iter() {
            size += item.encoded_length();
        }
        size
    }
}
impl Contract {
    /// Returns the contract's ID
    pub fn id(&self) -> ContractID {
        let mut t = Transcript::new(b"ZkVM.contractid");
        self.encode(&mut t)
            .expect("Writing to Transcript never fails.");
        ContractID(t.challenge_u8x32(b"id"))
    }

    /// Parses a contract from an output object
    pub fn decode<'a>(reader: &mut impl Reader) -> Result<Self, VMError> {
        //    Output  =  Anchor  ||  Predicate  ||  LE32(k)  ||  Item[0]  || ... ||  Item[k-1]
        //    Anchor  =  <32 bytes>
        // Predicate  =  <32 bytes>
        //      Item  =  enum { String, Program, Value }
        //    String  =  0x00  ||  LE32(len)  ||  <bytes>
        //    Program =  0x01  ||  LE32(len)  ||  <bytes>
        //     Value  =  0x02  ||  <32 bytes> ||  <32 bytes>

        let anchor = Anchor(reader.read_u8x32()?);
        let predicate = Predicate::Opaque(reader.read_point()?);
        let k = reader.read_size()?;
        let payload: Vec<PortableItem> = reader.read_vec_with(k, 5, |r| PortableItem::decode(r))?;
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
                w.write_size(b"n", d.encoded_length())?;
                d.encode(w)?;
            }
            // Program = 0x01 || LE32(len) || <bytes>
            PortableItem::Program(p) => {
                w.write_u8(b"type", PROG_TYPE)?;
                w.write_size(b"n", p.encoded_length())?;
                p.encode(w)?;
            }
            // Value = 0x02 || <32 bytes> || <32 bytes>
            PortableItem::Value(v) => {
                w.write_u8(b"type", VALUE_TYPE)?;
                w.write_point(b"qty", &v.qty.to_point())?;
                w.write_point(b"flv", &v.flv.to_point())?;
            }
        }
        Ok(())
    }
    /// Precise length of a serialized payload item
    fn encoded_length(&self) -> usize {
        match self {
            PortableItem::String(d) => 1 + 4 + d.encoded_length(),
            PortableItem::Program(p) => 1 + 4 + p.encoded_length(),
            PortableItem::Value(_) => 1 + 64,
        }
    }
}

impl PortableItem {
    fn decode<'a>(output: &mut impl Reader) -> Result<Self, VMError> {
        match output.read_u8()? {
            STRING_TYPE => {
                let len = output.read_size()?;
                let bytes = output.read_vec(len)?;
                Ok(PortableItem::String(String::Opaque(bytes)))
            }
            PROG_TYPE => {
                let len = output.read_size()?;
                let bytes = output.read_vec(len)?;
                Ok(PortableItem::Program(ProgramItem::Bytecode(bytes)))
            }
            VALUE_TYPE => {
                let qty = Commitment::Closed(output.read_point()?);
                let flv = Commitment::Closed(output.read_point()?);
                Ok(PortableItem::Value(Value { qty, flv }))
            }
            _ => Err(VMError::FormatError),
        }
    }
}

impl MerkleItem for ContractID {
    fn commit(&self, t: &mut Transcript) {
        t.append_message(b"contract", self.as_bytes());
    }
}
