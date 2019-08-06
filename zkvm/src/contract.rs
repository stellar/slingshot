use serde::{self, Deserialize, Serialize};

use crate::constraints::Commitment;
use crate::encoding::{self, Encodable, SliceReader};
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
#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub struct Anchor([u8; 32]);

/// A unique identifier for a contract.
#[derive(Copy, Clone, Eq, Hash, Debug, PartialEq, Default, Serialize, Deserialize)]
pub struct ContractID([u8; 32]);

/// A ZkVM contract that holds a _payload_ (a list of portable items) protected by a _predicate_.
#[derive(Clone, Debug)]
pub struct Contract {
    /// Predicate that guards access to the contract’s payload.
    pub predicate: Predicate,

    /// List of payload items.
    pub payload: Vec<PortableItem>,

    /// Anchor string which makes the contract unique.
    pub anchor: Anchor,
}

/// Representation of items that can be stored within outputs and contracts.
#[derive(Clone, Debug)]
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
    fn encode(&self, buf: &mut Vec<u8>) {
        encoding::write_bytes(&self.anchor.0, buf);
        encoding::write_point(&self.predicate.to_point(), buf);
        encoding::write_u32(self.payload.len() as u32, buf);
        for item in self.payload.iter() {
            item.encode(buf);
        }
    }
    /// Precise length of a serialized output
    fn serialized_length(&self) -> usize {
        let mut size = 32 + 32 + 4;
        for item in self.payload.iter() {
            size += item.serialized_length();
        }
        size
    }
}
impl Contract {
    /// Returns the contract's ID
    pub fn id(&self) -> ContractID {
        let buf = self.encode_to_vec();
        let mut t = Transcript::new(b"ZkVM.contractid");
        t.append_message(b"contract", &buf);
        let mut id = [0u8; 32];
        t.challenge_bytes(b"id", &mut id);
        ContractID(id)
    }

    /// Parses a contract from an output object
    pub fn decode<'a>(reader: &mut SliceReader<'a>) -> Result<Self, VMError> {
        //    Output  =  Anchor  ||  Predicate  ||  LE32(k)  ||  Item[0]  || ... ||  Item[k-1]
        //    Anchor  =  <32 bytes>
        // Predicate  =  <32 bytes>
        //      Item  =  enum { String, Value }
        //    String  =  0x00  ||  LE32(len)  ||  <bytes>
        //    Program =  0x01  ||  LE32(len)  ||  <bytes>
        //     Value  =  0x02  ||  <32 bytes> ||  <32 bytes>

        let anchor = Anchor(reader.read_u8x32()?);
        let predicate = Predicate::Opaque(reader.read_point()?);
        let k = reader.read_size()?;

        // sanity check: avoid allocating unreasonably more memory
        // just because an untrusted length prefix says so.
        if k > reader.len() {
            return Err(VMError::FormatError);
        }
        let mut payload: Vec<PortableItem> = Vec::with_capacity(k);
        for _ in 0..k {
            payload.push(PortableItem::decode(reader)?);
        }
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
    fn encode(&self, buf: &mut Vec<u8>) {
        match self {
            // String = 0x00 || LE32(len) || <bytes>
            PortableItem::String(d) => {
                encoding::write_u8(STRING_TYPE, buf);
                encoding::write_u32(d.serialized_length() as u32, buf);
                d.encode(buf);
            }
            // Program = 0x01 || LE32(len) || <bytes>
            PortableItem::Program(p) => {
                encoding::write_u8(PROG_TYPE, buf);
                encoding::write_u32(p.serialized_length() as u32, buf);
                p.encode(buf);
            }
            // Value = 0x02 || <32 bytes> || <32 bytes>
            PortableItem::Value(v) => {
                encoding::write_u8(VALUE_TYPE, buf);
                encoding::write_point(&v.qty.to_point(), buf);
                encoding::write_point(&v.flv.to_point(), buf);
            }
        }
    }
    /// Precise length of a serialized payload item
    fn serialized_length(&self) -> usize {
        match self {
            PortableItem::String(d) => 1 + 4 + d.serialized_length(),
            PortableItem::Program(p) => 1 + 4 + p.serialized_length(),
            PortableItem::Value(_) => 1 + 64,
        }
    }
}

impl PortableItem {
    fn decode<'a>(output: &mut SliceReader<'a>) -> Result<Self, VMError> {
        match output.read_u8()? {
            STRING_TYPE => {
                let len = output.read_size()?;
                let bytes = output.read_bytes(len)?;
                Ok(PortableItem::String(String::Opaque(bytes.to_vec())))
            }
            PROG_TYPE => {
                let len = output.read_size()?;
                let bytes = output.read_bytes(len)?;
                Ok(PortableItem::Program(ProgramItem::Bytecode(bytes.to_vec())))
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
