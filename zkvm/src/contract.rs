use crate::constraints::Commitment;
use crate::encoding;
use crate::encoding::Encodable;
use crate::encoding::SliceReader;
use crate::errors::VMError;
use crate::merkle::MerkleItem;
use crate::predicate::Predicate;
use crate::program::ProgramItem;
use crate::types::{Data, Value};
use merlin::Transcript;

/// Prefix for the data type in the Output Structure
pub const DATA_TYPE: u8 = 0x00;

/// Prefix for the program type in the Output Structure
pub const PROG_TYPE: u8 = 0x01;

/// Prefix for the value type in the Output Structure
pub const VALUE_TYPE: u8 = 0x02;

/// A unique identifier for an anchor
#[derive(Copy, Clone, Debug)]
pub struct Anchor([u8; 32]);

/// A unique identifier for a contract.
#[derive(Copy, Clone, Eq, Hash, Debug, PartialEq, Default)]
pub struct ContractID([u8; 32]);

/// A ZkVM contract that holds a _payload_ (a list of portable items) protected by a _predicate_.
#[derive(Clone, Debug)]
pub struct Contract {
    /// ID of the contract
    id: ContractID,

    /// Predicate that guards access to the contract’s payload.
    predicate: Predicate,

    /// List of payload items.
    payload: Vec<PortableItem>,

    /// Anchor string which makes the contract unique.
    anchor: Anchor,
}

/// Representation of items that can be stored within outputs and contracts.
#[derive(Clone, Debug)]
pub enum PortableItem {
    /// Plain data payload
    Data(Data),

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
    /// Creates a contract from a given fields
    pub fn new(predicate: Predicate, payload: Vec<PortableItem>, anchor: Anchor) -> Self {
        let mut contract = Self {
            id: ContractID::default(), // will be updated below
            predicate,
            payload,
            anchor,
        };
        let buf = contract.encode_to_vec();
        contract.id = ContractID::from_serialized_contract(&buf);
        contract
    }

    /// Returns the contract's ID
    pub fn id(&self) -> ContractID {
        self.id
    }

    /// Breaks up the contract into individual fields
    pub fn into_tuple(self) -> (ContractID, Predicate, Vec<PortableItem>, Anchor) {
        (self.id, self.predicate, self.payload, self.anchor)
    }

    /// Parses a contract from an output object
    pub fn decode<'a>(reader: &mut SliceReader<'a>) -> Result<Self, VMError> {
        //    Output  =  Anchor  ||  Predicate  ||  LE32(k)  ||  Item[0]  || ... ||  Item[k-1]
        //    Anchor  =  <32 bytes>
        // Predicate  =  <32 bytes>
        //      Item  =  enum { Data, Value }
        //      Data  =  0x00  ||  LE32(len)  ||  <bytes>
        //    Program =  0x01  ||  LE32(len)  ||  <bytes>
        //     Value  =  0x02  ||  <32 bytes> ||  <32 bytes>
        let (mut contract, serialized_contract) = reader.slice(|r| {
            let anchor = Anchor(r.read_u8x32()?);
            let predicate = Predicate::Opaque(r.read_point()?);
            let k = r.read_size()?;

            // sanity check: avoid allocating unreasonably more memory
            // just because an untrusted length prefix says so.
            if k > r.len() {
                return Err(VMError::FormatError);
            }
            let mut payload: Vec<PortableItem> = Vec::with_capacity(k);
            for _ in 0..k {
                payload.push(PortableItem::decode(r)?);
            }
            Ok(Contract {
                id: ContractID::default(), // will be updated below
                anchor,
                predicate,
                payload,
            })
        })?;
        contract.id = ContractID::from_serialized_contract(serialized_contract);
        Ok(contract)
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
        t.commit_bytes(b"old", &self.0);
        t.challenge_bytes(b"new", &mut self.0);
        self
    }
}

impl ContractID {
    /// Provides a view into the contract ID's bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    fn from_serialized_contract(bytes: &[u8]) -> Self {
        let mut t = Transcript::new(b"ZkVM.contractid");
        t.commit_bytes(b"contract", bytes);
        let mut id = [0u8; 32];
        t.challenge_bytes(b"id", &mut id);
        Self(id)
    }

    /// Re-wraps contract ID bytes into Anchor
    pub(crate) fn to_anchor(self) -> Anchor {
        Anchor(self.0)
    }
}

impl Encodable for PortableItem {
    fn encode(&self, buf: &mut Vec<u8>) {
        match self {
            // Data = 0x00 || LE32(len) || <bytes>
            PortableItem::Data(d) => {
                encoding::write_u8(DATA_TYPE, buf);
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
            PortableItem::Data(d) => 1 + 4 + d.serialized_length(),
            PortableItem::Program(p) => 1 + 4 + p.serialized_length(),
            PortableItem::Value(_) => 1 + 64,
        }
    }
}

impl PortableItem {
    fn decode<'a>(output: &mut SliceReader<'a>) -> Result<Self, VMError> {
        match output.read_u8()? {
            DATA_TYPE => {
                let len = output.read_size()?;
                let bytes = output.read_bytes(len)?;
                Ok(PortableItem::Data(Data::Opaque(bytes.to_vec())))
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
        t.commit_bytes(b"utxo", self.as_bytes());
    }
}
