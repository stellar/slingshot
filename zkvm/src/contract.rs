use merlin::Transcript;

use crate::constraints::Commitment;
use crate::encoding;
use crate::encoding::SliceReader;
use crate::errors::VMError;
use crate::predicate::Predicate;
use crate::types::{Data, Value};

/// Prefix for the data type in the Output Structure
pub const DATA_TYPE: u8 = 0x00;

/// Prefix for the value type in the Output Structure
pub const VALUE_TYPE: u8 = 0x01;

/// A unique identifier for an anchor
#[derive(Copy, Clone, Debug)]
pub struct Anchor([u8; 32]);

/// A unique identifier for a contract.
#[derive(Copy, Clone, Eq, Hash, Debug, PartialEq)]
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

    /// Value payload
    Value(Value),
}

// /// Representation of the claimed UTXO
// #[derive(Clone, Debug)]
// pub struct Output {
//     contract: Contract,
//     id: ContractID,
// }

// impl Output {
//     /// Creates an Output with a given contract
//     pub fn new(contract: Contract) -> Self {
//         let mut buf = Vec::with_capacity(contract.serialized_length());
//         contract.encode(&mut buf);
//         let id = ContractID::from_serialized_contract(&buf);
//         Self { id, contract }
//     }

//     /// Returns the contract ID
//     pub fn id(&self) -> ContractID {
//         self.id
//     }

//     /// Converts output to a contract and also returns its precomputed ID
//     pub fn into_contract(self) -> (Contract, ContractID) {
//         (self.contract, self.id)
//     }

//     /// Precise length of a serialized output
//     pub fn serialized_length(&self) -> usize {
//         self.contract.serialized_length()
//     }

//     /// Serializes the output to a byte array
//     pub fn encode(&self, buf: &mut Vec<u8>) {
//         self.contract.encode(buf)
//     }

//     /// Parses an output
//     pub fn decode<'a>(output: &mut SliceReader<'a>) -> Result<Self, VMError> {
//         let (contract, id) = Contract::decode(output)?;
//         Ok(Self { contract, id })
//     }
// }

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

impl PortableItem {
    /// Precise length of a serialized payload item
    fn serialized_length(&self) -> usize {
        match self {
            PortableItem::Data(d) => 1 + 4 + d.serialized_length(),
            PortableItem::Value(_) => 1 + 64,
        }
    }

    fn encode(&self, buf: &mut Vec<u8>) {
        match self {
            // Data = 0x00 || LE32(len) || <bytes>
            PortableItem::Data(d) => {
                encoding::write_u8(DATA_TYPE, buf);
                encoding::write_u32(d.serialized_length() as u32, buf);
                d.encode(buf);
            }
            // Value = 0x01 || <32 bytes> || <32 bytes>
            PortableItem::Value(v) => {
                encoding::write_u8(VALUE_TYPE, buf);
                encoding::write_point(&v.qty.to_point(), buf);
                encoding::write_point(&v.flv.to_point(), buf);
            }
        }
    }

    fn decode<'a>(output: &mut SliceReader<'a>) -> Result<Self, VMError> {
        match output.read_u8()? {
            DATA_TYPE => {
                let len = output.read_size()?;
                let bytes = output.read_bytes(len)?;
                Ok(PortableItem::Data(Data::Opaque(bytes.to_vec())))
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

impl Contract {
    /// Creates a contract from a given fields
    pub fn new(predicate: Predicate, payload: Vec<PortableItem>, anchor: Anchor) -> Self {
        Self {
            predicate,
            payload,
            anchor,
        }
        // todo: compute contract id
    }

    /// Returns the contract's ID
    pub fn id(&self) -> ContractID {
        unimplemented!()
    }

    /// Breaks up the contract into individual fields
    pub fn into_tuple(self) -> (ContractID, Predicate, Vec<PortableItem>, Anchor) {
        unimplemented!()
    }

    /// Precise length of a serialized output
    pub fn serialized_length(&self) -> usize {
        let mut size = 32 + 32 + 4;
        for item in self.payload.iter() {
            size += item.serialized_length();
        }
        size
    }

    /// Serializes the contract to a byte array
    pub fn encode(&self, buf: &mut Vec<u8>) {
        encoding::write_bytes(&self.anchor.0, buf);
        encoding::write_point(&self.predicate.to_point(), buf);
        encoding::write_u32(self.payload.len() as u32, buf);
        for item in self.payload.iter() {
            item.encode(buf);
        }
    }

    /// Parses a contract from an output object
    pub fn decode<'a>(reader: &mut SliceReader<'a>) -> Result<Self, VMError> {
        //    Output  =  Anchor  ||  Predicate  ||  LE32(k)  ||  Item[0]  || ... ||  Item[k-1]
        //    Anchor  =  <32 bytes>
        // Predicate  =  <32 bytes>
        //      Item  =  enum { Data, Value }
        //      Data  =  0x00  ||  LE32(len)  ||  <bytes>
        //     Value  =  0x01  ||  <32 bytes> ||  <32 bytes>
        let (contract, serialized_contract) = reader.slice(|r| {
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
                anchor,
                predicate,
                payload,
            })
        })?;

        let id = ContractID::from_serialized_contract(serialized_contract);

        Ok((contract, id))
    }
}
