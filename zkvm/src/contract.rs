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
#[derive(Copy,Clone,Debug)]
pub struct Anchor([u8; 32]);

/// A unique identifier for a contract.
#[derive(Copy,Clone,Debug)]
pub struct ContractID([u8; 32]);

/// A ZkVM contract that holds a _payload_ (a list of portable items) protected by a _predicate_.
#[derive(Clone, Debug)]
pub struct Contract {
    /// Anchor string which makes the contract unique.
    pub anchor: Anchor,

    /// List of payload items.
    pub payload: Vec<PortableItem>,

    /// Predicate that guards access to the contract’s payload.
    pub predicate: Predicate,
}

/// Representation of items that can be stored within outputs and contracts.
#[derive(Clone, Debug)]
pub enum PortableItem {
    /// Plain data payload
    Data(Data),

    /// Value payload
    Value(Value),
}

/// Representation of the claimed UTXO
#[derive(Clone, Debug)]
pub struct Input {
    contract: Contract,
    id: ContractID,
}

impl Input {
    /// Creates an Input with a given contract
    pub fn new(contract: Contract) -> Self {
        Self {
            id: contract.id(),
            contract,
        }
    }

    /// Parses an input from a byte array.
    pub fn from_bytes(data: Vec<u8>) -> Result<Self, VMError> {
        let (contract, id) = SliceReader::parse(&data, |r| Contract::decode(r))?;
        Ok(Self{ contract, id })
    }

    /// Precise length of a serialized contract
    pub fn serialized_length(&self) -> usize {
        self.contract.serialized_length()
    }

    /// Serializes the input to a byte array.
    pub fn encode(&self, buf: &mut Vec<u8>) {
        self.contract.encode(buf);
    }

    pub(crate) fn unfreeze(self) -> (Contract, ContractID) {
        (self.contract, self.id)
    }
}

impl Anchor {
    /// Provides a view into the anchor’s bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Computes a nonce anchor from its components
    pub fn nonce(blockid: [u8;32], predicate: &Predicate, maxtime: u64) -> Self {
        let mut t = Transcript::new(b"ZkVM.nonce");
        t.commit_bytes(b"blockid", &blockid);
        t.commit_bytes(b"predicate", predicate.to_point().as_bytes());
        t.commit_u64(b"maxtime", maxtime);
        let mut nonce = [0u8; 32];
        t.challenge_bytes(b"anchor", &mut nonce);
        Self(nonce)
    }

    /// Ratchet the anchor into two new anchors
    pub fn ratchet(&self) -> (Self, Self) {
        let mut t = Transcript::new(b"ZkVM.ratchet-anchor");
        t.commit_bytes(b"anchor", &self.0);
        let mut a1 = [0u8; 32];
        let mut a2 = [0u8; 32];
        t.challenge_bytes(b"anchor1", &mut a1);
        t.challenge_bytes(b"anchor1", &mut a2);
        (Self(a1), Self(a2))
    }
}

impl ContractID {
    /// Provides a view into the contract ID's bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Converts the contract ID to an anchor.
    pub fn to_anchor(self) -> Anchor {
        Anchor(self.0)
    }

    fn from_serialized_contract(bytes: &[u8]) -> Self {
        let mut t = Transcript::new(b"ZkVM.contractid");
        t.commit_bytes(b"contract", bytes);
        let mut id = [0u8; 32];
        t.challenge_bytes(b"id", &mut id);
        Self(id)
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

    /// Serializes the contract to a byte array
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

    /// Converts self to vector of bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.serialized_length());
        self.encode(&mut buf);
        buf
    }

    /// Serializes the contract and computes its ID.
    pub fn id(&self) -> ContractID {
        ContractID::from_serialized_contract(&self.to_bytes())
    }

    /// Precise length of a serialized contract
    fn serialized_length(&self) -> usize {
        let mut size = 32 + 4;
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

    fn decode<'a>(reader: &mut SliceReader<'a>) -> Result<(Self, ContractID), VMError> {
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
                let item = PortableItem::decode(r)?;
                payload.push(item);
            }

            Ok(Contract { anchor, predicate, payload })
        })?;

        let id = ContractID::from_serialized_contract(serialized_contract);

        Ok((contract, id))
    }
}
