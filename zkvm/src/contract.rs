use crate::encoding;
use crate::predicate::Predicate;
use crate::txlog::{TxID, UTXO};
use crate::types::{Commitment, Data, Value};

/// A ZkVM contract that holds a _payload_ (a list of portable items) protected by a _predicate_.
#[derive(Debug)]
pub struct Contract {
    pub(crate) payload: Vec<PortableItem>,
    pub(crate) predicate: Predicate,
}

/// Representation of items that can be stored within outputs and contracts.
#[derive(Debug)]
pub enum PortableItem {
    Data(Data),
    Value(Value),
}

#[derive(Clone, Debug)]
pub enum Input {
    Opaque(Vec<u8>),
    Witness(Box<InputWitness>),
}

#[derive(Clone, Debug)]
pub struct InputWitness {
    contract: FrozenContract,
    utxo: UTXO,
    txid: TxID,
}

/// Representation of a Contract inside an Input that can be cloned.
#[derive(Clone, Debug)]
pub struct FrozenContract {
    pub(crate) payload: Vec<FrozenItem>,
    pub(crate) predicate: Predicate,
}

/// Representation of a PortableItem inside an Input that can be cloned.
#[derive(Clone, Debug)]
pub enum FrozenItem {
    Data(Data),
    Value(FrozenValue),
}

/// Representation of a Value inside an Input that can be cloned.
/// Note: values do not necessarily have open commitments. Some can be reblinded,
/// others can be passed-through to an output without going through `cloak` and the constraint system.
#[derive(Clone, Debug)]
pub struct FrozenValue {
    pub(crate) qty: Commitment,
    pub(crate) flv: Commitment,
}

impl InputWitness {
    pub fn encode(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.txid.0);
        self.contract.encode(buf);
    }
}

impl Contract {
    pub fn min_serialized_length(&self) -> usize {
        let mut size = 32 + 4;
        for item in self.payload.iter() {
            match item {
                PortableItem::Data(d) => size += 1 + 4 + d.min_serialized_length(),
                PortableItem::Value(_) => size += 1 + 64,
            }
        }
        size
    }
}

impl FrozenContract {
    fn encode(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.predicate.point().to_bytes());
        for p in self.payload.iter() {
            match p {
                // Data = 0x00 || LE32(len) || <bytes>
                FrozenItem::Data(d) => {
                    buf.push(0u8);
                    let mut bytes = d.to_bytes();
                    encoding::write_u32(bytes.len() as u32, buf);
                    buf.extend_from_slice(&mut bytes);
                }
                // Value = 0x01 || <32 bytes> || <32 bytes>
                FrozenItem::Value(v) => {
                    buf.push(1u8);
                    buf.extend_from_slice(&v.qty.to_point().to_bytes());
                    buf.extend_from_slice(&v.flv.to_point().to_bytes());
                }
            }
        }
    }
}
