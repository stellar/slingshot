use crate::encoding;
use crate::encoding::Subslice;
use crate::errors::VMError;
use crate::predicate::Predicate;
use crate::txlog::{TxID, UTXO};
use crate::types::{Commitment, Data, Value};

/// Prefix for the data type in the Output Structure
pub const DATA_TYPE: u8 = 0x00;

/// Prefix for the value type in the Output Structure
pub const VALUE_TYPE: u8 = 0x01;

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
pub struct Input {
    pub(crate) contract: FrozenContract,
    pub(crate) utxo: UTXO,
    pub(crate) txid: TxID,
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

impl Input {
    pub fn from_bytes(data: Vec<u8>) -> Result<Self, VMError> {
        let mut reader = Subslice::new(&data);
        let contract = Self::decode(&mut reader)?;
        // Check that reader bytes have been fully consumed
        if reader.len() != 0 {
            return Err(VMError::FormatError);
        }
        Ok(contract)
    }

    pub fn encode(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.txid.0);
        self.contract.encode(buf);
    }

    fn decode<'a>(reader: &mut Subslice<'a>) -> Result<Self, VMError> {
        // Input  =  PreviousTxID || PreviousOutput
        // PreviousTxID  =  <32 bytes>
        let txid = TxID(reader.read_u8x32()?);
        // Hash the contract into utxo before the subslice
        // is advanced by the contract.decode method
        let utxo = UTXO::from_output(&reader, &txid);
        let contract = FrozenContract::decode(reader)?;
        Ok(Input {
            contract,
            utxo,
            txid,
        })
    }
}

impl FrozenContract {
    pub fn encode(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.predicate.point().to_bytes());
        encoding::write_u32(self.payload.len() as u32, buf);

        for p in self.payload.iter() {
            match p {
                // Data = 0x00 || LE32(len) || <bytes>
                FrozenItem::Data(d) => {
                    buf.push(DATA_TYPE);
                    let mut bytes = d.to_bytes();
                    encoding::write_u32(bytes.len() as u32, buf);
                    buf.extend_from_slice(&mut bytes);
                }
                // Value = 0x01 || <32 bytes> || <32 bytes>
                FrozenItem::Value(v) => {
                    buf.push(VALUE_TYPE);
                    buf.extend_from_slice(&v.qty.to_point().to_bytes());
                    buf.extend_from_slice(&v.flv.to_point().to_bytes());
                }
            }
        }
    }

    fn decode<'a>(output: &mut Subslice<'a>) -> Result<Self, VMError> {
        //    Output  =  Predicate  ||  LE32(k)  ||  Item[0]  || ... ||  Item[k-1]
        // Predicate  =  <32 bytes>
        //      Item  =  enum { Data, Value }
        //      Data  =  0x00  ||  LE32(len)  ||  <bytes>
        //     Value  =  0x01  ||  <32 bytes> ||  <32 bytes>

        let predicate = Predicate::opaque(output.read_point()?);
        let k = output.read_size()?;

        // sanity check: avoid allocating unreasonably more memory
        // just because an untrusted length prefix says so.
        if k > output.len() {
            return Err(VMError::FormatError);
        }

        let mut payload: Vec<FrozenItem> = Vec::with_capacity(k);
        for _ in 0..k {
            let item = match output.read_u8()? {
                DATA_TYPE => {
                    let len = output.read_size()?;
                    let bytes = output.read_bytes(len)?;
                    FrozenItem::Data(Data::Opaque(bytes.to_vec()))
                }
                VALUE_TYPE => {
                    let qty = Commitment::Closed(output.read_point()?);
                    let flv = Commitment::Closed(output.read_point()?);

                    FrozenItem::Value(FrozenValue { qty, flv })
                }
                _ => return Err(VMError::FormatError),
            };
            payload.push(item);
        }

        Ok(FrozenContract { predicate, payload })
    }
}
