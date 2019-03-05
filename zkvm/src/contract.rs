use crate::constraints::Commitment;
use crate::encoding;
use crate::encoding::SliceReader;
use crate::errors::VMError;
use crate::predicate::Predicate;
use crate::txlog::{TxID, UTXO};
use crate::types::{Data, Value};

/// Prefix for the data type in the Output Structure
pub const DATA_TYPE: u8 = 0x00;

/// Prefix for the value type in the Output Structure
pub const VALUE_TYPE: u8 = 0x01;

/// A ZkVM contract that holds a _payload_ (a list of portable items) protected by a _predicate_.
#[derive(Clone, Debug)]
pub struct Contract {
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

/// Representation of a claimed UTXO for the `input` instruction.
#[derive(Clone, Debug)]
pub struct Input {
    prev_output: Contract,
    utxo: UTXO,
    txid: TxID,
}

impl Input {
    /// Creates an Input with a given Output and transaction id
    pub fn new(prev_output: Contract, txid: TxID) -> Self {
        let utxo = UTXO::from_output(&prev_output.to_bytes(), &txid);
        Input {
            prev_output,
            utxo,
            txid,
        }
    }

    /// Parses an input from a byte array.
    pub fn from_bytes(data: Vec<u8>) -> Result<Self, VMError> {
        let output = SliceReader::parse(&data, |r| Self::decode(r))?;
        Ok(output)
    }

    /// Precise serialized length in bytes for the Input
    pub fn serialized_length(&self) -> usize {
        32 + self.prev_output.serialized_length()
    }

    /// Serializes the input to a byte array.
    pub fn encode(&self, buf: &mut Vec<u8>) {
        encoding::write_bytes(&self.txid.0, buf);
        self.prev_output.encode(buf);
    }

    /// Unfreezes the input by converting it to the Contract an UTXO ID.
    pub(crate) fn unfreeze(self) -> (Contract, UTXO) {
        (self.prev_output, self.utxo)
    }

    fn decode<'a>(reader: &mut SliceReader<'a>) -> Result<Self, VMError> {
        // Input  =  PreviousTxID || PreviousOutput
        // PreviousTxID  =  <32 bytes>
        let txid = TxID(reader.read_u8x32()?);
        let (prev_output, contract_bytes) = reader.slice(|r| Contract::decode(r))?;
        let utxo = UTXO::from_output(contract_bytes, &txid);
        Ok(Input {
            prev_output,
            utxo,
            txid,
        })
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

    /// Precise length of a serialized contract
    fn serialized_length(&self) -> usize {
        let mut size = 32 + 4;
        for item in self.payload.iter() {
            size += item.serialized_length();
        }
        size
    }

    /// Serializes the contract to a byte array
    fn encode(&self, buf: &mut Vec<u8>) {
        encoding::write_point(&self.predicate.to_point(), buf);
        encoding::write_u32(self.payload.len() as u32, buf);

        for item in self.payload.iter() {
            item.encode(buf);
        }
    }

    fn decode<'a>(output: &mut SliceReader<'a>) -> Result<Self, VMError> {
        //    Output  =  Predicate  ||  LE32(k)  ||  Item[0]  || ... ||  Item[k-1]
        // Predicate  =  <32 bytes>
        //      Item  =  enum { Data, Value }
        //      Data  =  0x00  ||  LE32(len)  ||  <bytes>
        //     Value  =  0x01  ||  <32 bytes> ||  <32 bytes>

        let predicate = Predicate::Opaque(output.read_point()?);
        let k = output.read_size()?;

        // sanity check: avoid allocating unreasonably more memory
        // just because an untrusted length prefix says so.
        if k > output.len() {
            return Err(VMError::FormatError);
        }

        let mut payload: Vec<PortableItem> = Vec::with_capacity(k);
        for _ in 0..k {
            let item = PortableItem::decode(output)?;
            payload.push(item);
        }

        Ok(Contract { predicate, payload })
    }
}
