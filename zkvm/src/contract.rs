use crate::constraints::{Commitment, Variable};
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

/// Representation of a claimed UTXO for the `input` instruction.
#[derive(Clone, Debug)]
pub struct Input {
    prev_output: Output,
    utxo: UTXO,
    txid: TxID,
}

/// Representation of a Contract inside an Input that can be cloned.
#[derive(Clone, Debug)]
pub(crate) struct Output {
    payload: Vec<FrozenItem>,
    predicate: Predicate,
}

/// Representation of a PortableItem inside an Input that can be cloned.
#[derive(Clone, Debug)]
enum FrozenItem {
    Data(Data),
    Value(FrozenValue),
}

/// Representation of a Value inside an Input that can be cloned.
/// Note: values do not necessarily have open commitments. Some can be reblinded,
/// others can be passed-through to an output without going through `cloak` and the constraint system.
#[derive(Clone, Debug)]
struct FrozenValue {
    qty: Commitment,
    flv: Commitment,
}

impl Input {
    /// Creates a "frozen contract" from payload (which is a vector of (qty, flv)) and pred.
    /// Serializes the contract, and uses the serialized contract and txid to generate a utxo.
    /// Returns an Input with the contract, txid, and utxo.
    pub fn new<I>(payload: I, predicate: Predicate, txid: TxID) -> Self
    where
        I: IntoIterator<Item = (Commitment, Commitment)>,
    {
        let payload: Vec<FrozenItem> = payload
            .into_iter()
            .map(|(qty, flv)| FrozenItem::Value(FrozenValue { qty, flv }))
            .collect();

        let prev_output = Output { payload, predicate };
        let utxo = UTXO::from_output(&prev_output.clone().to_bytes(), &txid);

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
    pub(crate) fn unfreeze<F>(self, com_to_var: F) -> (Contract, UTXO)
    where
        F: FnMut(Commitment) -> Variable,
    {
        (self.prev_output.unfreeze(com_to_var), self.utxo)
    }

    fn decode<'a>(reader: &mut SliceReader<'a>) -> Result<Self, VMError> {
        // Input  =  PreviousTxID || PreviousOutput
        // PreviousTxID  =  <32 bytes>
        let txid = TxID(reader.read_u8x32()?);
        let (prev_output, contract_bytes) = reader.slice(|r| Output::decode(r))?;
        let utxo = UTXO::from_output(contract_bytes, &txid);
        Ok(Input {
            prev_output,
            utxo,
            txid,
        })
    }
}

impl Output {
    /// Converts self to vector of bytes
    pub fn to_bytes(self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.serialized_length());
        self.encode(&mut buf);
        buf
    }

    /// Precise length of a serialized contract
    fn serialized_length(&self) -> usize {
        let mut size = 32 + 4;
        for item in self.payload.iter() {
            match item {
                FrozenItem::Data(d) => size += 1 + 4 + d.serialized_length(),
                FrozenItem::Value(_) => size += 1 + 64,
            }
        }
        size
    }

    /// Serializes the contract to a byte array
    fn encode(&self, buf: &mut Vec<u8>) {
        encoding::write_point(&self.predicate.to_point(), buf);
        encoding::write_u32(self.payload.len() as u32, buf);

        for p in self.payload.iter() {
            match p {
                // Data = 0x00 || LE32(len) || <bytes>
                FrozenItem::Data(d) => {
                    encoding::write_u8(DATA_TYPE, buf);
                    encoding::write_u32(d.serialized_length() as u32, buf);
                    d.encode(buf);
                }
                // Value = 0x01 || <32 bytes> || <32 bytes>
                FrozenItem::Value(v) => {
                    encoding::write_u8(VALUE_TYPE, buf);
                    encoding::write_point(&v.qty.to_point(), buf);
                    encoding::write_point(&v.flv.to_point(), buf);
                }
            }
        }
    }

    /// Converts Output to a Contract and uses provided closure
    /// to allocate R1CS variables for the Values stored in the contract’s payload.
    fn unfreeze<F>(self, mut com_to_var: F) -> Contract
    where
        F: FnMut(Commitment) -> Variable,
    {
        let payload = self
            .payload
            .into_iter()
            .map(|p| match p {
                FrozenItem::Data(d) => PortableItem::Data(d),
                FrozenItem::Value(v) => PortableItem::Value(Value {
                    qty: com_to_var(v.qty),
                    flv: com_to_var(v.flv),
                }),
            })
            .collect::<Vec<_>>();
        let predicate = self.predicate;
        Contract { payload, predicate }
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

        Ok(Output { predicate, payload })
    }
}

impl Contract {
    /// Converts Contract to an Output and uses provided closure
    /// to get the commitments for the variables inside the contract’s Values.
    pub(crate) fn freeze<F>(self, mut var_to_com: F) -> Output
    where
        F: FnMut(Variable) -> Commitment,
    {
        let payload = self
            .payload
            .into_iter()
            .map(|i| match i {
                PortableItem::Data(d) => FrozenItem::Data(d),
                PortableItem::Value(v) => FrozenItem::Value(FrozenValue {
                    flv: var_to_com(v.flv),
                    qty: var_to_com(v.qty),
                }),
            })
            .collect::<Vec<_>>();
        let predicate = self.predicate;

        Output { payload, predicate }
    }
}
