use crate::shortid::{ShortIDVec, SHORTID_LEN};
use crate::utreexo::Proof;
use crate::{
    Block, BlockHeader, BlockID, BlockTx, GetBlock, GetInventory, GetMempoolTxs, Inventory,
    MempoolTxs, Message,
};
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use readerwriter::{Decodable, Encodable, ReadError, Reader, WriteError, Writer};
use std::convert::TryFrom;
use zkvm::{merkle, Hash, Signature, Tx};

#[repr(u8)]
enum MessageType {
    Block = 0,
    GetBlock = 1,
    Inventory = 2,
    GetInventory = 3,
    MempoolTxs = 4,
    GetMempoolTxs = 5,
}

impl TryFrom<u8> for MessageType {
    type Error = ReadError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(MessageType::Block),
            1 => Ok(MessageType::GetBlock),
            2 => Ok(MessageType::Inventory),
            3 => Ok(MessageType::GetInventory),
            4 => Ok(MessageType::MempoolTxs),
            5 => Ok(MessageType::GetMempoolTxs),
            _ => Err(ReadError::Custom(
                format!("unknown message type: {}", value).into(),
            )),
        }
    }
}

impl Encodable for BlockHeader {
    fn encode(&self, w: &mut impl Writer) -> Result<(), WriteError> {
        w.write_u64(b"version", self.version)?;
        w.write_u64(b"height", self.height)?;
        w.write_blockid(b"prev", &self.prev)?;
        w.write_u64(b"timestamp_ms", self.timestamp_ms)?;
        w.write_hash(b"txroot", &self.txroot)?;
        w.write_hash(b"utxoroot", &self.utxoroot)?;
        w.write_u8_vec(b"ext", &self.ext)?;
        Ok(())
    }

    fn encoded_length(&self) -> usize {
        8 + 8 + 32 + 8 + 32 + 32 + 4 + self.ext.len()
    }
}

impl Decodable for BlockHeader {
    fn decode(buf: &mut impl Reader) -> Result<Self, ReadError> {
        Ok(BlockHeader {
            version: buf.read_u64()?,
            height: buf.read_u64()?,
            prev: buf.read_blockid()?,
            timestamp_ms: buf.read_u64()?,
            txroot: buf.read_hash()?,
            utxoroot: buf.read_hash()?,
            ext: buf.read_u8_vec()?,
        })
    }
}

impl Encodable for Inventory {
    fn encode(&self, w: &mut impl Writer) -> Result<(), WriteError> {
        w.write_u64(b"version", self.version)?;
        self.tip.encode(w)?;
        w.write_signature(&self.tip_signature)?;
        w.write_u64(b"shortid_nonce", self.shortid_nonce)?;
        w.write_shortid_vec(b"shortid_list", &self.shortid_list)?;
        Ok(())
    }

    fn encoded_length(&self) -> usize {
        8 + self.tip.encoded_length() + 64 + 8 + 4 + (self.shortid_list.len() * SHORTID_LEN)
    }
}

impl Decodable for Inventory {
    fn decode(buf: &mut impl Reader) -> Result<Self, ReadError> {
        Ok(Inventory {
            version: buf.read_u64()?,
            tip: BlockHeader::decode(buf)?,
            tip_signature: buf.read_signature()?,
            shortid_nonce: buf.read_u64()?,
            shortid_list: buf.read_shortid_vec()?,
        })
    }
}

// Tx now implement Encoder, but it's implementation isn't suitable for
// encoding in that case
fn read_tx(buf: &mut impl Reader) -> Result<Tx, ReadError> {
    let tx_size = buf.read_u32()? as usize;
    let vec = buf.read_vec(tx_size)?;
    Tx::from_bytes(&vec).map_err(|_| ReadError::InvalidFormat)
}

fn write_tx(tx: &Tx, dst: &mut impl Writer) -> Result<(), WriteError> {
    dst.write_u32(b"tx_length", tx.encoded_length() as u32)?;
    tx.encode(dst)
}

fn read_block_tx(src: &mut impl Reader) -> Result<BlockTx, ReadError> {
    let tx = read_tx(src)?;
    let len = src.read_u32()? as usize;
    let proofs = src.read_vec_with(len, 1, |src| match src.read_u8()? {
        0 => Ok(Proof::Transient),
        1 => merkle::Path::decode(src)
            .map(Proof::Committed)
            .map_err(|_| ReadError::InvalidFormat),
        _ => Err(ReadError::InvalidFormat),
    })?;
    Ok(BlockTx { tx, proofs })
}

fn write_block_tx(block: &BlockTx, dst: &mut impl Writer) -> Result<(), WriteError> {
    write_tx(&block.tx, dst)?;
    dst.write_u32(b"n", block.proofs.len() as u32)?;
    for proof in block.proofs.iter() {
        match proof {
            Proof::Transient => dst.write_u8(b"type", 0)?,
            Proof::Committed(path) => {
                dst.write_u8(b"type", 1)?;
                path.encode(dst)?;
            }
        }
    }
    Ok(())
}

fn read_block_txs(src: &mut impl Reader) -> Result<Vec<BlockTx>, ReadError> {
    let len = src.read_u32()? as usize;
    const BLOCK_TX_MIN_LENGTH: usize = 8 + 8 + 8 + 8 + 32 + 32 + 1 + 11 * 32 + 8;
    src.read_vec_with(len, BLOCK_TX_MIN_LENGTH, read_block_tx)
}

fn write_block_txs(block_txs: &[BlockTx], dst: &mut impl Writer) -> Result<(), WriteError> {
    dst.write_u32(b"block_txs length", block_txs.len() as u32)?;
    block_txs.iter().map(|e| write_block_tx(e, dst)).collect()
}

trait ReaderExt: Reader + Sized {
    fn read_u8_vec(&mut self) -> Result<Vec<u8>, ReadError> {
        let len = self.read_u32()? as usize;
        self.read_vec(len)
    }

    fn read_signature(&mut self) -> Result<Signature, ReadError> {
        let bytes = self.read_u8x64()?;
        Signature::from_bytes(bytes).map_err(|_| ReadError::InvalidFormat)
    }

    fn read_shortid_vec(&mut self) -> Result<ShortIDVec, ReadError> {
        self.read_u8_vec().map(ShortIDVec)
    }

    fn read_blockid(&mut self) -> Result<BlockID, ReadError> {
        self.read_u8x32().map(BlockID)
    }

    fn read_hash(&mut self) -> Result<Hash, ReadError> {
        self.read_u8x32().map(Hash)
    }
}

trait WriterExt: Writer + Sized {
    fn write_u8_vec(&mut self, label: &'static [u8], vec: &[u8]) -> Result<(), WriteError> {
        self.write_u32(b"len", vec.len() as u32)?;
        self.write(label, vec)?;
        Ok(())
    }

    fn write_signature(&mut self, sig: &Signature) -> Result<(), WriteError> {
        self.write(b"signature", &sig.to_bytes()[..])
    }

    fn write_shortid_vec(
        &mut self,
        label: &'static [u8],
        vec: &ShortIDVec,
    ) -> Result<(), WriteError> {
        self.write_u8_vec(label, vec.0.as_ref())
    }

    fn write_blockid(
        &mut self,
        label: &'static [u8],
        block_id: &BlockID,
    ) -> Result<(), WriteError> {
        self.write(label, block_id.as_ref())
    }

    fn write_hash(&mut self, label: &'static [u8], hash: &Hash) -> Result<(), WriteError> {
        self.write(label, hash.0.as_ref())
    }
}

impl<R: Reader> ReaderExt for R {}
impl<W: Writer> WriterExt for W {}

impl Decodable for Message {
    fn decode(src: &mut impl Reader) -> Result<Self, ReadError>
    where
        Self: Sized,
    {
        let message_type_byte = src.read_u8()?;
        let message_type = MessageType::try_from(message_type_byte)?;
        match message_type {
            MessageType::Block => {
                let header = BlockHeader::decode(src)?;
                let signature = src.read_signature()?;
                let txs = read_block_txs(src)?;
                Ok(Message::Block(Block {
                    header,
                    signature,
                    txs,
                }))
            }
            MessageType::GetBlock => {
                let height = src.read_u64()?;
                Ok(Message::GetBlock(GetBlock { height }))
            }
            MessageType::Inventory => {
                let inventory = Inventory::decode(src)?;
                Ok(Message::Inventory(inventory))
            }
            MessageType::GetInventory => {
                let version = src.read_u64()?;
                let shortid_nonce = src.read_u64()?;
                Ok(Message::GetInventory(GetInventory {
                    version,
                    shortid_nonce,
                }))
            }
            MessageType::MempoolTxs => {
                let tip = src.read_blockid()?;
                let txs = read_block_txs(src)?;
                Ok(Message::MempoolTxs(MempoolTxs { tip, txs }))
            }
            MessageType::GetMempoolTxs => {
                let shortid_nonce = src.read_u64()?;
                let shortid_list = src.read_shortid_vec()?;
                Ok(Message::GetMempoolTxs(GetMempoolTxs {
                    shortid_nonce,
                    shortid_list,
                }))
            }
        }
    }
}

impl Encodable for Message {
    fn encode(&self, dst: &mut impl Writer) -> Result<(), WriteError> {
        match self {
            Message::Block(b) => {
                dst.write_u8(b"message_type", MessageType::Block as u8)?;
                BlockHeader::encode(&b.header, dst)?;
                dst.write_signature(&b.signature)?;
                write_block_txs(&b.txs, dst)?;
            }
            Message::GetBlock(g) => {
                dst.write_u8(b"message_type", MessageType::GetBlock as u8)?;
                dst.write_u64(b"block height", g.height)?;
            }
            Message::Inventory(inv) => {
                dst.write_u8(b"message_type", MessageType::Inventory as u8)?;
                Inventory::encode(&inv, dst)?;
            }
            Message::GetInventory(g) => {
                dst.write_u8(b"message_type", MessageType::GetInventory as u8)?;
                dst.write_u64(b"version", g.version)?;
                dst.write_u64(b"shortid_nonce", g.shortid_nonce)?;
            }
            Message::MempoolTxs(mempool) => {
                dst.write_u8(b"message_type", MessageType::MempoolTxs as u8)?;
                dst.write_blockid(b"tip", &mempool.tip)?;
                write_block_txs(&mempool.txs, dst)?;
            }
            Message::GetMempoolTxs(g) => {
                dst.write_u8(b"message_type", MessageType::GetMempoolTxs as u8)?;
                dst.write_u64(b"shortid_nonce", g.shortid_nonce)?;
                dst.write_shortid_vec(b"shortid_list", &g.shortid_list)?;
            }
        }
        Ok(())
    }

    fn encoded_length(&self) -> usize {
        unimplemented!() // see https://github.com/stellar/slingshot/issues/437
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{utreexo, BlockHeader, BlockID, BlockTx};
    use curve25519_dalek::ristretto::CompressedRistretto;
    use curve25519_dalek::scalar::Scalar;
    use zkvm::bulletproofs::r1cs::R1CSProof;
    use zkvm::{Hash, Signature, Tx, TxHeader};

    #[test]
    fn message_block() {
        let message = Message::Block(Block {
            header: BlockHeader {
                version: 0,
                height: 1,
                prev: BlockID([2; 32]),
                timestamp_ms: 3,
                txroot: Hash([4; 32]),
                utxoroot: Hash([5; 32]),
                ext: vec![6; 79],
            },
            signature: Signature {
                s: Scalar::from_bits([7; 32]),
                R: CompressedRistretto([8; 32]),
            },
            txs: vec![BlockTx {
                tx: Tx {
                    header: TxHeader {
                        version: 9,
                        mintime_ms: 10,
                        maxtime_ms: 11,
                    },
                    program: vec![12; 34],
                    signature: Signature {
                        s: Scalar::from_bits([13; 32]),
                        R: CompressedRistretto([14; 32]),
                    },
                    proof: R1CSProof::from_bytes(&[0; 1 + 15 * 32]).unwrap(),
                },
                proofs: vec![
                    utreexo::Proof::Transient,
                    utreexo::Proof::Committed(zkvm::merkle::Path {
                        position: 15,
                        neighbors: vec![Hash([16; 32]), Hash([17; 32])],
                    }),
                ],
            }],
        });
        let mut bytes = Vec::<u8>::new();
        message.clone().encode(&mut bytes).unwrap();
        let mut bytes_to_decode = bytes.as_slice();
        let res = Message::decode(&mut bytes_to_decode).unwrap();
        assert!(
            bytes_to_decode.is_empty(),
            "len = {}",
            bytes_to_decode.len()
        );

        let left = format!("{:?}", message);
        let right = format!("{:?}", res);
        assert_eq!(left, right);
    }

    #[test]
    fn message_get_block() {
        let message = Message::GetBlock(GetBlock { height: 30 });
        let mut bytes = Vec::<u8>::new();
        message.clone().encode(&mut bytes).unwrap();
        let mut bytes_to_decode = bytes.as_slice();
        let res = Message::decode(&mut bytes_to_decode).unwrap();
        assert!(
            bytes_to_decode.is_empty(),
            "len = {}",
            bytes_to_decode.len()
        );

        let left = format!("{:?}", message);
        let right = format!("{:?}", res);
        assert_eq!(left, right);
    }
}
