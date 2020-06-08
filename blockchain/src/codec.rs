use crate::shortid::ShortIDVec;
use crate::{
    Block, BlockHeader, BlockID, BlockTx, GetBlock, GetInventory, GetMempoolTxs, Inventory,
    MempoolTxs, Message,
};
use readerwriter::{Decodable, Encodable, ReadError, Reader, WriteError, Writer};
use std::convert::TryFrom;
use zkvm::{Hash, Signature};

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

impl Encodable for Inventory {
    fn encode(&self, w: &mut impl Writer) -> Result<(), WriteError> {
        w.write_u64(b"version", self.version)?;
        self.tip.encode(w)?;
        w.write_signature(&self.tip_signature)?;
        w.write_u64(b"shortid_nonce", self.shortid_nonce)?;
        w.write_shortid_vec(b"shortid_list", &self.shortid_list)?;
        Ok(())
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

fn read_block_txs(src: &mut impl Reader) -> Result<Vec<BlockTx>, ReadError> {
    let n = src.read_u32()? as usize;
    src.read_vec(n, BlockTx::decode)
}

fn write_block_txs(block_txs: &[BlockTx], dst: &mut impl Writer) -> Result<(), WriteError> {
    dst.write_u32(b"n", block_txs.len() as u32)?;
    block_txs.iter().map(|btx| btx.encode(dst)).collect()
}

trait ReaderExt: Reader + Sized {
    fn read_u8_vec(&mut self) -> Result<Vec<u8>, ReadError> {
        let len = self.read_u32()? as usize;
        self.read_bytes(len)
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

impl Message {
    fn encode_block(b: &Block, dst: &mut impl Writer) -> Result<(), WriteError> {
        BlockHeader::encode(&b.header, dst)?;
        dst.write_signature(&b.signature)?;
        write_block_txs(&b.txs, dst)?;
        Ok(())
    }
    fn decode_block(src: &mut impl Reader) -> Result<Self, ReadError> {
        let header = BlockHeader::decode(src)?;
        let signature = src.read_signature()?;
        let txs = read_block_txs(src)?;
        Ok(Message::Block(Block {
            header,
            signature,
            txs,
        }))
    }

    fn encode_get_block(g: &GetBlock, dst: &mut impl Writer) -> Result<(), WriteError> {
        dst.write_u64(b"block_height", g.height)
    }
    fn decode_get_block(src: &mut impl Reader) -> Result<Self, ReadError> {
        let height = src.read_u64()?;
        Ok(Message::GetBlock(GetBlock { height }))
    }

    fn encode_inventory(inv: &Inventory, dst: &mut impl Writer) -> Result<(), WriteError> {
        Inventory::encode(inv, dst)
    }
    fn decode_inventory(src: &mut impl Reader) -> Result<Self, ReadError> {
        Ok(Message::Inventory(Inventory::decode(src)?))
    }

    fn encode_get_inventory(g: &GetInventory, dst: &mut impl Writer) -> Result<(), WriteError> {
        dst.write_u64(b"version", g.version)?;
        dst.write_u64(b"shortid_nonce", g.shortid_nonce)?;
        Ok(())
    }
    fn decode_get_inventory(src: &mut impl Reader) -> Result<Self, ReadError> {
        let version = src.read_u64()?;
        let shortid_nonce = src.read_u64()?;
        Ok(Message::GetInventory(GetInventory {
            version,
            shortid_nonce,
        }))
    }

    fn encode_mempool_txs(mempool: &MempoolTxs, dst: &mut impl Writer) -> Result<(), WriteError> {
        dst.write_blockid(b"tip", &mempool.tip)?;
        write_block_txs(&mempool.txs, dst)?;
        Ok(())
    }
    fn decode_mempool_txs(src: &mut impl Reader) -> Result<Self, ReadError> {
        let tip = src.read_blockid()?;
        let txs = read_block_txs(src)?;
        Ok(Message::MempoolTxs(MempoolTxs { tip, txs }))
    }

    fn encode_get_mempool_txs(g: &GetMempoolTxs, dst: &mut impl Writer) -> Result<(), WriteError> {
        dst.write_u64(b"shortid_nonce", g.shortid_nonce)?;
        dst.write_shortid_vec(b"shortid_list", &g.shortid_list)?;
        Ok(())
    }
    fn decode_get_mempool_txs(src: &mut impl Reader) -> Result<Self, ReadError> {
        let shortid_nonce = src.read_u64()?;
        let shortid_list = src.read_shortid_vec()?;
        Ok(Message::GetMempoolTxs(GetMempoolTxs {
            shortid_nonce,
            shortid_list,
        }))
    }
}

impl Decodable for Message {
    fn decode(src: &mut impl Reader) -> Result<Self, ReadError>
    where
        Self: Sized,
    {
        let message_type_byte = src.read_u8()?;
        let message_type = MessageType::try_from(message_type_byte)?;
        match message_type {
            MessageType::Block => Message::decode_block(src),
            MessageType::GetBlock => Message::decode_get_block(src),
            MessageType::Inventory => Message::decode_inventory(src),
            MessageType::GetInventory => Message::decode_get_inventory(src),
            MessageType::MempoolTxs => Message::decode_mempool_txs(src),
            MessageType::GetMempoolTxs => Message::decode_get_mempool_txs(src),
        }
    }
}

impl Encodable for Message {
    fn encode(&self, dst: &mut impl Writer) -> Result<(), WriteError> {
        macro_rules! typ {
            ($msg_type:expr) => {
                dst.write_u8(b"message_type", $msg_type as u8)?;
            };
        }
        match self {
            Message::Block(b) => {
                typ!(MessageType::Block);
                Self::encode_block(b, dst)
            }
            Message::GetBlock(g) => {
                typ!(MessageType::GetBlock);
                Self::encode_get_block(g, dst)
            }
            Message::Inventory(inv) => {
                typ!(MessageType::Inventory);
                Self::encode_inventory(inv, dst)
            }
            Message::GetInventory(g) => {
                typ!(MessageType::GetInventory);
                Self::encode_get_inventory(g, dst)
            }
            Message::MempoolTxs(mempool) => {
                typ!(MessageType::MempoolTxs);
                Self::encode_mempool_txs(mempool, dst)
            }
            Message::GetMempoolTxs(g) => {
                typ!(MessageType::GetMempoolTxs);
                Self::encode_get_mempool_txs(g, dst)
            }
        }
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
