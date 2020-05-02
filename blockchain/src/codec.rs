use crate::shortid::ShortIDVec;
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

fn read<T>(data: Result<T, ReadError>, label: &'static str) -> Result<T, ReadError> {
    data.map_err(|err| {
        ReadError::Custom(
            match err {
                ReadError::InvalidFormat => format!("invalid format of {}", label),
                r => r.to_string(),
            }
            .into(),
        )
    })
}

trait ReaderExt: Reader + Sized {
    fn read_u8_vec(&mut self) -> Result<Vec<u8>, ReadError> {
        let len = self.read_u32()? as usize;
        self.read_vec(len)
    }

    fn read_signature(&mut self) -> Result<Signature, ReadError> {
        let s = self.read_u8x32()?;
        let r = self.read_u8x32()?;
        Ok(Signature {
            s: Scalar::from_bits(s),
            R: CompressedRistretto(r),
        })
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

    fn read_block_header(&mut self) -> Result<BlockHeader, ReadError> {
        Ok(BlockHeader {
            version: self.read_u64()?,
            height: self.read_u64()?,
            prev: self.read_blockid()?,
            timestamp_ms: self.read_u64()?,
            txroot: self.read_hash()?,
            utxoroot: self.read_hash()?,
            ext: self.read_u8_vec()?,
        })
    }

    fn read_inventory(&mut self) -> Result<Inventory, ReadError> {
        Ok(Inventory {
            version: self.read_u64()?,
            tip: self.read_block_header()?,
            tip_signature: self.read_signature()?,
            shortid_nonce: self.read_u64()?,
            shortid_list: self.read_shortid_vec()?,
        })
    }

    fn read_tx(&mut self) -> Result<Tx, ReadError> {
        let tx_size = self.read_u32()? as usize;
        let vec = self.read_vec(tx_size)?;
        Tx::from_bytes(&vec).map_err(|_| ReadError::InvalidFormat)
    }

    fn read_txs(&mut self) -> Result<Vec<BlockTx>, ReadError> {
        let len = self.read_u32()? as usize;
        const BLOCK_TX_MIN_LENGTH: usize = 8 + 8 + 8 + 8 + 32 + 32 + 1 + 11 * 32 + 8;
        self.read_vec_with(len, BLOCK_TX_MIN_LENGTH, |src| {
            let tx = src.read_tx()?;
            let len = src.read_u32()? as usize;
            let proofs = src.read_vec_with(len, 1, |src| match src.read_u8()? {
                0 => Ok(Proof::Transient),
                1 => merkle::Path::decode(src)
                    .map(Proof::Committed)
                    .map_err(|_| ReadError::InvalidFormat),
                _ => Err(ReadError::InvalidFormat),
            })?;
            Ok(BlockTx { tx, proofs })
        })
    }
}

trait WriterExt: Writer + Sized {
    fn write_u8_vec(&mut self, label: &'static [u8], vec: &[u8]) -> Result<(), WriteError> {
        self.write_u32(b"vec length", vec.len() as u32)?;
        self.write(label, vec)?;
        Ok(())
    }

    fn write_signature(&mut self, sig: &Signature) -> Result<(), WriteError> {
        self.write(b"scalar", sig.s.as_bytes())?;
        self.write(b"key", sig.R.as_bytes())?;
        Ok(())
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

    fn write_block_header(&mut self, block_header: &BlockHeader) -> Result<(), WriteError> {
        self.write_u64(b"version", block_header.version)?;
        self.write_u64(b"height", block_header.height)?;
        self.write_blockid(b"prev", &block_header.prev)?;
        self.write_u64(b"timestamp_ms", block_header.timestamp_ms)?;
        self.write_hash(b"txroot", &block_header.txroot)?;
        self.write_hash(b"utxoroot", &block_header.utxoroot)?;
        self.write_u8_vec(b"ext", &block_header.ext)?;
        Ok(())
    }

    fn write_inventory(&mut self, inv: &Inventory) -> Result<(), WriteError> {
        self.write_u64(b"version", inv.version)?;
        self.write_block_header(&inv.tip)?;
        self.write_signature(&inv.tip_signature)?;
        self.write_u64(b"shortid_nonce", inv.shortid_nonce)?;
        self.write_shortid_vec(b"shortid_list", &inv.shortid_list)?;
        Ok(())
    }

    fn write_txs(&mut self, txs: &[BlockTx]) -> Result<(), WriteError> {
        self.write_u32(b"txs length", txs.len() as u32)?;
        txs.iter()
            .map(|block| {
                self.write_u32(b"tx length", block.tx.encoded_length() as u32)?;
                block.tx.encode(self)?;
                self.write_u32(b"n", block.proofs.len() as u32)?;
                for proof in block.proofs.iter() {
                    match proof {
                        Proof::Transient => self.write_u8(b"type", 0)?,
                        Proof::Committed(path) => {
                            self.write_u8(b"type", 1)?;
                            path.encode(self)?;
                        }
                    }
                }
                Ok(())
            })
            .collect()
    }
}

impl<R: Reader> ReaderExt for R {}
impl<W: Writer> WriterExt for W {}

impl Decodable for Message {
    fn decode(src: &mut impl Reader) -> Result<Self, ReadError>
    where
        Self: Sized,
    {
        let message_type_byte = read(src.read_u8(), "message body")?;
        let message_type = MessageType::try_from(message_type_byte)?;
        match message_type {
            MessageType::Block => {
                let header = read(src.read_block_header(), "block header")?;
                let signature = read(src.read_signature(), "signature")?;
                let txs = read(src.read_txs(), "txs")?;
                Ok(Message::Block(Block {
                    header,
                    signature,
                    txs,
                }))
            }
            MessageType::GetBlock => {
                let height = read(src.read_u64(), "height of block")?;
                Ok(Message::GetBlock(GetBlock { height }))
            }
            MessageType::Inventory => {
                let inventory = read(src.read_inventory(), "inventory")?;
                Ok(Message::Inventory(inventory))
            }
            MessageType::GetInventory => {
                let version = read(src.read_u64(), "inventory version")?;
                let shortid_nonce = read(src.read_u64(), "shortid_nonce")?;
                Ok(Message::GetInventory(GetInventory {
                    version,
                    shortid_nonce,
                }))
            }
            MessageType::MempoolTxs => {
                let tip = read(src.read_blockid(), "inventory version")?;
                let txs = read(src.read_txs(), "txs")?;
                Ok(Message::MempoolTxs(MempoolTxs { tip, txs }))
            }
            MessageType::GetMempoolTxs => {
                let shortid_nonce = read(src.read_u64(), "shortid_nonce")?;
                let shortid_list = read(src.read_shortid_vec(), "shortid_list")?;
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
                dst.write_u8(b"message type", MessageType::Block as u8)?;
                dst.write_block_header(&b.header)?;
                dst.write_signature(&b.signature)?;
                dst.write_txs(&b.txs)?;
            }
            Message::GetBlock(g) => {
                dst.write_u8(b"message type", MessageType::GetBlock as u8)?;
                dst.write_u64(b"block height", g.height)?;
            }
            Message::Inventory(inv) => {
                dst.write_u8(b"message type", MessageType::Inventory as u8)?;
                dst.write_inventory(&inv)?;
            }
            Message::GetInventory(g) => {
                dst.write_u8(b"message type", MessageType::GetInventory as u8)?;
                dst.write_u64(b"version", g.version)?;
                dst.write_u64(b"shortid_nonce", g.shortid_nonce)?;
            }
            Message::MempoolTxs(mempool) => {
                dst.write_u8(b"message type", MessageType::MempoolTxs as u8)?;
                dst.write_blockid(b"tip", &mempool.tip)?;
                dst.write_txs(&mempool.txs)?;
            }
            Message::GetMempoolTxs(g) => {
                dst.write_u8(b"message type", MessageType::GetMempoolTxs as u8)?;
                dst.write_u64(b"shortid_nonce", g.shortid_nonce)?;
                dst.write_shortid_vec(b"shortid_list", &g.shortid_list)?;
            }
        }
        Ok(())
    }

    fn encoded_length(&self) -> usize {
        unimplemented!()
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
