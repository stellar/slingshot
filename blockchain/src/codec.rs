use crate::{Block, GetBlock, GetInventory, GetMempoolTxs, MempoolTxs, Message};
use p2p::{
    reexport::{Buf, BufMut, Bytes, BytesMut},
    CustomMessage,
};
use std::convert::TryFrom;

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
    type Error = String;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(MessageType::Block),
            1 => Ok(MessageType::GetBlock),
            2 => Ok(MessageType::Inventory),
            3 => Ok(MessageType::GetInventory),
            4 => Ok(MessageType::MempoolTxs),
            5 => Ok(MessageType::GetMempoolTxs),
            _ => Err(format!("unknown message type: {}", value)),
        }
    }
}

impl CustomMessage for Message {
    type Error = String;

    fn decode(src: &mut Bytes) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        let message_type_byte = get_u8(src, "message body")?;
        let message_type = MessageType::try_from(message_type_byte)?;
        match message_type {
            MessageType::Block => {
                let header = block_header::decode(src)?;
                let signature = signature::decode(src)?;
                let txs = txs::decode(src)?;
                Ok(Message::Block(Block {
                    header,
                    signature,
                    txs,
                }))
            }
            MessageType::GetBlock => {
                let height = get_u64_le(src, "height of block")?;
                Ok(Message::GetBlock(GetBlock { height }))
            }
            MessageType::Inventory => {
                let inventory = inventory::decode(src)?;
                Ok(Message::Inventory(inventory))
            }
            MessageType::GetInventory => {
                let version = get_u64_le(src, "inventory version")?;
                let shortid_nonce = get_u64_le(src, "shortid_nonce")?;
                Ok(Message::GetInventory(GetInventory {
                    version,
                    shortid_nonce,
                }))
            }
            MessageType::MempoolTxs => {
                let tip = block_id::decode(src)?;
                let txs = txs::decode(src)?;
                Ok(Message::MempoolTxs(MempoolTxs { tip, txs }))
            }
            MessageType::GetMempoolTxs => {
                let shortid_nonce = get_u64_le(src, "shortid_nonce")?;
                let shortid_list = shortid_list::decode(src)?;
                Ok(Message::GetMempoolTxs(GetMempoolTxs {
                    shortid_nonce,
                    shortid_list,
                }))
            }
        }
    }

    fn encode(self, dst: &mut BytesMut) -> Result<(), Self::Error> {
        match self {
            Message::Block(b) => {
                dst.put_u8(MessageType::Block as u8); // Message type
                block_header::encode(&b.header, dst);
                signature::encode(&b.signature, dst);
                txs::encode(b.txs, dst);
            }
            Message::GetBlock(g) => {
                dst.put_u8(MessageType::GetBlock as u8);
                dst.put_u64_le(g.height);
            }
            Message::Inventory(inv) => {
                dst.put_u8(MessageType::Inventory as u8);
                inventory::encode(inv, dst);
            }
            Message::GetInventory(g) => {
                dst.put_u8(MessageType::GetInventory as u8);
                dst.put_u64_le(g.version);
                dst.put_u64_le(g.shortid_nonce);
            }
            Message::MempoolTxs(mempool) => {
                block_id::encode(&mempool.tip, dst);
                txs::encode(mempool.txs, dst);
            }
            Message::GetMempoolTxs(g) => {
                dst.put_u64_le(g.shortid_nonce);
                shortid_list::encode(&g.shortid_list, dst);
            }
        }
        Ok(())
    }
}

mod block_header {
    use crate::codec::{block_id, check_length, decode_u8_vec, encode_u8_slice};
    use crate::BlockHeader;
    use p2p::reexport::{Buf, BufMut, Bytes, BytesMut};
    use std::convert::TryInto;
    use zkvm::Hash;

    pub fn encode(header: &BlockHeader, dst: &mut BytesMut) {
        dst.put_u64_le(header.version);
        dst.put_u64_le(header.height);
        dst.put(&header.prev.0[..]);
        dst.put_u64_le(header.timestamp_ms);
        dst.put(header.txroot.0.as_ref());
        dst.put(header.utxoroot.0.as_ref());
        encode_u8_slice(header.ext.as_slice(), dst);
    }

    const BLOCK_HEADER_SIZE: usize = 8 + 8 + 32 + 8 + 32 + 32;
    pub fn decode(src: &mut Bytes) -> Result<BlockHeader, String> {
        check_length(src, BLOCK_HEADER_SIZE, "block header")?;
        let version = src.get_u64_le();
        let height = src.get_u64_le();
        let prev = block_id::decode(src)?;
        let timestamp_ms = src.get_u64_le();
        let txroot = src.split_to(32);
        let utxoroot = src.split_to(32);
        let ext = decode_u8_vec(src, "ext")?;
        Ok(BlockHeader {
            version,
            height,
            prev,
            timestamp_ms,
            txroot: Hash(txroot.as_ref().try_into().unwrap()),
            utxoroot: Hash(utxoroot.as_ref().try_into().unwrap()),
            ext,
        })
    }
}

mod signature {
    use crate::codec::check_length;
    use curve25519_dalek::ristretto::CompressedRistretto;
    use curve25519_dalek::scalar::Scalar;
    use p2p::reexport::{BufMut, Bytes, BytesMut};
    use std::convert::TryInto;
    use zkvm::Signature;

    pub fn encode(signature: &Signature, dst: &mut BytesMut) {
        dst.put(signature.s.as_bytes().as_ref());
        dst.put(signature.R.as_bytes().as_ref());
    }

    const SIGNATURE_SIZE: usize = 32 + 32;
    pub fn decode(src: &mut Bytes) -> Result<Signature, String> {
        check_length(src, SIGNATURE_SIZE, "signature")?;
        let s = src.split_to(32).as_ref().try_into().unwrap();
        let r = src.split_to(32).as_ref().try_into().unwrap();
        Ok(Signature {
            s: Scalar::from_bits(s),
            R: CompressedRistretto(r),
        })
    }
}

mod shortid_list {
    use super::{decode_u8_vec, encode_u8_slice, Bytes, BytesMut};
    use crate::shortid::ShortIDVec;

    pub fn decode(src: &mut Bytes) -> Result<ShortIDVec, String> {
        let shortid_list = decode_u8_vec(src, "shortid_list")?;
        Ok(ShortIDVec(shortid_list))
    }

    pub fn encode(vec: &ShortIDVec, dst: &mut BytesMut) {
        encode_u8_slice(vec.0.as_slice(), dst);
    }
}

mod block_id {
    use super::{check_length, encode_u8_slice, Bytes, BytesMut};
    use crate::BlockID;
    use std::convert::TryInto;

    pub fn decode(src: &mut Bytes) -> Result<BlockID, String> {
        check_length(src, 32, "block id")?;
        let bytes = src.split_to(32);
        Ok(BlockID(bytes.as_ref().try_into().unwrap()))
    }

    pub fn encode(block_id: &BlockID, dst: &mut BytesMut) {
        encode_u8_slice(block_id.0.as_ref(), dst);
    }
}

mod txs {
    use crate::codec::{
        check_length, decode_u8_vec, decode_vector, encode_u8_slice, encode_vector, get_array,
        get_u64_le, get_u8, signature,
    };
    use crate::{utreexo, BlockTx};
    use p2p::reexport::{Buf, BufMut, Bytes, BytesMut};
    use std::convert::TryInto;
    use zkvm::bulletproofs::r1cs::R1CSProof;
    use zkvm::{Hash, Tx, TxHeader};

    pub fn encode(txs: Vec<BlockTx>, dst: &mut BytesMut) {
        fn encode_block_tx(block_tx: BlockTx, dst: &mut BytesMut) {
            dst.put_u64_le(block_tx.tx.header.version);
            dst.put_u64_le(block_tx.tx.header.mintime_ms);
            dst.put_u64_le(block_tx.tx.header.maxtime_ms);
            encode_u8_slice(block_tx.tx.program.as_slice(), dst);
            signature::encode(&block_tx.tx.signature, dst);
            encode_u8_slice(block_tx.tx.proof.to_bytes().as_slice(), dst);
            fn encode_proof(proof: utreexo::Proof, dst: &mut BytesMut) {
                match proof {
                    utreexo::Proof::Transient => dst.put_u8(0),
                    utreexo::Proof::Committed(path) => {
                        dst.put_u8(1);
                        dst.put_u64_le(path.position);
                        fn encode_hash(hash: Hash, dst: &mut BytesMut) {
                            dst.put(hash.0.as_ref());
                        }
                        encode_vector(path.neighbors, dst, encode_hash);
                    }
                }
            }
            encode_vector(block_tx.proofs, dst, encode_proof);
        }
        encode_vector(txs, dst, encode_block_tx)
    }

    pub fn decode(src: &mut Bytes) -> Result<Vec<BlockTx>, String> {
        fn decode_block_tx(src: &mut Bytes) -> Result<BlockTx, String> {
            const TX_HEADER_LENGTH: usize = 8 + 8 + 8;
            check_length(src, TX_HEADER_LENGTH, "tx header")?;
            let header = TxHeader {
                version: src.get_u64_le(),
                mintime_ms: src.get_u64_le(),
                maxtime_ms: src.get_u64_le(),
            };
            let program = decode_u8_vec(src, "program")?;
            let signature = signature::decode(src)?;
            let proof_bytes = get_array(src, "r1cs proof")?;
            let proof = R1CSProof::from_bytes(proof_bytes.as_ref())
                .map_err(|_| "an error was occur when parse r1cs proof")?;

            let tx = Tx {
                header,
                program,
                signature,
                proof,
            };

            fn decode_utreexo_proof(src: &mut Bytes) -> Result<utreexo::Proof, String> {
                let proof_type = get_u8(src, "proof")?;
                match proof_type {
                    0 => Ok(utreexo::Proof::Transient),
                    1 => {
                        let position = get_u64_le(src, "path position")?;
                        fn decode_hash(src: &mut Bytes) -> Result<Hash, String> {
                            check_length(src, 32, "utreexo proof hash")?;
                            Ok(Hash(src.split_to(32).as_ref().try_into().unwrap()))
                        }
                        let neighbors = decode_vector(src, "utreexo proof", decode_hash)?;
                        Ok(utreexo::Proof::Committed(zkvm::merkle::Path {
                            position,
                            neighbors,
                        }))
                    }
                    _ => Err(format!("unknown proof type: {}", proof_type)),
                }
            }
            let proofs = decode_vector(src, "utreexo proofs", decode_utreexo_proof)?;
            Ok(BlockTx { tx, proofs })
        }
        decode_vector(src, "block txs", decode_block_tx)
    }
}

mod inventory {
    use crate::codec::{block_header, get_u64_le, shortid_list, signature};
    use crate::Inventory;
    use p2p::reexport::{BufMut, Bytes, BytesMut};

    pub fn encode(inv: Inventory, dst: &mut BytesMut) {
        dst.put_u64_le(inv.version);
        block_header::encode(&inv.tip, dst);
        signature::encode(&inv.tip_signature, dst);
        dst.put_u64_le(inv.shortid_nonce);
        shortid_list::encode(&inv.shortid_list, dst);
    }

    pub fn decode(src: &mut Bytes) -> Result<Inventory, String> {
        let version = get_u64_le(src, "version")?;
        let tip = block_header::decode(src)?;
        let tip_signature = signature::decode(src)?;
        let shortid_nonce = get_u64_le(src, "shortid_nonce")?;
        let shortid_list = shortid_list::decode(src)?;
        Ok(Inventory {
            version,
            tip,
            tip_signature,
            shortid_nonce,
            shortid_list,
        })
    }
}

fn encode_vector<T, F: Fn(T, &mut BytesMut)>(vec: Vec<T>, dst: &mut BytesMut, f: F) {
    let start = dst.len();
    dst.put_u64(0); // We put here length after
    vec.into_iter().for_each(|elem| f(elem, dst));
    let len = (dst.len() - start - 8) as u64;
    dst[start..start + 8].copy_from_slice(&len.to_le_bytes()[..]);
}

fn encode_u8_slice(vec: &[u8], dst: &mut BytesMut) {
    dst.put_u64_le(vec.len() as u64);
    dst.put(vec);
}

fn decode_vector<T, F>(src: &mut Bytes, label: &str, parse: F) -> Result<Vec<T>, String>
where
    F: Fn(&mut Bytes) -> Result<T, String>,
{
    let mut vec_bytes = get_array(src, label)?;
    let mut vec = vec![];
    while !vec_bytes.is_empty() {
        vec.push(parse(&mut vec_bytes)?);
    }
    Ok(vec)
}

fn decode_u8_vec(src: &mut Bytes, label: &str) -> Result<Vec<u8>, String> {
    let bytes = get_array(src, label)?;
    Ok(bytes.to_vec())
}

fn get_u8(src: &mut Bytes, label: &str) -> Result<u8, String> {
    check_length(&src, 1, label)?;
    Ok(src.get_u8())
}

fn get_array(src: &mut Bytes, label: &str) -> Result<Bytes, String> {
    let len = get_u64_le(src, label)? as usize;
    check_length(src, len, label)?;
    Ok(src.split_to(len))
}

fn get_u64_le(src: &mut Bytes, label: &str) -> Result<u64, String> {
    check_length(&src, 8, label)?;
    Ok(src.get_u64_le())
}

fn check_length<'a, T: Into<&'a str>>(buf: &Bytes, len: usize, label: T) -> Result<(), String> {
    if buf.len() < len {
        Err(format!(
            "Expected {} bytes for {}, but found {}",
            len,
            label.into(),
            buf.len()
        ))
    } else {
        Ok(())
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
        let mut bytes = BytesMut::new();
        message.clone().encode(&mut bytes).unwrap();
        let mut bytes = bytes.freeze();
        let res = Message::decode(&mut bytes).unwrap();
        assert!(bytes.is_empty());

        let left = format!("{:?}", message);
        let right = format!("{:?}", res);
        assert_eq!(left, right);
    }

    #[test]
    fn message_get_block() {
        let message = Message::GetBlock(GetBlock { height: 30 });
        let mut bytes = BytesMut::new();
        message.clone().encode(&mut bytes).unwrap();
        let mut bytes = bytes.freeze();
        let res = Message::decode(&mut bytes).unwrap();
        assert!(bytes.is_empty());

        let left = format!("{:?}", message);
        let right = format!("{:?}", res);
        assert_eq!(left, right);
    }
}
