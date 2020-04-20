use crate::{utreexo, Block, BlockHeader, BlockID, BlockTx, Message};
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use p2p::{
    reexport::{Buf, BufMut, Bytes, BytesMut},
    CustomMessage,
};
use std::convert::{Infallible, TryFrom, TryInto};
use zkvm::bulletproofs::r1cs::{R1CSError, R1CSProof};
use zkvm::{Hash, Signature, Tx, TxHeader};

#[repr(u8)]
enum MessageType {
    Block = 0,
    F = 1,
}

impl TryFrom<u8> for MessageType {
    type Error = String;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(MessageType::Block),
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
                let header = decode_block_header(src)?;
                let signature = decode_signature(src)?;
                let txs = decode_txs(src)?;
                Ok(Message::Block(Block {
                    header,
                    signature,
                    txs,
                }))
            }
            _ => unimplemented!(),
        }
    }

    fn encode(self, dst: &mut BytesMut) -> Result<(), Self::Error> {
        match self {
            Message::Block(b) => {
                dst.put_u8(MessageType::Block as u8); // Message type
                encode_block_header(&b.header, dst);
                encode_signature(&b.signature, dst);
                encode_txs(b.txs, dst);
            }
            _ => unimplemented!(),
        }
        Ok(())
    }
}

fn encode_block_header(header: &BlockHeader, dst: &mut BytesMut) {
    dst.put_u64_le(header.version);
    dst.put_u64_le(header.height);
    dst.put(&header.prev.0[..]);
    dst.put_u64_le(header.timestamp_ms);
    dst.put(header.txroot.0.as_ref());
    dst.put(header.utxoroot.0.as_ref());
    encode_u8_slice(header.ext.as_slice(), dst);
}

fn encode_signature(signature: &Signature, dst: &mut BytesMut) {
    dst.put(signature.s.as_bytes().as_ref());
    dst.put(signature.R.as_bytes().as_ref());
}

fn encode_txs(txs: Vec<BlockTx>, dst: &mut BytesMut) {
    fn encode_block_tx(block_tx: BlockTx, dst: &mut BytesMut) {
        dst.put_u64_le(block_tx.tx.header.version);
        dst.put_u64_le(block_tx.tx.header.mintime_ms);
        dst.put_u64_le(block_tx.tx.header.maxtime_ms);
        encode_u8_slice(block_tx.tx.program.as_slice(), dst);
        encode_signature(&block_tx.tx.signature, dst);
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

const BLOCK_HEADER_SIZE: usize = 8 + 8 + 32 + 8 + 32 + 32;
fn decode_block_header(src: &mut Bytes) -> Result<BlockHeader, String> {
    check_length(src, BLOCK_HEADER_SIZE, "block header")?;
    let version = src.get_u64_le();
    let height = src.get_u64_le();
    let prev = src.split_to(32);
    let timestamp_ms = src.get_u64_le();
    let txroot = src.split_to(32);
    let utxoroot = src.split_to(32);
    let ext = decode_u8_vec(src, "ext")?;
    Ok(BlockHeader {
        version,
        height,
        prev: BlockID(prev.as_ref().try_into().unwrap()),
        timestamp_ms,
        txroot: Hash(txroot.as_ref().try_into().unwrap()),
        utxoroot: Hash(utxoroot.as_ref().try_into().unwrap()),
        ext,
    })
}

const SIGNATURE_SIZE: usize = 32 + 32;
fn decode_signature(src: &mut Bytes) -> Result<Signature, String> {
    check_length(src, SIGNATURE_SIZE, "signature")?;
    let s = src.split_to(32).as_ref().try_into().unwrap();
    let r = src.split_to(32).as_ref().try_into().unwrap();
    Ok(Signature {
        s: Scalar::from_bits(s),
        R: CompressedRistretto(r),
    })
}

fn decode_txs(src: &mut Bytes) -> Result<Vec<BlockTx>, String> {
    fn decode_block_tx(src: &mut Bytes) -> Result<BlockTx, String> {
        const TX_HEADER_LENGTH: usize = 8 + 8 + 8;
        check_length(src, TX_HEADER_LENGTH, "tx header")?;
        let header = TxHeader {
            version: src.get_u64_le(),
            mintime_ms: src.get_u64_le(),
            maxtime_ms: src.get_u64_le(),
        };
        let program = decode_u8_vec(src, "program")?;
        let signature = decode_signature(src)?;
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

fn decode_vector<T, F: Fn(&mut Bytes) -> Result<T, String>>(
    src: &mut Bytes,
    label: &str,
    parse: F,
) -> Result<Vec<T>, String> {
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
    use std::fmt::Debug;

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
}
