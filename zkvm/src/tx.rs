use bulletproofs::r1cs::R1CSProof;
use bulletproofs::BulletproofGens;
use core::borrow::Borrow;
use curve25519_dalek::ristretto::CompressedRistretto;
use merlin::Transcript;
use musig::{Signature, VerificationKey};
use serde::{Deserialize, Serialize};

use crate::contract::{Contract, ContractID};
use crate::encoding;
use crate::encoding::Encodable;
use crate::encoding::SliceReader;
use crate::errors::VMError;
use crate::merkle::{Hash, MerkleItem, MerkleTree};
use crate::transcript::TranscriptProtocol;
use crate::verifier::Verifier;

/// Transaction log, a list of all effects of a transaction called [entries](TxEntry).
pub type TxLog = Vec<TxEntry>;

/// Transaction ID is a unique 32-byte identifier of a transaction.
#[derive(Copy, Clone, PartialEq, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TxID(pub Hash);

/// Entry in a transaction log. All entries are hashed into a [transaction ID](TxID).
#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum TxEntry {
    /// Transaction [header](self::TxHeader).
    /// This entry is not present in the [transaction log](TxLog), but used only for computing a [TxID](TxID) hash.
    Header(TxHeader),
    /// Asset issuance entry that consists of a _flavor commitment_ and a _quantity commitment_.
    Issue(CompressedRistretto, CompressedRistretto),
    /// Asset retirement entry that consists of a _flavor commitment_ and a _quantity commitment_.
    Retire(CompressedRistretto, CompressedRistretto),
    /// Input entry that signals that a contract was spent. Contains the [ID](crate::contract::ContractID) of a contract.
    Input(ContractID),
    /// Output entry that signals that a contract was created. Contains the [Contract](crate::contract::Contract).
    Output(Contract),
    /// Plain data entry created by [`log`](crate::ops::Instruction::Log) instruction. Contains an arbitrary binary string.
    Data(Vec<u8>),
}

/// Header metadata for the transaction
#[derive(Clone, Copy, Debug, PartialEq, Deserialize, Serialize)]
pub struct TxHeader {
    /// Version of the transaction
    pub version: u64,

    /// Timestamp before which tx is invalid (in milliseconds since the Unix epoch)
    pub mintime_ms: u64,

    /// Timestamp after which tx is invalid (in milliseconds since the Unix epoch)
    pub maxtime_ms: u64,
}

/// Instance of a transaction that is not signed yet.
#[derive(Clone)]
pub struct UnsignedTx {
    /// Header metadata
    pub header: TxHeader,

    /// Program representing the transaction
    pub program: Vec<u8>,

    /// Constraint system proof for all the constraints
    pub proof: R1CSProof,

    /// TxID of the resulting tx
    pub txid: TxID,

    /// Log of tx entries
    pub txlog: TxLog,

    /// List of (key,contractid) pairs for multi-message signature
    /// TBD: change to some key witness type
    pub signing_instructions: Vec<(VerificationKey, ContractID)>,
}

/// Instance of a transaction that contains all necessary data to validate it.
#[derive(Clone, Serialize, Deserialize)]
pub struct Tx {
    /// Header metadata
    pub header: TxHeader,

    /// Program representing the transaction
    pub program: Vec<u8>,

    /// Aggregated signature of the txid
    pub signature: Signature,

    /// Constraint system proof for all the constraints
    pub proof: R1CSProof,
}

/// Represents a verified transaction: a txid and a list of state updates.
#[derive(Clone, Deserialize, Serialize)]
pub struct VerifiedTx {
    /// Transaction header
    pub header: TxHeader,

    /// Transaction ID
    pub id: TxID,

    /// Transaction log: a list of changes to the blockchain state (UTXOs to delete/insert, etc.)
    pub log: TxLog,
}

impl Encodable for TxHeader {
    fn encode(&self, buf: &mut Vec<u8>) {
        encoding::write_u64(self.version, buf);
        encoding::write_u64(self.mintime_ms, buf);
        encoding::write_u64(self.maxtime_ms, buf);
    }
    fn serialized_length(&self) -> usize {
        8 * 3
    }
}
impl TxHeader {
    fn decode<'a>(reader: &mut SliceReader<'a>) -> Result<Self, VMError> {
        Ok(TxHeader {
            version: reader.read_u64()?,
            mintime_ms: reader.read_u64()?,
            maxtime_ms: reader.read_u64()?,
        })
    }
}

impl UnsignedTx {
    /// Attaches the signature to the transaction.
    pub fn sign(self, signature: Signature) -> Tx {
        Tx {
            header: self.header,
            program: self.program,
            proof: self.proof,
            signature,
        }
    }
}

impl Encodable for Tx {
    fn encode(&self, buf: &mut Vec<u8>) {
        self.header.encode(buf);
        encoding::write_size(self.program.len(), buf);
        buf.extend(&self.program);
        buf.extend_from_slice(&self.signature.to_bytes());
        buf.extend_from_slice(&self.proof.to_bytes());
    }

    /// Returns the size in bytes required to serialize the `Tx`.
    fn serialized_length(&self) -> usize {
        // header is 8 bytes * 3 fields = 24 bytes
        // program length is 4 bytes
        // program is self.program.len() bytes
        // signature is 64 bytes
        // proof is 14*32 + the ipp bytes
        self.header.serialized_length() + 4 + self.program.len() + 64 + self.proof.serialized_size()
    }
}
impl Tx {
    fn decode<'a>(r: &mut SliceReader<'a>) -> Result<Tx, VMError> {
        let header = TxHeader::decode(r)?;
        let prog_len = r.read_size()?;
        let program = r.read_bytes(prog_len)?.to_vec();

        let signature = Signature::from_bytes(r.read_u8x64()?).map_err(|_| VMError::FormatError)?;
        let proof =
            R1CSProof::from_bytes(r.read_bytes(r.len())?).map_err(|_| VMError::FormatError)?;
        Ok(Tx {
            header,
            program,
            signature,
            proof,
        })
    }

    /// Computes the TxID and TxLog without verifying the transaction.
    pub fn precompute(&self) -> Result<(TxID, TxLog), VMError> {
        Verifier::precompute(self)
    }

    /// Performs stateless verification of the transaction:
    /// logic, signatures and ZK R1CS proof.
    pub fn verify(&self, bp_gens: &BulletproofGens) -> Result<VerifiedTx, VMError> {
        Verifier::verify_tx(self, bp_gens)
    }

    /// Verifies a batch of transactions, typically coming from a Block.
    pub fn verify_batch<T>(
        txs: impl IntoIterator<Item = T>,
        bp_gens: &BulletproofGens,
    ) -> Result<Vec<VerifiedTx>, VMError>
    where
        T: Borrow<Self>,
    {
        // TODO: implement and adopt a batch verification API for R1CS proofs.

        txs.into_iter()
            .map(|tx| tx.borrow().verify(bp_gens))
            .collect()
    }

    /// Serializes the tx into a byte array.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.encode_to_vec()
    }

    /// Deserializes the tx from a byte slice.
    ///
    /// Returns an error if the byte slice cannot be parsed into a `Tx`.
    pub fn from_bytes(slice: &[u8]) -> Result<Tx, VMError> {
        SliceReader::parse(slice, |r| Self::decode(r))
    }
}

impl TxEntry {
    /// Converts entry to the input and provides its contract ID.
    pub fn as_input(&self) -> Option<ContractID> {
        match self {
            TxEntry::Input(cid) => Some(*cid),
            _ => None,
        }
    }

    /// Converts entry to the output and provides a reference to its contract.
    pub fn as_output(&self) -> Option<&Contract> {
        match self {
            TxEntry::Output(c) => Some(c),
            _ => None,
        }
    }
}

impl MerkleItem for TxID {
    fn commit(&self, t: &mut Transcript) {
        t.append_message(b"txid", &self.0)
    }
}

impl TxID {
    /// Computes TxID from a tx log
    pub fn from_log(list: &[TxEntry]) -> Self {
        TxID(MerkleTree::root(b"ZkVM.txid", list))
    }
}

impl AsRef<[u8]> for TxID {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl core::ops::Deref for TxID {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl core::ops::DerefMut for TxID {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl MerkleItem for TxEntry {
    fn commit(&self, t: &mut Transcript) {
        match self {
            TxEntry::Header(h) => {
                t.append_u64(b"tx.version", h.version);
                t.append_u64(b"tx.mintime", h.mintime_ms);
                t.append_u64(b"tx.maxtime", h.maxtime_ms);
            }
            TxEntry::Issue(q, f) => {
                t.commit_point(b"issue.q", q);
                t.commit_point(b"issue.f", f);
            }
            TxEntry::Retire(q, f) => {
                t.commit_point(b"retire.q", q);
                t.commit_point(b"retire.f", f);
            }
            TxEntry::Input(contract) => {
                t.append_message(b"input", contract.as_bytes());
            }
            TxEntry::Output(contract) => {
                t.append_message(b"output", contract.id().as_bytes());
            }
            TxEntry::Data(data) => {
                t.append_message(b"data", data);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle::{Hasher, Path};

    fn txlog_helper() -> Vec<TxEntry> {
        vec![
            TxEntry::Header(TxHeader {
                mintime_ms: 0,
                maxtime_ms: 0,
                version: 0,
            }),
            TxEntry::Issue(
                CompressedRistretto::from_slice(&[0u8; 32]),
                CompressedRistretto::from_slice(&[1u8; 32]),
            ),
            TxEntry::Data(vec![0u8]),
            TxEntry::Data(vec![1u8]),
            TxEntry::Data(vec![2u8]),
        ]
    }

    #[test]
    fn valid_txid_proof() {
        let hasher = Hasher::new(b"ZkVM.txid");
        let (entry, txid, path) = {
            let entries = txlog_helper();
            let index = 3;
            let path = Path::new(&entries, index, &hasher).unwrap();
            (entries[index].clone(), TxID::from_log(&entries), path)
        };
        assert!(path.verify_root(&txid.0, &entry, &hasher));
    }

    #[test]
    fn invalid_txid_proof() {
        let hasher = Hasher::new(b"ZkVM.txid");
        let (entry, txid, path) = {
            let entries = txlog_helper();
            let index = 3;
            let path = Path::new(&entries, index, &hasher).unwrap();
            (entries[index + 1].clone(), TxID::from_log(&entries), path)
        };
        assert!(path.verify_root(&txid.0, &entry, &hasher) == false);
    }
}
