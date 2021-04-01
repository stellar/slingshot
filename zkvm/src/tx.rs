use bulletproofs::r1cs::R1CSProof;
use bulletproofs::BulletproofGens;
use curve25519_dalek::ristretto::CompressedRistretto;
use merlin::Transcript;
use musig::Signature;
use serde::{Deserialize, Serialize};

use crate::contract::{Contract, ContractID};
use crate::encoding::*;
use crate::errors::VMError;
use crate::fees::FeeRate;
use crate::merkle::{Hash, MerkleItem, MerkleTree};
use crate::predicate::Predicate;
use crate::transcript::TranscriptProtocol;
use crate::verifier::Verifier;

/// Transaction log, a list of all effects of a transaction called [entries](TxEntry).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TxLog(Vec<TxEntry>);

/// Transaction ID is a unique 32-byte identifier of a transaction effects represented by `TxLog`.
#[derive(Copy, Clone, PartialEq, Serialize, Deserialize)]
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
    /// Amount of fee being paid (transaction may have multiple fee entries).
    Fee(u64),
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
#[derive(Clone, Debug, Serialize, Deserialize)]
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
    pub signing_instructions: Vec<(Predicate, ContractID)>,
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

/// Represents a precomputed, but not verified transaction.
pub struct PrecomputedTx {
    /// Transaction header
    pub header: TxHeader,

    /// Transaction ID
    pub id: TxID,

    /// Transaction log: a list of changes to the blockchain state (UTXOs to delete/insert, etc.)
    pub log: TxLog,

    /// Fee rate of the transaction
    pub feerate: FeeRate,

    /// Verifier to continue verification of the transaction
    pub(crate) verifier: Verifier,

    /// Schnorr signature
    pub(crate) signature: Signature,

    /// R1CS proof
    pub(crate) proof: R1CSProof,
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

    /// Fee rate of the transaction
    pub feerate: FeeRate,
}

impl Encodable for TxHeader {
    fn encode(&self, w: &mut impl Writer) -> Result<(), WriteError> {
        w.write_u64(b"version", self.version)?;
        w.write_u64(b"mintime", self.mintime_ms)?;
        w.write_u64(b"maxtime", self.maxtime_ms)?;
        Ok(())
    }
}
impl ExactSizeEncodable for TxHeader {
    fn encoded_size(&self) -> usize {
        8 * 3
    }
}

impl Decodable for TxHeader {
    fn decode(r: &mut impl Reader) -> Result<Self, ReadError> {
        Ok(TxHeader {
            version: r.read_u64()?,
            mintime_ms: r.read_u64()?,
            maxtime_ms: r.read_u64()?,
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
    fn encode(&self, w: &mut impl Writer) -> Result<(), WriteError> {
        self.header.encode(w)?;
        w.write_size(b"program_len", self.program.len())?;
        w.write(b"program", &self.program)?;
        w.write(b"signature", &self.signature.to_bytes())?;
        let proof_bytes = self.proof.to_bytes();
        w.write_size(b"r1cs_proof_len", proof_bytes.len())?;
        w.write(b"r1cs_proof", &proof_bytes)?;
        Ok(())
    }
}

impl ExactSizeEncodable for Tx {
    fn encoded_size(&self) -> usize {
        // header is 8 bytes * 3 fields = 24 bytes
        // program length is 4 bytes
        // program is self.program.len() bytes
        // signature is 64 bytes
        // proof is 14*32 + the ipp bytes
        self.header.encoded_size() + 4 + self.program.len() + 64 + 4 + self.proof.serialized_size()
    }
}

impl Decodable for Tx {
    fn decode(r: &mut impl Reader) -> Result<Self, ReadError> {
        let header = TxHeader::decode(r)?;
        let prog_len = r.read_size()?;
        let program = r.read_bytes(prog_len)?;

        let signature =
            Signature::from_bytes(r.read_u8x64()?).map_err(|_| ReadError::InvalidFormat)?;
        let proof_len = r.read_size()?;
        let proof_bytes = r.read_bytes(proof_len)?;
        let proof = R1CSProof::from_bytes(&proof_bytes).map_err(|_| ReadError::InvalidFormat)?;
        Ok(Tx {
            header,
            program,
            signature,
            proof,
        })
    }
}

impl Tx {
    /// Computes the TxID and TxLog without verifying the transaction.
    pub fn precompute(&self) -> Result<PrecomputedTx, VMError> {
        Verifier::precompute(self)
    }

    /// Performs stateless verification of the transaction:
    /// logic, signatures and ZK R1CS proof.
    pub fn verify(&self, bp_gens: &BulletproofGens) -> Result<VerifiedTx, VMError> {
        self.precompute()?.verify(bp_gens)
    }

    /// Serializes the tx into a byte array.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.encode_to_vec()
    }

    /// Deserializes the tx from a byte slice.
    ///
    /// Returns an error if the byte slice cannot be parsed into a `Tx`.
    pub fn from_bytes(mut slice: &[u8]) -> Result<Tx, VMError> {
        slice
            .read_all(|r| Self::decode(r))
            .map_err(|_| VMError::InvalidFormat)
    }
}

impl PrecomputedTx {
    /// Completes verification of the transaction,
    /// performing expensive checks of the R1CS proof, Schnorr signatures
    /// and other Ristretto255 operations.
    pub fn verify(self, bp_gens: &BulletproofGens) -> Result<VerifiedTx, VMError> {
        Verifier::verify_tx(self, bp_gens)
    }

    /// Verifies a batch of transactions, typically coming from a Block.
    pub fn verify_batch(
        txs: impl IntoIterator<Item = Self>,
        bp_gens: &BulletproofGens,
    ) -> Result<Vec<VerifiedTx>, VMError> {
        // TODO: implement and adopt a batch verification API for R1CS proofs.

        txs.into_iter().map(|tx| tx.verify(bp_gens)).collect()
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

impl TxLog {
    /// Total amount of fees paid in the transaction
    pub fn fee(&self) -> u64 {
        self.0
            .iter()
            .map(|e| if let TxEntry::Fee(f) = e { *f } else { 0 })
            .sum()
    }

    /// Adds an entry to the txlog.
    pub fn push(&mut self, item: TxEntry) {
        self.0.push(item);
    }

    /// Iterator over the input entries
    pub fn inputs(&self) -> impl Iterator<Item = &ContractID> {
        self.0.iter().filter_map(|entry| match entry {
            TxEntry::Input(contract_id) => Some(contract_id),
            _ => None,
        })
    }

    /// Iterator over the output entries
    pub fn outputs(&self) -> impl Iterator<Item = &Contract> {
        self.0.iter().filter_map(|entry| match entry {
            TxEntry::Output(contract) => Some(contract),
            _ => None,
        })
    }

    /// Iterator over all data entries
    pub fn data_entries<'a>(&'a self) -> impl Iterator<Item = &'a [u8]> {
        self.0.iter().filter_map(|entry| match entry {
            TxEntry::Data(buf) => Some(&buf[..]),
            _ => None,
        })
    }
}

impl From<Vec<TxEntry>> for TxLog {
    fn from(v: Vec<TxEntry>) -> TxLog {
        TxLog(v)
    }
}

impl Into<Vec<TxEntry>> for TxLog {
    fn into(self) -> Vec<TxEntry> {
        self.0
    }
}

impl core::ops::Deref for TxLog {
    type Target = [TxEntry];
    fn deref(&self) -> &Self::Target {
        &self.0
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
            TxEntry::Fee(fee) => {
                t.append_u64(b"fee", *fee);
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
