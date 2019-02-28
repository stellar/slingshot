use curve25519_dalek::ristretto::CompressedRistretto;
use merlin::Transcript;

use crate::transcript::TranscriptProtocol;
use crate::vm::TxHeader;

/// Transaction log. `TxLog` is a type alias for `Vec<Entry>`.
pub type TxLog = Vec<Entry>;

/// Entry in a transaction log
#[derive(Clone, PartialEq, Debug)]
#[allow(missing_docs)]
pub enum Entry {
    Header(TxHeader),
    Issue(CompressedRistretto, CompressedRistretto),
    Retire(CompressedRistretto, CompressedRistretto),
    Input(UTXO),
    Nonce(CompressedRistretto, u64),
    Output(Vec<u8>),
    Data(Vec<u8>),
    Import, // TBD: parameters
    Export, // TBD: parameters
}

/// Transaction ID is a unique 32-byte identifier of a transaction
#[derive(Copy, Clone, PartialEq, Debug)]
pub struct TxID(pub [u8; 32]);

/// UTXO is a unique 32-byte identifier of a transaction output
#[derive(Copy, Clone, PartialEq, Debug)]
pub struct UTXO(pub [u8; 32]);

impl UTXO {
    /// Computes UTXO identifier from an output and transaction id.
    pub fn from_output(output: &[u8], txid: &TxID) -> Self {
        let mut t = Transcript::new(b"ZkVM.utxo");
        t.commit_bytes(b"txid", &txid.0);
        t.commit_bytes(b"output", &output);
        let mut utxo = UTXO([0u8; 32]);
        t.challenge_bytes(b"id", &mut utxo.0);
        utxo
    }
}

impl TxID {
    /// Computes TxID from a tx log
    pub fn from_log(list: &[Entry]) -> Self {
        let t = Transcript::new(b"ZkVM.txid");
        let mut result = [0u8; 32];
        Self::node(t, list, &mut result);
        Self(result)
    }

    fn node(mut t: Transcript, list: &[Entry], result: &mut [u8; 32]) {
        match list.len() {
            0 => Self::empty(t, result),
            1 => Self::leaf(t, &list[0], result),
            n => {
                let k = n.next_power_of_two() / 2;
                let mut righthash = [0u8; 32];
                Self::node(t.clone(), &list[..k], result);
                Self::node(t.clone(), &list[k..], &mut righthash);
                t.commit_bytes(b"L", result);
                t.commit_bytes(b"R", &righthash);
                t.challenge_bytes(b"merkle.node", result);
            }
        }
    }

    fn empty(mut t: Transcript, result: &mut [u8; 32]) {
        t.challenge_bytes(b"merkle.empty", result);
    }

    fn leaf(mut t: Transcript, entry: &Entry, result: &mut [u8; 32]) {
        entry.commit_to_transcript(&mut t);
        t.challenge_bytes(b"merkle.leaf", result);
    }
}

impl Entry {
    fn commit_to_transcript(&self, t: &mut Transcript) {
        match self {
            Entry::Header(h) => {
                t.commit_u64(b"tx.version", h.version);
                t.commit_u64(b"tx.mintime", h.mintime);
                t.commit_u64(b"tx.maxtime", h.maxtime);
            }
            Entry::Issue(q, f) => {
                t.commit_point(b"issue.q", q);
                t.commit_point(b"issue.f", f);
            }
            Entry::Retire(q, f) => {
                t.commit_point(b"retire.q", q);
                t.commit_point(b"retire.f", f);
            }
            Entry::Input(utxo) => {
                t.commit_bytes(b"input", &utxo.0);
            }
            Entry::Nonce(pred, maxtime) => {
                t.commit_point(b"nonce.p", &pred);
                t.commit_u64(b"nonce.t", *maxtime);
            }
            Entry::Output(outstruct) => {
                t.commit_bytes(b"output", outstruct);
            }
            Entry::Data(data) => {
                t.commit_bytes(b"data", data);
            }
            Entry::Import => {
                // TBD: commit parameters
            }
            Entry::Export => {
                // TBD: commit parameters
            }
        }
    }
}
