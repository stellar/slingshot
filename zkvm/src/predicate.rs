//! Implementation of a predicate tree.
//! Inspired by Taproot by Greg Maxwell and G'root by Anthony Towns.
//! Operations:
//! - disjunction: P = L + f(L,R)*B
//! - program_commitment: P = h(prog)*B2
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;

use crate::encoding;
use crate::encoding::SliceReader;
use crate::errors::VMError;
use crate::merkle::MerkleNeighbor;
use crate::point_ops::PointOp;
use crate::program::Program;
use crate::signature::VerificationKey;
use crate::transcript::TranscriptProtocol;

/// Represents a ZkVM predicate with its optional witness data.
#[derive(Clone, Debug)]
pub enum Predicate {
    /// Verifier's view on the predicate in a compressed form to defer decompression cost.
    Opaque(CompressedRistretto),

    /// Signing key for the predicate-as-a-verification-key.
    /// Prover will provide secret signing key separately when
    /// constructing aggregated signature.
    Key(VerificationKey),

    /// Taproot Merkle tree.
    Tree(PredicateTree),
}

#[derive(Clone, Debug)]
pub struct PredicateTree {
    progs: Vec<Program>,
    key: VerificationKey,
    blinding: [u8; 32],
    // We precompute the disjunction predicate when composing it via `Predicate::or()`,
    // so that we can keep `to_point`/`encode` methods non-failable across all types.
    precomputed_point: CompressedRistretto,
}

#[derive(Clone, Debug, Default)]
pub struct CallProof {
    // Signing key
    // PRTODO: Check if we want new SigningKey struct.
    pub signing_key: VerificationKey,

    // Bit pattern indicating neighbor position
    pub positions: u32,

    // List of left-right neighbors, excluding the root and leaf hash
    pub neighbors: Vec<MerkleNeighbor>,
}

// PRTODO: Rewrite MerkleItem stuff using BlindedProgram. 
// pub enum BlindedProgram {
//     Program(Program),
//     Blinding([u8; 32]),
// }

impl Predicate {
    /// Returns the number of bytes needed to serialize the Predicate.
    pub fn serialized_length(&self) -> usize {
        32
    }

    /// Converts predicate to a compressed point
    pub fn to_point(&self) -> CompressedRistretto {
        match self {
            Predicate::Opaque(p) => *p,
            Predicate::Key(k) => k.0,
            Predicate::Tree(d) => d.precomputed_point,
        }
    }

    /// Encodes the Predicate in program bytecode.
    pub fn encode(&self, prog: &mut Vec<u8>) {
        encoding::write_point(&self.to_point(), prog);
    }

    /// Downcasts the predicate to a verification key
    pub fn to_key(self) -> Result<VerificationKey, VMError> {
        match self {
            Predicate::Key(k) => Ok(k),
            _ => Err(VMError::TypeNotKey),
        }
    }

    /// Converts the predicate to its opaque representation.
    pub fn as_opaque(&self) -> Self {
        Predicate::Opaque(self.to_point())
    }

    fn commit_taproot(key: &[u8], root: &[u8]) -> Scalar {
        let mut t = Transcript::new(b"ZkVM.taproot");
        t.commit_bytes(b"key", key);
        t.commit_bytes(b"merkle", root);
        t.challenge_scalar(b"h")
    }

    /// Verifies whether the current predicate is a commitment to a signing key `key` and Merkle root `root`.
    /// Returns a `PointOp` instance that can be verified in a batch with other operations.
    pub fn prove_taproot(&self, key: &CompressedRistretto, root: &[u8]) -> PointOp {
        let h = Self::commit_taproot(&key.to_bytes(), root);
        // P == X + h1(X, M)*B -> 0 == -P + X + h1(X, M)*B
        PointOp {
            primary: Some(h),
            secondary: None,
            arbitrary: vec![(-Scalar::one(), self.to_point()), (Scalar::one(), *key)],
        }
    }
}

impl Into<CompressedRistretto> for Predicate {
    fn into(self) -> CompressedRistretto {
        self.to_point()
    }
}

impl CallProof {
    pub fn serialized_length(&self) -> usize {
        // VerificationKey is a 32-byte array
        // MerkleNeighbor is a 32-byte array
        32 + 4 + self.neighbors.len() * 32
    }

    pub fn parse(data: &[u8]) -> Result<Self, VMError> {
        SliceReader::parse(data, |r| {
            let mut call_proof = CallProof::default();
            call_proof.signing_key = VerificationKey(r.read_point()?);
            call_proof.positions = r.read_u32()?;
            let mut neighbors = vec![];
            while r.len() > 0 {
                neighbors.push(r.read_u8x32()?);
            }
            for i in 0..neighbors.len() {
                if call_proof.positions & (1 << 31 - i) == 0 {
                    call_proof
                        .neighbors
                        .push(MerkleNeighbor::Left(neighbors[i]));
                } else {
                    call_proof
                        .neighbors
                        .push(MerkleNeighbor::Right(neighbors[i]));
                }
            }
            Ok(call_proof)
        })
    }

    /// Serializes the call proof to a byte array
    pub fn encode(&self, buf: &mut Vec<u8>) {
        encoding::write_point(&self.signing_key.0, buf);
        encoding::write_u32(self.positions, buf);
        for n in &self.neighbors {
            match n {
                MerkleNeighbor::Left(l) => encoding::write_bytes(l, buf),
                MerkleNeighbor::Right(r) => encoding::write_bytes(r, buf),
            }
        }
    }
}
