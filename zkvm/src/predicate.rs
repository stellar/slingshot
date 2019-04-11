//! ZkVM-specific implementation of a Taproot design proposed by Greg Maxwell.
//! https://lists.linuxfoundation.org/pipermail/bitcoin-dev/2018-January/015614.html
//! Operations:
//! - taproot key: P = X + h(X, M)*B
//! - program_commitment: P = h(prog)*B2
use bulletproofs::PedersenGens;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use musig::VerificationKey;

use crate::encoding;
use crate::encoding::SliceReader;
use crate::errors::VMError;
use crate::merkle::{MerkleItem, MerkleNeighbor, MerkleTree};
use crate::point_ops::PointOp;
use crate::program::Program;
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
    pub leaves: Vec<PredicateLeaf>,
    pub key: VerificationKey,
    blinding: [u8; 32],
    // We precompute the tweaked aggregated signing key when composing it via `Predicate::tree()`,
    // so that we can keep `to_point`/`encode` methods non-failable across all types.
    precomputed_point: CompressedRistretto,
}

#[derive(Clone, Debug, Default)]
pub struct CallProof {
    // Tweaked verification key
    pub verification_key: VerificationKey,

    // List of left-right neighbors, excluding the root and leaf hash
    pub neighbors: Vec<MerkleNeighbor>,
}

#[derive(Clone, Debug)]
pub enum PredicateLeaf {
    Program(Program),
    Blinding([u8; 32]),
}

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

    /// Downcasts the predicate to a predicate tree.
    pub fn to_predicate_tree(self) -> Result<PredicateTree, VMError> {
        match self {
            Predicate::Tree(d) => Ok(d),
            _ => Err(VMError::TypeNotPredicateTree),
        }
    }

    /// Converts the predicate to its opaque representation.
    pub fn as_opaque(&self) -> Self {
        Predicate::Opaque(self.to_point())
    }

    /// Creates a Tree from a vector of programs.
    pub fn tree(
        key: Option<VerificationKey>,
        progs: Vec<Program>,
        blinding_key: [u8; 32],
    ) -> Result<Self, VMError> {
        let signing_key = match key {
            Some(x) => x,
            _ => VerificationKey(PedersenGens::default().B_blinding.compress()),
        };
        let leaves = Self::commit_leaves(&progs, blinding_key);
        let root = MerkleTree::root(b"ZkVM.taproot", &leaves);
        // P = X + h(X, M)*G
        let point = {
            let h = Predicate::commit_taproot(signing_key.0.as_bytes(), &root);
            let x = signing_key.0.decompress().ok_or(VMError::InvalidPoint)?;
            let p = x + h * PedersenGens::default().B;
            p.compress()
        };

        Ok(Predicate::Tree(PredicateTree {
            leaves: leaves,
            blinding: blinding_key,
            key: signing_key,
            precomputed_point: point,
        }))
    }

    fn commit_taproot(key: &[u8], root: &[u8]) -> Scalar {
        let mut t = Transcript::new(b"ZkVM.taproot");
        t.commit_bytes(b"key", key);
        t.commit_bytes(b"merkle", root);
        t.challenge_scalar(b"h")
    }

    /// Verifies whether the current predicate is a commitment to a signing key `key` and Merkle root `root`.
    /// Returns a `PointOp` instance that can be verified in a batch with other operations.
    pub fn prove_taproot(&self, program: &Program, call_proof: &CallProof) -> PointOp {
        let pred_leaf = PredicateLeaf::Program(program.clone());
        let key = &call_proof.verification_key;
        let neighbors = &call_proof.neighbors;
        let root = MerkleTree::compute_root_from_path(b"ZkVM.taproot", &pred_leaf, neighbors);
        let h = Self::commit_taproot(&key.0.to_bytes(), &root);

        // P == X + h1(X, M)*B -> 0 == -P + X + h1(X, M)*B
        PointOp {
            primary: Some(h),
            secondary: None,
            arbitrary: vec![(-Scalar::one(), self.to_point()), (Scalar::one(), key.0)],
        }
    }

    fn commit_leaves(progs: &Vec<Program>, blinding_key: [u8; 32]) -> Vec<PredicateLeaf> {
        let mut t = Transcript::new(b"ZkVM.taproot-derive-blinding");
        let n: u64 = progs.len() as u64;
        t.commit_u64(b"n", n);
        t.commit_bytes(b"key", &blinding_key);
        for prog in progs.iter() {
            let mut buf = Vec::new();
            prog.encode(&mut buf);
            t.commit_bytes(b"prog", &buf);
        }

        let mut leaves = Vec::new();
        for prog in progs.iter() {
            let blinding = t.challenge_scalar(b"blinding");
            let blinding_leaf = PredicateLeaf::Blinding(blinding.to_bytes());
            let program_leaf = PredicateLeaf::Program(prog.clone());
            if blinding.to_bytes()[31] & 1 == 0 {
                leaves.push(blinding_leaf);
                leaves.push(program_leaf);
            } else {
                leaves.push(program_leaf);
                leaves.push(blinding_leaf);
            }
        }
        leaves
    }
}

impl Into<CompressedRistretto> for Predicate {
    fn into(self) -> CompressedRistretto {
        self.to_point()
    }
}

impl PredicateTree {
    /// Creates the call proof and returns that with the program at an index.
    pub fn create_callproof_program(
        &self,
        prog_index: usize,
    ) -> Result<(CallProof, Program), VMError> {
        let poss_leaf = &self.leaves[2 * prog_index];
        let leaf_index = match poss_leaf {
            PredicateLeaf::Blinding(_) => 2 * prog_index + 1,
            PredicateLeaf::Program(_) => 2 * prog_index,
        };
        let tree = MerkleTree::build(b"ZkVM.taproot", &self.leaves);
        let neighbors = tree.create_path(leaf_index).unwrap();
        let call_proof = CallProof {
            verification_key: self.key,
            neighbors: neighbors,
        };
        let program = self.leaves[leaf_index].clone().to_program()?;
        Ok((call_proof, program))
    }
}

impl CallProof {
    pub fn serialized_length(&self) -> usize {
        // VerificationKey is a 32-byte array
        // MerkleNeighbor is a 32-byte array
        32 + self.neighbors.len() * 32
    }

    pub fn parse(data: &[u8]) -> Result<Self, VMError> {
        SliceReader::parse(data, |r| {
            let mut call_proof = CallProof::default();
            call_proof.verification_key = VerificationKey(r.read_point()?);
            let positions = r.read_u32()?;
            let mut neighbors = vec![];
            while r.len() > 0 {
                neighbors.push(r.read_u8x32()?);
            }
            for i in 0..neighbors.len() {
                if positions & (1 << i) == 0 {
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
        encoding::write_point(&self.verification_key.0, buf);

        let mut positions: u32 = 0;
        for (i, n) in self.neighbors.iter().enumerate() {
            match n {
                MerkleNeighbor::Right(_) => {
                    positions = positions | (1 << i);
                }
                _ => {}
            }
        }
        encoding::write_u32(positions, buf);
        for n in &self.neighbors {
            match n {
                MerkleNeighbor::Left(l) => encoding::write_bytes(l, buf),
                MerkleNeighbor::Right(r) => encoding::write_bytes(r, buf),
            }
        }
    }
}

impl PredicateLeaf {
    /// Downcasts the predicate leaf to a program.
    pub fn to_program(self) -> Result<Program, VMError> {
        match self {
            PredicateLeaf::Program(p) => Ok(p),
            _ => Err(VMError::TypeNotProgram),
        }
    }
}

impl MerkleItem for PredicateLeaf {
    fn commit(&self, t: &mut Transcript) {
        match self {
            PredicateLeaf::Program(prog) => {
                let mut buf = Vec::new();
                prog.encode(&mut buf);
                t.commit_bytes(b"predicate_leaf", &buf);
            }
            PredicateLeaf::Blinding(bytes) => {
                t.commit_bytes(b"predicate_leaf", &bytes.clone());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rng;

    #[test]
    fn valid_taproot() {
        let prog1 = Program::build(|p| p.drop());
        let prog2 = Program::build(|p| p.dup(1));
        let progs = vec![prog1, prog2];
        let blinding_key = rand::thread_rng().gen::<[u8; 32]>();
        let tree_pred = Predicate::tree(None, progs, blinding_key).unwrap();
        let tree = tree_pred.clone().to_predicate_tree().unwrap();
        let (call_proof, prog) = tree.create_callproof_program(0).unwrap();
        let op = tree_pred.prove_taproot(&prog, &call_proof);
        assert!(op.verify().is_ok());
    }

    #[test]
    fn invalid_taproot() {
        let prog1 = Program::build(|p| p.drop());
        let prog2 = Program::build(|p| p.dup(1));
        let prog3 = Program::build(|p| p.dup(2));
        let progs = vec![prog1, prog2];
        let blinding_key = rand::thread_rng().gen::<[u8; 32]>();
        let tree_pred = Predicate::tree(None, progs, blinding_key).unwrap();
        let tree = tree_pred.clone().to_predicate_tree().unwrap();
        let (call_proof, _) = tree.create_callproof_program(0).unwrap();
        let op = tree_pred.prove_taproot(&prog3, &call_proof);
        assert!(op.verify().is_err())
    }
}
