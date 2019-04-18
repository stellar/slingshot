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
use crate::program::{Program, ProgramItem};
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

/// Represents a ZkVM predicate tree.
#[derive(Clone, Debug)]
pub struct PredicateTree {
    /// Vector of the programs and blinding factors, stored as Merkelized predicate leafs.
    leaves: Vec<PredicateLeaf>,

    /// Verification key for the tree.
    key: VerificationKey,

    /// Random seed from which we derive individual blinding factors for each leaf program.
    blinding_key: [u8; 32],

    // We precompute the tweaked aggregated signing key when composing it via `Predicate::tree()`,
    // so that we can keep `to_point`/`encode` methods non-failable across all types.
    precomputed_key: VerificationKey,

    // Scalar that's added to the signing key - a hash of the merkle root and the pubkey
    adjustment_factor: Scalar,
}

/// Call proof represents a proof that a certain program is committed via the merkle tree into the predicate.
/// Used by `call` instruction. The program is not the part of the proof.
#[derive(Clone, Debug)]
pub struct CallProof {
    // Pure verification key
    pub verification_key: VerificationKey,

    // List of left-right neighbors, excluding the root and leaf hash
    pub neighbors: Vec<MerkleNeighbor>,
}

/// PredicateLeaf represents a leaf in the merkle tree of predicate's clauses.
/// For secrecy, each program is blinded via a dummy neighbour called the "blinding leaf".
/// From the verifier's perspective, the hash of this node simply appears as part of a merkle proof,
/// but from the prover's perspective, some leafs are dummy uniformly random nodes.
#[derive(Clone, Debug)]
pub enum PredicateLeaf {
    Program(ProgramItem),
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
            Predicate::Key(k) => k.into_compressed(),
            Predicate::Tree(d) => d.precomputed_key.into_compressed(),
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
            Predicate::Tree(t) => Ok(t.precomputed_key),
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

    fn commit_taproot(key: &VerificationKey, root: &[u8; 32]) -> Scalar {
        let mut t = Transcript::new(b"ZkVM.taproot");
        t.commit_bytes(b"key", &key.as_compressed().to_bytes());
        t.commit_bytes(b"merkle", root);
        t.challenge_scalar(b"h")
    }

    /// Verifies whether the current predicate is a commitment to a signing key `key` and Merkle root `root`.
    /// Returns a `PointOp` instance that can be verified in a batch with other operations.
    pub fn prove_taproot(&self, program_item: &ProgramItem, call_proof: &CallProof) -> PointOp {
        let key = &call_proof.verification_key;
        let neighbors = &call_proof.neighbors;
        let root = MerkleTree::compute_root_from_path(b"ZkVM.taproot", program_item, neighbors);
        let h = Self::commit_taproot(key, &root);

        // P == X + h1(X, M)*B -> 0 == -P + X + h1(X, M)*B
        PointOp {
            primary: Some(h),
            secondary: None,
            arbitrary: vec![
                (-Scalar::one(), self.to_point()),
                (Scalar::one(), key.into_compressed()),
            ],
        }
    }

    /// Helper to create an unsignable key
    fn unsignable_key() -> VerificationKey {
        VerificationKey::from(PedersenGens::default().B_blinding)
    }
}

impl Into<CompressedRistretto> for Predicate {
    fn into(self) -> CompressedRistretto {
        self.to_point()
    }
}

impl PredicateTree {
    /// Creates new predicate tree with a verification key and a list of programs
    pub fn new(
        key: Option<VerificationKey>,
        progs: Vec<Program>,
        blinding_key: [u8; 32],
    ) -> Result<Self, VMError> {
        // If the key is None, use a point with provably unknown discrete log w.r.t. primary basepoint.
        let key = key.unwrap_or_else(|| Predicate::unsignable_key());
        let leaves = Self::create_merkle_leaves(&progs, blinding_key);
        if leaves.len() > (1 << 31) {
            return Err(VMError::InvalidPredicateTree);
        }
        let root = MerkleTree::root(b"ZkVM.taproot", &leaves);

        // P = X + h(X, M)*G
        let adjustment_factor = Predicate::commit_taproot(&key, &root);
        let precomputed_key = {
            let h = adjustment_factor;
            let x = key.into_point();
            let p = x + h * PedersenGens::default().B;
            VerificationKey::from(p)
        };

        Ok(Self {
            leaves,
            blinding_key,
            key,
            precomputed_key,
            adjustment_factor,
        })
    }

    /// Returns the adjustment factor for signing
    // TODO: Instead, we would rather return a "key witness" object like musig::Multikey.
    // That would directly store the adjustment factor.
    pub fn adjustment_factor(&self) -> Scalar {
        self.adjustment_factor
    }

    /// Creates the call proof and returns that with the program at an index.
    pub fn create_callproof(&self, prog_index: usize) -> Result<(CallProof, Program), VMError> {
        // The `prog_index` is used over the list of the programs,
        // but the actual tree contains also contains blinding factors,
        // so we need to adjust the index accordingly.
        // Blinding factors are located randomly to the left or right of the program leaf,
        // so we simply pick the left leaf, check it, and if it's not the program, pick the right one instead.
        if prog_index >= self.leaves.len() / 2 {
            return Err(VMError::BadArguments);
        }
        let possible_leaf = &self.leaves[2 * prog_index];
        let leaf_index = match possible_leaf {
            PredicateLeaf::Blinding(_) => 2 * prog_index + 1,
            PredicateLeaf::Program(_) => 2 * prog_index,
        };
        let tree = MerkleTree::build(b"ZkVM.taproot", &self.leaves);
        let neighbors = tree.create_path(leaf_index)?;
        let verification_key = self.key.clone();
        let call_proof = CallProof {
            verification_key,
            neighbors,
        };
        let program = self.leaves[leaf_index].clone().to_program()?;
        Ok((call_proof, program))
    }

    fn create_merkle_leaves(progs: &Vec<Program>, blinding_key: [u8; 32]) -> Vec<PredicateLeaf> {
        let mut t = Transcript::new(b"ZkVM.taproot-derive-blinding");
        let n: u64 = progs.len() as u64;
        t.commit_u64(b"n", n);
        t.commit_bytes(b"key", &blinding_key);
        for prog in progs.iter() {
            let mut buf = Vec::with_capacity(prog.serialized_length());
            prog.encode(&mut buf);
            t.commit_bytes(b"prog", &buf);
        }

        let mut leaves = Vec::new();
        for prog in progs.iter() {
            let mut blinding = [0u8; 32];
            t.challenge_bytes(b"blinding", &mut blinding);
            let blinding_leaf = PredicateLeaf::Blinding(blinding);
            let program_leaf = PredicateLeaf::Program(ProgramItem::Program(prog.clone()));

            // Sacrifice one bit of entropy in the blinding factor
            // to make the position of the program random and
            // make the tree indistinguishable from non-blinded trees.
            if blinding[0] & 1 == 0 {
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

impl CallProof {
    pub fn serialized_length(&self) -> usize {
        // VerificationKey is a 32-byte array
        // MerkleNeighbor is a 32-byte array
        32 + 4 + self.neighbors.len() * 32
    }

    /// Decodes the call proof from bytes.
    pub fn decode<'a>(reader: &mut SliceReader<'a>) -> Result<Self, VMError> {
        let verification_key =
            VerificationKey::from_compressed(reader.read_point()?).ok_or(VMError::InvalidPoint)?;

        let positions = reader.read_u32()?;
        if positions == 0 {
            return Err(VMError::FormatError);
        }
        let num_neighbors = (31 - positions.leading_zeros()) as usize;
        let mut neighbors = Vec::with_capacity(num_neighbors);
        for i in 0..num_neighbors {
            let bytes = reader.read_u8x32()?;
            neighbors.push(if positions & (1 << i) == 0 {
                MerkleNeighbor::Left(bytes)
            } else {
                MerkleNeighbor::Right(bytes)
            });
        }
        Ok(CallProof {
            verification_key,
            neighbors,
        })
    }

    /// Serializes the call proof to a byte array.
    pub fn encode(&self, buf: &mut Vec<u8>) {
        encoding::write_point(self.verification_key.as_compressed(), buf);

        let num_neighbors = self.neighbors.len();
        let mut positions: u32 = 1 << num_neighbors;
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

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.serialized_length());
        self.encode(&mut buf);
        buf
    }
}

impl PredicateLeaf {
    /// Downcasts the predicate leaf to a program.
    pub fn to_program(self) -> Result<Program, VMError> {
        match self {
            PredicateLeaf::Program(p) => p.to_program(),
            _ => Err(VMError::TypeNotProgram),
        }
    }
}

impl MerkleItem for PredicateLeaf {
    fn commit(&self, t: &mut Transcript) {
        match self {
            PredicateLeaf::Program(prog) => prog.commit(t),
            PredicateLeaf::Blinding(bytes) => t.commit_bytes(b"blinding", &bytes.clone()),
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
        let tree = PredicateTree::new(None, progs, blinding_key).unwrap();
        let tree_pred = Predicate::Tree(tree.clone());
        let (call_proof, prog) = tree.create_callproof(0).unwrap();
        let op = tree_pred.prove_taproot(&ProgramItem::Program(prog), &call_proof);
        assert!(op.verify().is_ok());
    }

    #[test]
    fn invalid_taproot() {
        let prog1 = Program::build(|p| p.drop());
        let prog2 = Program::build(|p| p.dup(1));
        let prog3 = Program::build(|p| p.dup(2));
        let progs = vec![prog1, prog2];
        let blinding_key = rand::thread_rng().gen::<[u8; 32]>();
        let tree = PredicateTree::new(None, progs, blinding_key).unwrap();
        let tree_pred = Predicate::Tree(tree.clone());
        let (call_proof, _) = tree.create_callproof(0).unwrap();
        let op = tree_pred.prove_taproot(&ProgramItem::Program(prog3), &call_proof);
        assert!(op.verify().is_err())
    }
}
