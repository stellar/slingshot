//! ZkVM-specific implementation of a Taproot design proposed by Greg Maxwell.
//! https://lists.linuxfoundation.org/pipermail/bitcoin-dev/2018-January/015614.html
//! Operations:
//! - taproot key: P = X + h(X, M)*B
//! - program_commitment: P = h(prog)*B2

use bulletproofs::PedersenGens;
use core::iter;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use musig::{BatchVerification, SingleVerifier, VerificationKey};
use serde::{Deserialize, Serialize};

use crate::encoding;
use crate::encoding::Encodable;
use crate::encoding::{Reader, ReaderExt};
use crate::errors::VMError;
use crate::merkle::{Hash, Hasher, MerkleItem, MerkleTree, Path};
use crate::program::{Program, ProgramItem};
use crate::transcript::TranscriptProtocol;

/// Represents a ZkVM predicate with its optional witness data.
#[derive(Clone, PartialEq, Deserialize, Serialize)]
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
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
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
#[derive(Clone, Debug, PartialEq)]
pub struct CallProof {
    // Pure verification key
    pub verification_key: VerificationKey,

    // Merkle path.
    pub path: Path,
}

/// PredicateLeaf represents a leaf in the merkle tree of predicate's clauses.
/// For secrecy, each program is blinded via a dummy neighbour called the "blinding leaf".
/// From the verifier's perspective, the hash of this node simply appears as part of a merkle proof,
/// but from the prover's perspective, some leafs are dummy uniformly random nodes.
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub enum PredicateLeaf {
    Program(ProgramItem),
    Blinding([u8; 32]),
}
impl Encodable for Predicate {
    /// Encodes the Predicate in program bytecode.
    fn encode(&self, prog: &mut Vec<u8>) {
        encoding::write_point(&self.to_point(), prog);
    }
    /// Returns the number of bytes needed to serialize the Predicate.
    fn encoded_length(&self) -> usize {
        32
    }
}
impl Predicate {
    /// Converts predicate to a compressed point
    pub fn to_point(&self) -> CompressedRistretto {
        match self {
            Predicate::Opaque(p) => *p,
            Predicate::Key(k) => k.into_point(),
            Predicate::Tree(d) => d.precomputed_key.into_point(),
        }
    }

    /// Converts the predicate to a verification key
    pub fn to_verification_key(self) -> Result<VerificationKey, VMError> {
        match self {
            Predicate::Opaque(pt) => {
                VerificationKey::from_compressed(pt).ok_or(VMError::InvalidPoint)
            }
            Predicate::Key(k) => Ok(k),
            Predicate::Tree(t) => Ok(t.precomputed_key),
        }
    }

    /// Downcasts the predicate to a verification key witness.
    /// TBD: use Multikey
    pub fn to_verification_key_witness(self) -> Result<VerificationKey, VMError> {
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

    fn commit_taproot(key: &VerificationKey, root: &Hash) -> Scalar {
        let mut t = Transcript::new(b"ZkVM.taproot");
        t.append_message(b"key", key.as_bytes());
        t.append_message(b"merkle", root);
        t.challenge_scalar(b"h")
    }

    /// Verifies whether the current predicate is a commitment to a signing key `key` and Merkle root `root`,
    /// defers operation to `batch`.
    pub fn verify_taproot_batched(
        &self,
        program_item: &ProgramItem,
        call_proof: &CallProof,
        batch: &mut impl BatchVerification,
    ) {
        let key = &call_proof.verification_key;
        let root = &call_proof
            .path
            .compute_root(program_item, &Hasher::new(b"ZkVM.taproot"));
        let h = Self::commit_taproot(key, &root);

        // P == X + h1(X, M)*B -> 0 == -P + X + h1(X, M)*B
        batch.append(
            h,
            iter::once(-Scalar::one()).chain(iter::once(Scalar::one())),
            iter::once(self.to_point().decompress())
                .chain(iter::once(key.into_point().decompress())),
        )
    }

    /// Verifies whether the current predicate is a commitment to a signing key `key` and Merkle root `root`.
    pub fn verify_taproot(
        &self,
        program_item: &ProgramItem,
        call_proof: &CallProof,
    ) -> Result<(), VMError> {
        SingleVerifier::verify(|v| self.verify_taproot_batched(program_item, call_proof, v))
            .map_err(|_| VMError::InvalidPredicateTree)
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
        let root = MerkleTree::root(b"ZkVM.taproot", leaves.iter());

        // P = X + h(X, M)*G
        let adjustment_factor = Predicate::commit_taproot(&key, &root);
        let precomputed_key = {
            let h = adjustment_factor;
            let x = key.into_point().decompress().ok_or(VMError::InvalidPoint)?;
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
        // let tree = MerkleTree::build(b"ZkVM.taproot", &self.leaves);
        // let path = tree.create_path(leaf_index).ok_or(VMError::BadArguments)?;
        let path = Path::new(&self.leaves, leaf_index, &Hasher::new(b"ZkVM.taproot"))
            .ok_or(VMError::BadArguments)?;
        let verification_key = self.key.clone();
        let call_proof = CallProof {
            verification_key,
            path,
        };
        let program = self.leaves[leaf_index].clone().to_program()?;
        Ok((call_proof, program))
    }

    fn create_merkle_leaves(progs: &Vec<Program>, blinding_key: [u8; 32]) -> Vec<PredicateLeaf> {
        let mut t = Transcript::new(b"ZkVM.taproot-derive-blinding");
        let n: u64 = progs.len() as u64;
        t.append_u64(b"n", n);
        t.append_message(b"key", &blinding_key);
        for prog in progs.iter() {
            let buf = prog.encode_to_vec();
            t.append_message(b"prog", &buf);
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

impl Encodable for CallProof {
    /// Serializes the call proof to a byte array.
    fn encode(&self, buf: &mut Vec<u8>) {
        encoding::write_point(self.verification_key.as_point(), buf);
        self.path.encode(buf);
    }
    fn encoded_length(&self) -> usize {
        32 + self.path.encoded_length()
    }
}

impl CallProof {
    /// Decodes the call proof from bytes.
    pub fn decode(reader: &mut impl Reader) -> Result<Self, VMError> {
        let point = VerificationKey::from_compressed(reader.read_point()?);
        Ok(CallProof {
            verification_key: point.ok_or(VMError::InvalidPoint)?,
            path: Path::decode(reader)?,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.encode_to_vec()
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
            PredicateLeaf::Blinding(bytes) => t.append_message(b"blinding", &bytes.clone()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rng;

    #[test]
    fn valid_taproot() {
        let prog1 = Program::build(|p| {
            p.drop();
        });
        let prog2 = Program::build(|p| {
            p.dup(1);
        });
        let progs = vec![prog1, prog2];
        let blinding_key = rand::thread_rng().gen::<[u8; 32]>();
        let tree = PredicateTree::new(None, progs, blinding_key).unwrap();
        let tree_pred = Predicate::Tree(tree.clone());
        let (call_proof, prog) = tree.create_callproof(0).unwrap();
        let result = tree_pred.verify_taproot(&ProgramItem::Program(prog), &call_proof);
        assert!(result.is_ok());
    }

    #[test]
    fn invalid_taproot() {
        let prog1 = Program::build(|p| {
            p.drop();
        });
        let prog2 = Program::build(|p| {
            p.dup(1);
        });
        let prog3 = Program::build(|p| {
            p.dup(2);
        });
        let progs = vec![prog1, prog2];
        let blinding_key = rand::thread_rng().gen::<[u8; 32]>();
        let tree = PredicateTree::new(None, progs, blinding_key).unwrap();
        let tree_pred = Predicate::Tree(tree.clone());
        let (call_proof, _) = tree.create_callproof(0).unwrap();
        let result = tree_pred.verify_taproot(&ProgramItem::Program(prog3), &call_proof);
        assert!(result.is_err())
    }
}
