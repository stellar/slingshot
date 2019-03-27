//! Implementation of a predicate tree.
//! Inspired by Taproot by Greg Maxwell and G'root by Anthony Towns.
//! Operations:
//! - disjunction: P = L + f(L,R)*B
//! - program_commitment: P = h(prog)*B2
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;

use crate::encoding;
use crate::errors::VMError;
use crate::point_ops::PointOp;
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

    /// Disjunction of n predicates.
    Merkle(PredicateDisjunction),
}

#[derive(Clone, Debug)]
pub struct PredicateDisjunction {
    preds: Vec<Predicate>,
    // We precompute the disjunction predicate when composing it via `Predicate::or()`,
    // so that we can keep `to_point`/`encode` methods non-failable across all types.
    precomputed_point: CompressedRistretto,
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
            Predicate::Or(d) => d.precomputed_point,
        }
    }

    /// Encodes the Predicate in program bytecode.
    pub fn encode(&self, prog: &mut Vec<u8>) {
        encoding::write_point(&self.to_point(), prog);
    }

    /// Verifies whether the current predicate is a commitment to a program `prog`.
    /// Returns a `PointOp` instance that can be verified in a batch with other operations.
    pub fn prove_program_predicate(&self, prog: &[u8], blinding: &[u8]) -> PointOp {
        let h = Self::commit_program(prog, blinding);
        // P == h*B2   ->   0 == -P + h*B2
        PointOp {
            primary: None,
            secondary: Some(h),
            arbitrary: vec![(-Scalar::one(), self.to_point())],
        }
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

    fn commit_program(prog: &[u8], blinding: &[u8]) -> Scalar {
        let mut t = Transcript::new(b"ZkVM.predicate");
        t.commit_bytes(b"blinding", blinding);
        t.commit_bytes(b"prog", &prog);
        t.challenge_scalar(b"h")
    }
}

impl Into<CompressedRistretto> for Predicate {
    fn into(self) -> CompressedRistretto {
        self.to_point()
    }
}
