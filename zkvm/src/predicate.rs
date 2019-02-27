//! Implementation of a predicate tree.
//! Inspired by Taproot by Greg Maxwell and G'root by Anthony Towns.
//! Operations:
//! - disjunction: P = L + f(L,R)*B
//! - program_commitment: P = h(prog)*B2
use bulletproofs::PedersenGens;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;

use crate::encoding;
use crate::errors::VMError;
use crate::ops::Instruction;
use crate::point_ops::PointOp;
use crate::signature::VerificationKey;
use crate::transcript::TranscriptProtocol;

/// Represents a ZkVM predicate with its optional witness data.
#[derive(Clone, Debug)]
pub enum Predicate {
    /// Verifier's view on the predicate in a compressed form to defer decompression cost.
    Opaque(RistrettoPoint),

    /// Signing key for the predicate-as-a-verification-key.
    /// Prover will provide secret signing key separately when
    /// constructing aggregated signature.
    Key(RistrettoPoint),

    /// Representation of a predicate as commitment to a program.
    Program(Vec<Instruction>),

    /// Disjunction of two predicates.
    Or(Box<Predicate>, Box<Predicate>),
}

impl Predicate {
    /// Returns the number of bytes needed to serialize the Predicate.
    pub fn serialized_length(&self) -> usize {
        32
    }

    /// Converts predicate to a compressed point
    pub fn to_point(&self) -> CompressedRistretto {
        self.to_uncompressed_point().compress()
    }

    /// Converts predicate to an uncompressed point
    fn to_uncompressed_point(&self) -> RistrettoPoint {
        match self {
            Predicate::Opaque(p) => *p,
            Predicate::Key(k) => *k,
            Predicate::Or(l, r) => {
                let l = l.to_uncompressed_point();
                let r = r.to_uncompressed_point();
                let f = Predicate::commit_or(l.compress(), r.compress());
                l + f * PedersenGens::default().B
            }
            Predicate::Program(prog) => {
                let mut bytecode = Vec::new();
                Instruction::encode_program(prog.iter(), &mut bytecode);
                let h = Predicate::commit_program(&bytecode);
                h * PedersenGens::default().B_blinding
            }
        }
    }

    /// Encodes the Predicate in program bytecode.
    pub fn encode(&self, prog: &mut Vec<u8>) {
        encoding::write_point(&self.to_point(), prog);
    }

    /// Verifies whether the current predicate is a disjunction of two others.
    /// Returns a `PointOp` instance that can be verified in a batch with other operations.
    pub fn prove_or(&self, left: &Predicate, right: &Predicate) -> PointOp {
        let l = left.to_point();
        let r = right.to_point();
        let f = Self::commit_or(l, r);

        // P = L + f*B
        PointOp {
            primary: Some(f),
            secondary: None,
            arbitrary: vec![(Scalar::one(), l), (-Scalar::one(), self.to_point())],
        }
    }

    /// Verifies whether the current predicate is a commitment to a program `prog`.
    /// Returns a `PointOp` instance that can be verified in a batch with other operations.
    pub fn prove_program_predicate(&self, prog: &[u8]) -> PointOp {
        let h = Self::commit_program(prog);
        // P == h*B2   ->   0 == -P + h*B2
        PointOp {
            primary: None,
            secondary: Some(h),
            arbitrary: vec![(-Scalar::one(), self.to_point())],
        }
    }

    /// Creates a predicate with witness being an opaque branch of the tree.
    pub fn opaque(point: CompressedRistretto) -> Result<Self, VMError> {
        Ok(Predicate::Opaque(
            point.decompress().ok_or(VMError::FormatError)?,
        ))
    }

    /// Creates a predicate with a signing key witness.
    pub fn from_key(key: CompressedRistretto) -> Result<Self, VMError> {
        Ok(Predicate::Key(
            key.decompress().ok_or(VMError::FormatError)?,
        ))
    }

    /// Downcasts the predicate to a signing key
    pub fn to_key(self) -> Result<CompressedRistretto, VMError> {
        match self {
            Predicate::Key(k) => Ok(k.compress()),
            _ => Err(VMError::TypeNotKey),
        }
    }

    /// Creates a disjunction of two predicates.
    pub fn or(self, right: Predicate) -> Result<Self, VMError> {
        Ok(Predicate::Or(Box::new(self), Box::new(right)).into())
    }

    /// Creates a program-based predicate.
    pub fn program(program: Vec<Instruction>) -> Self {
        Predicate::Program(program)
    }

    fn commit_or(left: CompressedRistretto, right: CompressedRistretto) -> Scalar {
        let mut t = Transcript::new(b"ZkVM.predicate");
        t.commit_point(b"L", &left);
        t.commit_point(b"R", &right);
        t.challenge_scalar(b"f")
    }

    fn commit_program(prog: &[u8]) -> Scalar {
        let mut t = Transcript::new(b"ZkVM.predicate");
        t.commit_bytes(b"prog", &prog);
        t.challenge_scalar(b"h")
    }
}

// impl From<CompressedRistretto> for Predicate {
//     fn from(p: CompressedRistretto) -> Self {
//         Predicate::Opaque(p)
//     }
// }

impl From<RistrettoPoint> for Predicate {
    fn from(p: RistrettoPoint) -> Self {
        Predicate::Opaque(p)
    }
}

impl Into<CompressedRistretto> for Predicate {
    fn into(self) -> CompressedRistretto {
        self.to_point()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bulletproofs::PedersenGens;

    fn bytecode(prog: &Vec<Instruction>) -> Vec<u8> {
        let mut prog_vec = Vec::new();
        Instruction::encode_program(prog.iter(), &mut prog_vec);
        prog_vec
    }

    #[test]
    fn valid_program_commitment() {
        let prog = vec![Instruction::Drop];
        let pred = Predicate::program(prog.clone());
        let op = pred.prove_program_predicate(&bytecode(&prog));
        assert!(op.verify().is_ok());
    }

    #[test]
    fn invalid_program_commitment() {
        let prog = vec![Instruction::Drop];
        let prog2 = vec![Instruction::Dup(1)];
        let pred = Predicate::program(prog);
        let op = pred.prove_program_predicate(&bytecode(&prog2));
        assert!(op.verify().is_err());
    }

    #[test]
    fn valid_disjunction() {
        let gens = PedersenGens::default();

        // dummy predicates
        let left = Predicate::Opaque(gens.B);
        let right = Predicate::Opaque(gens.B_blinding);

        let pred = left.clone().or(right.clone()).unwrap();
        let op = pred.prove_or(&left, &right);
        assert!(op.verify().is_ok());
    }

    #[test]
    fn invalid_disjunction1() {
        let gens = PedersenGens::default();

        // dummy predicates
        let left = Predicate::Opaque(gens.B);
        let right = Predicate::Opaque(gens.B_blinding);

        let pred = Predicate::Opaque(gens.B);
        let op = pred.prove_or(&left, &right);
        assert!(op.verify().is_err());
    }

    #[test]
    fn invalid_disjunction2() {
        let gens = PedersenGens::default();

        // dummy predicates
        let left = Predicate::Opaque(gens.B);
        let right = Predicate::Opaque(gens.B_blinding);

        let pred = left.clone().or(right.clone()).unwrap();
        let op = pred.prove_or(&right, &left);
        assert!(op.verify().is_err());
    }
}
