//! Implementation of a predicate tree.
//! Inspired by Taproot by Greg Maxwell and G'root by Anthony Towns.
//! Operations:
//! - disjunction: P = L + f(L,R)*B
//! - program_commitment: P = h(prog)*B2
use bulletproofs::PedersenGens;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;

use crate::errors::VMError;
use crate::ops::Instruction;
use crate::point_ops::PointOp;
use crate::signature::VerificationKey;
use crate::transcript::TranscriptProtocol;

/// Represents a ZkVM predicate with its optional witness data.
#[derive(Clone, Debug)]
pub enum Predicate {
    /// Verifier's view on the predicate in a compressed form to defer decompression cost.
    Opaque(CompressedRistretto),

    /// Prover's view on the predicate that has valid representation.
    Witness(PredicateWitness),
}

/// Prover's representation of the predicate tree with all the secret witness data.
#[derive(Clone, Debug)]
pub enum PredicateWitness {
    // Externally provided opaque predicate, but known to be a valid Ristretto point.
    Opaque(RistrettoPoint),
    Key(Scalar),
    Program(Vec<Instruction>),
    Or(Box<PredicateWitness>, Box<PredicateWitness>),
}

impl Predicate {
    /// Converts predicate to a compressed point
    pub fn to_point(&self) -> CompressedRistretto {
        match self {
            Predicate::Opaque(p) => *p,
            Predicate::Witness(w) => w.to_point(),
        }
    }

    /// Encodes the Predicate in program bytecode.
    pub fn encode(&self, prog: &mut Vec<u8>) {
        prog.extend_from_slice(&self.to_point().to_bytes())
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

    /// Creates an opaque predicate witness from a compressed point
    pub fn opaque_witness(point: CompressedRistretto) -> Result<Self, VMError> {
        Ok(Predicate::Witness(PredicateWitness::Opaque(
            point.decompress().ok_or(VMError::FormatError)?,
        )))
    }

    /// Creates a predicate with a signing key witness
    pub fn from_signing_key(secret_key: Scalar) -> Self {
        Predicate::Witness(PredicateWitness::Key(secret_key).into())
    }

    /// Downcasts the predicate to a signing key
    pub fn to_signing_key(self) -> Result<Scalar, VMError> {
        match self.to_witness()? {
            PredicateWitness::Key(s) => Ok(s),
            _ => Err(VMError::TypeNotKey),
        }
    }

    /// Creates a disjunction of two predicates.
    pub fn or(self, right: Predicate) -> Result<Self, VMError> {
        let l = self.to_witness()?;
        let r = right.to_witness()?;
        Ok(Predicate::Witness(
            PredicateWitness::Or(Box::new(l), Box::new(r)).into(),
        ))
    }

    /// Creates a program-based predicate.
    pub fn program(program: Vec<Instruction>) -> Self {
        Predicate::Witness(PredicateWitness::Program(program))
    }

    /// Downcasts the predicate to witness. Returns None if the predicate is opaque.
    fn to_witness(self) -> Result<PredicateWitness, VMError> {
        match self {
            Predicate::Opaque(_) => Err(VMError::WitnessMissing),
            Predicate::Witness(w) => Ok(w),
        }
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

impl PredicateWitness {
    /// Converts witness to a compressed point
    fn to_point(&self) -> CompressedRistretto {
        self.as_uncompressed_point().compress()
    }

    fn as_uncompressed_point(&self) -> RistrettoPoint {
        match self {
            PredicateWitness::Opaque(p) => *p,
            PredicateWitness::Key(s) => VerificationKey::from_secret_uncompressed(s),
            PredicateWitness::Or(l, r) => {
                let l = l.as_uncompressed_point();
                let f = Predicate::commit_or(l.compress(), r.to_point());
                l + f * PedersenGens::default().B
            }
            PredicateWitness::Program(prog) => {
                let mut bytecode = Vec::new();
                Instruction::encode_program(prog.iter(), &mut bytecode);
                let h = Predicate::commit_program(&bytecode);
                h * PedersenGens::default().B_blinding
            }
        }
    }
}

impl From<CompressedRistretto> for Predicate {
    fn from(p: CompressedRistretto) -> Self {
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
        let left = Predicate::opaque_witness(gens.B.compress()).unwrap();
        let right = Predicate::opaque_witness(gens.B_blinding.compress()).unwrap();

        let pred = left.clone().or(right.clone()).unwrap();
        let op = pred.prove_or(&left, &right);
        assert!(op.verify().is_ok());
    }

    #[test]
    fn invalid_disjunction1() {
        let gens = PedersenGens::default();

        // dummy predicates
        let left = Predicate::opaque_witness(gens.B.compress()).unwrap();
        let right = Predicate::opaque_witness(gens.B_blinding.compress()).unwrap();

        let pred = Predicate::Opaque(gens.B.compress());
        let op = pred.prove_or(&left, &right);
        assert!(op.verify().is_err());
    }

    #[test]
    fn invalid_disjunction2() {
        let gens = PedersenGens::default();

        // dummy predicates
        let left = Predicate::opaque_witness(gens.B.compress()).unwrap();
        let right = Predicate::opaque_witness(gens.B_blinding.compress()).unwrap();

        let pred = left.clone().or(right.clone()).unwrap();
        let op = pred.prove_or(&right, &left);
        assert!(op.verify().is_err());
    }
}
