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
use crate::transcript::TranscriptProtocol;
use crate::types::{Predicate, PredicateWitness};

impl Predicate {
    /// Computes a disjunction of two predicates.
    /// TBD: push this code into to_point() impl for the witness
    pub fn or(&self, right: &Predicate) -> Result<Predicate, VMError> {
        Ok(Predicate::Opaque(
            Self::commit_or(self.to_point()?, right.to_point()?)
                .compute()?
                .compress(),
        ))
    }

    /// Verifies whether the current predicate is a disjunction of two others.
    /// Returns a `PointOp` instance that can be verified in a batch with other operations.
    pub fn prove_or(&self, left: &Predicate, right: &Predicate) -> Result<PointOp, VMError> {
        let mut op = Self::commit_or(left.to_point()?, right.to_point()?);
        op.arbitrary.push((-Scalar::one(), self.to_point()?));
        Ok(op)
    }

    /// Creates a program-based predicate.
    /// One cannot sign for it as a public key because it’s using a secondary generator.
    /// TBD: push this code into to_point() impl for the witness
    pub fn program_predicate(prog: &[u8]) -> Result<Predicate, VMError> {
        Ok(Predicate::Opaque(
            Self::commit_program(prog).compute()?.compress(),
        ))
    }

    /// Verifies whether the current predicate is a commitment to a program `prog`.
    /// Returns a `PointOp` instance that can be verified in a batch with other operations.
    pub fn prove_program_predicate(&self, prog: &[u8]) -> Result<PointOp, VMError> {
        let mut op = Self::commit_program(prog);
        op.arbitrary.push((-Scalar::one(), self.to_point()?));
        Ok(op)
    }

    fn commit_or(left: CompressedRistretto, right: CompressedRistretto) -> PointOp {
        let mut t = Transcript::new(b"ZkVM.predicate");
        t.commit_point(b"L", &left);
        t.commit_point(b"R", &right);
        let f = t.challenge_scalar(b"f");

        // P = L + f*B
        PointOp {
            primary: Some(f),
            secondary: None,
            arbitrary: vec![(Scalar::one(), left)],
        }
    }

    fn commit_program(prog: &[u8]) -> PointOp {
        let mut t = Transcript::new(b"ZkVM.predicate");
        t.commit_bytes(b"prog", &prog);
        let h = t.challenge_scalar(b"h");

        // P = h*B2
        PointOp {
            primary: None,
            secondary: Some(h),
            arbitrary: Vec::new(),
        }
    }
}

impl PredicateWitness {
    pub fn to_point(&self) -> Result<CompressedRistretto, VMError> {
        Ok(self.to_uncompressed_point()?.compress())
    }

    fn to_uncompressed_point(&self) -> Result<RistrettoPoint, VMError> {
        Ok(match self {
            // TBD: use VerificationKey API instead of plain mult
            PredicateWitness::Key(s) => s * PedersenGens::default().B,
            PredicateWitness::Or(l, r) => {
                Predicate::commit_or(l.to_point()?, r.to_point()?).compute()?
            }
            PredicateWitness::Program(prog) => {
                let mut bytecode = Vec::new();
                Instruction::encode_program(prog.iter(), &mut bytecode);
                Predicate::commit_program(&bytecode).compute()?
            }
        })
    }

    pub fn encode(&self, program: &mut Vec<u8>) -> Result<(), VMError> {
        program.extend_from_slice(&self.to_point()?.to_bytes());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_program_commitment() {
        let prog = b"iddqd";
        let pred = Predicate::program_predicate(prog).unwrap();
        let op = pred.prove_program_predicate(prog).unwrap();
        assert!(op.verify().is_ok());
    }

    #[test]
    fn invalid_program_commitment() {
        let prog = b"iddqd";
        let prog2 = b"smth else";
        let pred = Predicate::program_predicate(prog).unwrap();
        let op = pred.prove_program_predicate(prog2).unwrap();
        assert!(op.verify().is_err());
    }

    #[test]
    fn valid_disjunction() {
        let gens = PedersenGens::default();

        // dummy predicates
        let left = Predicate::Opaque(gens.B.compress());
        let right = Predicate::Opaque(gens.B_blinding.compress());

        let pred = left.or(&right).unwrap();
        let op = pred.prove_or(&left, &right).unwrap();
        assert!(op.verify().is_ok());
    }

    #[test]
    fn invalid_disjunction1() {
        let gens = PedersenGens::default();

        // dummy predicates
        let left = Predicate::Opaque(gens.B.compress());
        let right = Predicate::Opaque(gens.B_blinding.compress());

        let pred = Predicate::Opaque(gens.B.compress());
        let op = pred.prove_or(&left, &right).unwrap();
        assert!(op.verify().is_err());
    }

    #[test]
    fn invalid_disjunction2() {
        let gens = PedersenGens::default();

        // dummy predicates
        let left = Predicate::Opaque(gens.B.compress());
        let right = Predicate::Opaque(gens.B_blinding.compress());

        let pred = left.or(&right).unwrap();
        let op = pred.prove_or(&right, &left).unwrap();
        assert!(op.verify().is_err());
    }
}
