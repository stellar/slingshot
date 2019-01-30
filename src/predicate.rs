//! Implementation of a predicate tree.
//! Inspired by Taproot by Greg Maxwell and G'root by Anthony Towns.
//! Operations:
//! - disjunction: P = L + f(L,R)*B
//! - program_commitment: P = h(prog)*B2
use bulletproofs::PedersenGens;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;

use crate::errors::VMError;
use crate::point_ops::PointOp;
use crate::transcript::TranscriptProtocol;

/// Predicate is represented by a compressed Ristretto point.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Predicate(pub CompressedRistretto);

impl Predicate {
    /// Computes a disjunction of two predicates.
    pub fn or(&self, right: &Predicate, gens: &PedersenGens) -> Result<Predicate, VMError> {
        let mut t = Transcript::new(b"ZkVM.predicate");
        t.commit_point(b"L", &self.0);
        t.commit_point(b"R", &right.0);
        let f = t.challenge_scalar(b"f");
        let l = self.0.decompress().ok_or(VMError::InvalidPoint)?;
        Ok(Predicate((l + f * gens.B).compress()))
    }

    /// Verifies whether the current predicate is a disjunction of two others.
    /// Returns a `PointOp` instance that can be verified in a batch with other operations.
    pub fn prove_or(&self, left: &Predicate, right: &Predicate) -> PointOp {
        let mut t = Transcript::new(b"ZkVM.predicate");
        t.commit_point(b"L", &left.0);
        t.commit_point(b"R", &right.0);
        let f = t.challenge_scalar(b"f");

        // P == L + f*B   ->   0 == -P + L + f*B
        PointOp {
            primary: Some(f),
            secondary: None,
            arbitrary: vec![(-Scalar::one(), self.0), (Scalar::one(), left.0)],
        }
    }

    /// Creates a program-based predicate.
    /// One cannot sign for it as a public key because it’s using a secondary generator.
    pub fn program_predicate(prog: &[u8], gens: &PedersenGens) -> Predicate {
        let mut t = Transcript::new(b"ZkVM.predicate");
        t.commit_bytes(b"prog", &prog);
        let h = t.challenge_scalar(b"h");
        Predicate((h * gens.B_blinding).compress())
    }

    /// Verifies whether the current predicate is a commitment to a program `prog`.
    /// Returns a `PointOp` instance that can be verified in a batch with other operations.
    pub fn prove_program_predicate(&self, prog: &[u8]) -> PointOp {
        let mut t = Transcript::new(b"ZkVM.predicate");
        t.commit_bytes(b"prog", &prog);
        let h = t.challenge_scalar(b"h");

        // P == h*B2   ->   0 == -P + h*B2
        PointOp {
            primary: None,
            secondary: Some(h),
            arbitrary: vec![(-Scalar::one(), self.0)],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_program_commitment() {
        let gens = PedersenGens::default();
        let prog = b"iddqd";
        let pred = Predicate::program_predicate(prog, &gens);
        let op = pred.prove_program_predicate(prog);
        assert!(op.verify(&gens).is_ok());
    }

    #[test]
    fn invalid_program_commitment() {
        let gens = PedersenGens::default();
        let prog = b"iddqd";
        let prog2 = b"smth else";
        let pred = Predicate::program_predicate(prog, &gens);
        let op = pred.prove_program_predicate(prog2);
        assert!(op.verify(&gens).is_err());
    }

    #[test]
    fn valid_disjunction() {
        let gens = PedersenGens::default();

        // dummy predicates
        let left = Predicate(gens.B.compress());
        let right = Predicate(gens.B_blinding.compress());

        let pred = left.or(&right, &gens).unwrap();
        let op = pred.prove_or(&left, &right);
        assert!(op.verify(&gens).is_ok());
    }

    #[test]
    fn invalid_disjunction1() {
        let gens = PedersenGens::default();

        // dummy predicates
        let left = Predicate(gens.B.compress());
        let right = Predicate(gens.B_blinding.compress());

        let pred = left.clone();
        let op = pred.prove_or(&left, &right);
        assert!(op.verify(&gens).is_err());
    }

    #[test]
    fn invalid_disjunction2() {
        let gens = PedersenGens::default();

        // dummy predicates
        let left = Predicate(gens.B.compress());
        let right = Predicate(gens.B_blinding.compress());

        let pred = left.or(&right, &gens).unwrap();
        let op = pred.prove_or(&right, &left);
        assert!(op.verify(&gens).is_err());
    }
}
