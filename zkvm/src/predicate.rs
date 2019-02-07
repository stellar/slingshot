//! Implementation of a predicate tree.
//! Inspired by Taproot by Greg Maxwell and G'root by Anthony Towns.
//! Operations:
//! - disjunction: P = L + f(L,R)*B
//! - program_commitment: P = h(prog)*B2
use bulletproofs::PedersenGens;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;

use crate::errors::VMError;
use crate::point_ops::PointOp;
use crate::transcript::TranscriptProtocol;
use crate::types::Predicate;

impl Predicate {
    /// Computes a disjunction of two predicates.
    /// TBD: push this code into to_point() impl for the witness
    pub fn or(&self, right: &Predicate) -> Result<Predicate, VMError> {
        let mut t = Transcript::new(b"ZkVM.predicate");
        let gens = PedersenGens::default();
        t.commit_point(b"L", &self.to_point());
        t.commit_point(b"R", &right.to_point());
        let f = t.challenge_scalar(b"f");
        let l = self.to_point().decompress().ok_or(VMError::InvalidPoint)?;
        Ok(Predicate::Opaque((l + f * gens.B).compress()))
    }

    /// Verifies whether the current predicate is a disjunction of two others.
    /// Returns a `PointOp` instance that can be verified in a batch with other operations.
    pub fn prove_or(&self, left: &Predicate, right: &Predicate) -> PointOp {
        let mut t = Transcript::new(b"ZkVM.predicate");
        t.commit_point(b"L", &left.to_point());
        t.commit_point(b"R", &right.to_point());
        let f = t.challenge_scalar(b"f");

        // P == L + f*B   ->   0 == -P + L + f*B
        PointOp {
            primary: Some(f),
            secondary: None,
            arbitrary: vec![
                (-Scalar::one(), self.to_point()),
                (Scalar::one(), left.to_point()),
            ],
        }
    }

    /// Creates a program-based predicate.
    /// One cannot sign for it as a public key because it’s using a secondary generator.
    /// TBD: push this code into to_point() impl for the witness
    pub fn program_predicate(prog: &[u8]) -> Predicate {
        let mut t = Transcript::new(b"ZkVM.predicate");
        let gens = PedersenGens::default();
        t.commit_bytes(b"prog", &prog);
        let h = t.challenge_scalar(b"h");
        Predicate::Opaque((h * gens.B_blinding).compress())
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
            arbitrary: vec![(-Scalar::one(), self.to_point())],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_program_commitment() {
        let prog = b"iddqd";
        let pred = Predicate::program_predicate(prog);
        let op = pred.prove_program_predicate(prog);
        assert!(op.verify().is_ok());
    }

    #[test]
    fn invalid_program_commitment() {
        let prog = b"iddqd";
        let prog2 = b"smth else";
        let pred = Predicate::program_predicate(prog);
        let op = pred.prove_program_predicate(prog2);
        assert!(op.verify().is_err());
    }

    #[test]
    fn valid_disjunction() {
        let gens = PedersenGens::default();

        // dummy predicates
        let left = Predicate::Opaque(gens.B.compress());
        let right = Predicate::Opaque(gens.B_blinding.compress());

        let pred = left.or(&right).unwrap();
        let op = pred.prove_or(&left, &right);
        assert!(op.verify().is_ok());
    }

    #[test]
    fn invalid_disjunction1() {
        let gens = PedersenGens::default();

        // dummy predicates
        let left = Predicate::Opaque(gens.B.compress());
        let right = Predicate::Opaque(gens.B_blinding.compress());

        let pred = Predicate::Opaque(gens.B.compress());
        let op = pred.prove_or(&left, &right);
        assert!(op.verify().is_err());
    }

    #[test]
    fn invalid_disjunction2() {
        let gens = PedersenGens::default();

        // dummy predicates
        let left = Predicate::Opaque(gens.B.compress());
        let right = Predicate::Opaque(gens.B_blinding.compress());

        let pred = left.or(&right).unwrap();
        let op = pred.prove_or(&right, &left);
        assert!(op.verify().is_err());
    }
}
