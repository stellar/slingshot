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
pub struct Predicate {
    point: CompressedRistretto,
    witness: Option<PredicateWitness>,
}

/// Prover's representation of the predicate tree with all the secret witness data.
#[derive(Clone, Debug)]
pub enum PredicateWitness {
    Key(Scalar),
    Program(Vec<Instruction>),
    Or(Box<Predicate>, Box<Predicate>),
}

impl Predicate {
    pub fn opaque(point: CompressedRistretto) -> Self {
        Predicate {
            point,
            witness: None,
        }
    }

    /// Constructs a predicate from a witness.
    pub fn from_witness(witness: PredicateWitness) -> Result<Self, VMError> {
        Ok(Predicate {
            point: witness.to_point()?,
            witness: Some(witness),
        })
    }

    pub fn point(&self) -> CompressedRistretto {
        self.point
    }

    pub fn witness(&self) -> Option<&PredicateWitness> {
        match &self.witness {
            None => None,
            Some(w) => Some(w),
        }
    }

    /// Encodes the Predicate in program bytecode.
    pub fn encode(&self, prog: &mut Vec<u8>) {
        prog.extend_from_slice(&self.point().to_bytes())
    }

    /// Computes a disjunction of two predicates.
    /// TBD: push this code into to_point() impl for the witness
    pub fn or(self, right: Predicate) -> Result<Predicate, VMError> {
        Ok(Predicate::from_witness(PredicateWitness::Or(
            Box::new(self),
            Box::new(right),
        ))?)
    }

    /// Verifies whether the current predicate is a disjunction of two others.
    /// Returns a `PointOp` instance that can be verified in a batch with other operations.
    pub fn prove_or(&self, left: &Predicate, right: &Predicate) -> PointOp {
        let mut op = Self::commit_or(left.point(), right.point());
        op.arbitrary.push((-Scalar::one(), self.point()));
        op
    }

    /// Creates a program-based predicate.
    /// One cannot sign for it as a public key because it’s using a secondary generator.
    /// TBD: push this code into to_point() impl for the witness
    pub fn from_program(program: Vec<Instruction>) -> Result<Predicate, VMError> {
        Ok(Predicate::from_witness(PredicateWitness::Program(program))?)
    }

    /// Verifies whether the current predicate is a commitment to a program `prog`.
    /// Returns a `PointOp` instance that can be verified in a batch with other operations.
    pub fn prove_program_predicate(&self, prog: &[u8]) -> PointOp {
        let mut op = Self::commit_program(prog);
        op.arbitrary.push((-Scalar::one(), self.point()));
        op
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

        // P == h*B2   ->   0 == -P + h*B2
        PointOp {
            primary: None,
            secondary: Some(h),
            arbitrary: Vec::new(),
        }
    }
}

impl PredicateWitness {
    pub fn to_point(&self) -> Result<CompressedRistretto, VMError> {
        Ok(match self {
            PredicateWitness::Key(s) => VerificationKey::from_secret(s).0,
            PredicateWitness::Or(l, r) => Predicate::commit_or(l.point(), r.point())
                .compute()?
                .compress(),
            PredicateWitness::Program(prog) => {
                let mut bytecode = Vec::new();
                Instruction::encode_program(prog.iter(), &mut bytecode);
                Predicate::commit_program(&bytecode).compute()?.compress()
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bytecode(prog: &Vec<Instruction>) -> Vec<u8> {
        let mut prog_vec = Vec::new();
        Instruction::encode_program(prog.iter(), &mut prog_vec);
        prog_vec
    }

    #[test]
    fn valid_program_commitment() {
        let prog = vec![Instruction::Drop];
        let pred = Predicate::from_program(prog.clone()).unwrap();
        let op = pred.prove_program_predicate(&bytecode(&prog));
        assert!(op.verify().is_ok());
    }

    #[test]
    fn invalid_program_commitment() {
        let prog = vec![Instruction::Drop];
        let prog2 = vec![Instruction::Dup(1)];
        let pred = Predicate::from_program(prog).unwrap();
        let op = pred.prove_program_predicate(&bytecode(&prog2));
        assert!(op.verify().is_err());
    }

    #[test]
    fn valid_disjunction() {
        let gens = PedersenGens::default();

        // dummy predicates
        let left = Predicate::opaque(gens.B.compress());
        let right = Predicate::opaque(gens.B_blinding.compress());

        let pred = left.clone().or(right.clone()).unwrap();
        let op = pred.prove_or(&left, &right);
        assert!(op.verify().is_ok());
    }

    #[test]
    fn invalid_disjunction1() {
        let gens = PedersenGens::default();

        // dummy predicates
        let left = Predicate::opaque(gens.B.compress());
        let right = Predicate::opaque(gens.B_blinding.compress());

        let pred = Predicate::opaque(gens.B.compress());
        let op = pred.prove_or(&left, &right);
        assert!(op.verify().is_err());
    }

    #[test]
    fn invalid_disjunction2() {
        let gens = PedersenGens::default();

        // dummy predicates
        let left = Predicate::opaque(gens.B.compress());
        let right = Predicate::opaque(gens.B_blinding.compress());

        let pred = left.clone().or(right.clone()).unwrap();
        let op = pred.prove_or(&right, &left);
        assert!(op.verify().is_err());
    }
}
