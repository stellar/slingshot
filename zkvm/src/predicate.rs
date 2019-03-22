//! Implementation of a predicate tree.
//! Inspired by Taproot by Greg Maxwell and G'root by Anthony Towns.
//! Operations:
//! - disjunction: P = L + f(L,R)*B
//! - program_commitment: P = h(prog)*B2
use bulletproofs::PedersenGens;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use std::borrow::Borrow;

use crate::encoding;
use crate::errors::VMError;
use crate::point_ops::PointOp;
use crate::program::Program;
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

    /// Representation of a predicate as commitment to a program and blinding factor.
    Program(Program, Vec<u8>),

    /// Disjunction of n predicates.
    Or(PredicateDisjunction),
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
            Predicate::Program(prog, blinding) => {
                let mut bytecode = Vec::new();
                prog.encode(&mut bytecode);
                let h = Predicate::commit_program(&bytecode, blinding);
                (h * PedersenGens::default().B_blinding).compress()
            }
        }
    }

    /// Encodes the Predicate in program bytecode.
    pub fn encode(&self, prog: &mut Vec<u8>) {
        encoding::write_point(&self.to_point(), prog);
    }

    /// Verifies whether the current predicate is a disjunction of n others.
    /// Returns a `PointOp` instance that can be verified in a batch with other operations.
    pub fn prove_disjunction(&self, preds: &[Predicate]) -> PointOp {
        let f = Self::commit_disjunction(preds.iter().map(|p| p.to_point()));

        // P = X[0] + f*B
        PointOp {
            primary: Some(f),
            secondary: None,
            arbitrary: vec![
                (Scalar::one(), preds[0].to_point()),
                (-Scalar::one(), self.to_point()),
            ],
        }
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

    /// Creates a program with a random blinding factor.
    pub fn blinded_program<T: Into<Program>>(x: T) -> Self {
        let blinding: [u8; 16] = rand::random();
        Predicate::Program(x.into(), blinding.to_vec())
    }

    /// Creates a program with an empty blinding factor.
    pub fn unblinded_program<T: Into<Program>>(x: T) -> Self {
        Predicate::Program(x.into(), Vec::new())
    }

    /// Downcasts the predicate to a verification key
    pub fn to_key(self) -> Result<VerificationKey, VMError> {
        match self {
            Predicate::Key(k) => Ok(k),
            _ => Err(VMError::TypeNotKey),
        }
    }

    /// Downcasts the predicate to a disjunction.
    pub fn to_disjunction(self) -> Result<Vec<Predicate>, VMError> {
        match self {
            Predicate::Or(d) => Ok(d.preds),
            _ => Err(VMError::TypeNotDisjunction),
        }
    }

    /// Downcasts the predicate to a program.
    pub fn to_program(self) -> Result<(Program, Vec<u8>), VMError> {
        match self {
            Predicate::Program(p, s) => Ok((p, s)),
            _ => Err(VMError::TypeNotProgram),
        }
    }

    /// Converts the predicate to its opaque representation.
    pub fn as_opaque(&self) -> Self {
        Predicate::Opaque(self.to_point())
    }

    /// Creates a disjunction of a vector of predicates.
    pub fn disjunction(preds: Vec<Predicate>) -> Result<Self, VMError> {
        let point = {
            let f = Predicate::commit_disjunction(preds.iter().map(|p| p.to_point()));
            let l = preds[0]
                .to_point()
                .decompress()
                .ok_or(VMError::InvalidPoint)?;
            l + f * PedersenGens::default().B
        };
        Ok(Predicate::Or(PredicateDisjunction {
            preds: preds,
            precomputed_point: point.compress(),
        }))
    }

    fn commit_disjunction<I>(preds: I) -> Scalar
    where
        I: IntoIterator,
        I::Item: Borrow<CompressedRistretto>,
        I::IntoIter: ExactSizeIterator,
    {
        let mut t = Transcript::new(b"ZkVM.predicate");
        let iter = preds.into_iter();
        t.commit_u64(b"n", iter.len() as u64);
        for x in iter {
            t.commit_point(b"X", x.borrow());
        }
        t.challenge_scalar(b"f")
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

#[cfg(test)]
mod tests {
    use super::*;
    use bulletproofs::PedersenGens;

    fn bytecode(prog: &Program) -> Vec<u8> {
        let mut prog_vec = Vec::new();
        prog.encode(&mut prog_vec);
        prog_vec
    }

    #[test]
    fn valid_program_commitment() {
        let prog = Program::build(|p| p.drop());
        let pred = Predicate::unblinded_program(prog.clone());
        let op = pred.prove_program_predicate(&bytecode(&prog), &[]);
        assert!(op.verify().is_ok());
    }

    #[test]
    fn invalid_program_commitment() {
        let prog = Program::build(|p| p.drop());
        let prog2 = Program::build(|p| p.dup(1));
        let pred = Predicate::unblinded_program(prog);
        let op = pred.prove_program_predicate(&bytecode(&prog2), &[]);
        assert!(op.verify().is_err());
    }

    #[test]
    fn valid_disjunction1() {
        let gens = PedersenGens::default();

        // dummy predicates
        let preds = vec![
            Predicate::Opaque(gens.B.compress()),
            Predicate::Opaque(gens.B_blinding.compress()),
        ];

        let pred = Predicate::disjunction(preds.clone()).unwrap();
        let op = pred.prove_disjunction(&preds);
        assert!(op.verify().is_ok());
    }

    #[test]
    fn valid_disjunction2() {
        let gens = PedersenGens::default();

        // dummy predicates
        let preds = vec![
            Predicate::Opaque(gens.B.compress()),
            Predicate::Opaque(gens.B_blinding.compress()),
        ];

        let pred = Predicate::disjunction(preds.clone()).unwrap();
        let op = pred.prove_disjunction(&preds);
        assert!(op.verify().is_ok());
    }
    #[test]
    fn invalid_disjunction1() {
        let gens = PedersenGens::default();

        // dummy predicates
        let preds = vec![
            Predicate::Opaque(gens.B_blinding.compress()),
            Predicate::Opaque(gens.B.compress()),
        ];

        let pred = Predicate::Opaque(gens.B.compress());
        let op = pred.prove_disjunction(&preds);
        assert!(op.verify().is_err());
    }
}
