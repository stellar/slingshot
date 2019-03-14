//! Implementation of a predicate tree.
//! Inspired by Taproot by Greg Maxwell and G'root by Anthony Towns.
//! Operations:
//! - disjunction: P = L + f(L,R)*B
//! - program_commitment: P = h(prog)*B2
use bulletproofs::PedersenGens;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;

use crate::encoding;
use crate::errors::VMError;
use crate::ops::Program;
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

    /// Representation of a predicate as commitment to a program and salt.
    Program(Program, Vec<u8>),

    /// Disjunction of two predicates.
    Or(Box<PredicateDisjunction>),
}

#[derive(Clone, Debug)]
pub struct PredicateDisjunction {
    left: Predicate,
    right: Predicate,
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
            Predicate::Program(prog, salt) => {
                let mut bytecode = Vec::new();
                prog.encode(&mut bytecode);
                // XXX: Check if this is correct, I don't think it is...
                let h = Predicate::commit_program(&bytecode, salt);
                (h * PedersenGens::default().B_blinding).compress()
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
    pub fn prove_program_predicate(&self, prog: &[u8], salt: &[u8]) -> PointOp {
        let h = Self::commit_program(prog, salt);
        // P == h*B2   ->   0 == -P + h*B2
        PointOp {
            primary: None,
            secondary: Some(h),
            arbitrary: vec![(-Scalar::one(), self.to_point())],
        }
    }

    /// Creates a program with a random salt.
    pub fn blinded_program<T: Into<Program>>(x: T) -> Self {
        let salt: [u8; 16] = rand::random();
        Predicate::Program(x.into(), salt.to_vec())
    }

    /// Creates a program with an empty salt.
    pub fn unblinded_program<T: Into<Program>>(x: T) -> Self {
        let salt: [u8; 0] = [];
        Predicate::Program(x.into(), salt.to_vec())
    }

    /// Downcasts the predicate to a verification key
    pub fn to_key(self) -> Result<VerificationKey, VMError> {
        match self {
            Predicate::Key(k) => Ok(k),
            _ => Err(VMError::TypeNotKey),
        }
    }

    /// Downcasts the predicate to a disjunction.
    pub fn to_disjunction(self) -> Result<(Predicate, Predicate), VMError> {
        match self {
            Predicate::Or(d) => Ok((d.left, d.right)),
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

    /// Creates a disjunction of two predicates.
    pub fn or(self, right: Predicate) -> Result<Self, VMError> {
        let point = {
            let l = self.to_point();
            let f = Predicate::commit_or(l, right.to_point());
            let l = l.decompress().ok_or(VMError::InvalidPoint)?;
            l + f * PedersenGens::default().B
        };
        Ok(Predicate::Or(Box::new(PredicateDisjunction {
            left: self,
            right: right,
            precomputed_point: point.compress(),
        })))
    }

    fn commit_or(left: CompressedRistretto, right: CompressedRistretto) -> Scalar {
        let mut t = Transcript::new(b"ZkVM.predicate");
        t.commit_point(b"L", &left);
        t.commit_point(b"R", &right);
        t.challenge_scalar(b"f")
    }

    fn commit_program(prog: &[u8], salt: &[u8]) -> Scalar {
        let mut t = Transcript::new(b"ZkVM.predicate");
        t.commit_bytes(b"salt", salt);
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
        let salt: [u8; 0] = [];
        let op = pred.prove_program_predicate(&bytecode(&prog), &salt);
        assert!(op.verify().is_ok());
    }

    #[test]
    fn invalid_program_commitment() {
        let prog = Program::build(|p| p.drop());
        let prog2 = Program::build(|p| p.dup(1));
        let pred = Predicate::unblinded_program(prog);
        let salt: [u8; 0] = [];
        let op = pred.prove_program_predicate(&bytecode(&prog2), &salt);
        assert!(op.verify().is_err());
    }

    #[test]
    fn valid_disjunction() {
        let gens = PedersenGens::default();

        // dummy predicates
        let left = Predicate::Opaque(gens.B.compress());
        let right = Predicate::Opaque(gens.B_blinding.compress());

        let pred = left.clone().or(right.clone()).unwrap();
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

        let pred = left.clone().or(right.clone()).unwrap();
        let op = pred.prove_or(&right, &left);
        assert!(op.verify().is_err());
    }
}
