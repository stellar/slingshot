#![allow(non_snake_case)]

use bulletproofs::r1cs::{Prover, R1CSError, R1CSProof, Verifier};
use bulletproofs::{BulletproofGens, PedersenGens};
use gadgets::transaction;
use merlin::Transcript;
use rand::{CryptoRng, Rng};
use value::{CommittedValue, ProverCommittable, Value, VerifierCommittable};

pub struct SpacesuitProof(R1CSProof);

pub fn prove<R: Rng + CryptoRng>(
    bp_gens: &BulletproofGens,
    pc_gens: &PedersenGens,
    inputs: &Vec<Value>,
    outputs: &Vec<Value>,
    rng: &mut R,
) -> Result<(SpacesuitProof, Vec<CommittedValue>, Vec<CommittedValue>), R1CSError>
where
    R: rand::RngCore,
{
    let mut prover_transcript = Transcript::new(b"TransactionTest");
    let mut prover = Prover::new(&bp_gens, &pc_gens, &mut prover_transcript);

    let (in_com, in_vars) = inputs.commit(&mut prover, rng);
    let (out_com, out_vars) = outputs.commit(&mut prover, rng);

    transaction::fill_cs(&mut prover, in_vars, out_vars)?;
    let proof = SpacesuitProof(prover.prove()?);

    Ok((proof, in_com, out_com))
}

pub fn verify(
    bp_gens: &BulletproofGens,
    pc_gens: &PedersenGens,
    proof: &SpacesuitProof,
    in_com: &Vec<CommittedValue>,
    out_com: &Vec<CommittedValue>,
) -> Result<(), R1CSError> {
    // Verifier makes a `ConstraintSystem` instance representing a merge gadget
    let mut verifier_transcript = Transcript::new(b"TransactionTest");
    let mut verifier = Verifier::new(&bp_gens, &pc_gens, &mut verifier_transcript);

    let in_vars = in_com.commit(&mut verifier);
    let out_vars = out_com.commit(&mut verifier);

    assert!(transaction::fill_cs(&mut verifier, in_vars, out_vars,).is_ok());

    Ok(verifier.verify(&proof.0)?)
}
