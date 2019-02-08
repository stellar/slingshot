#[macro_use]
extern crate criterion;
use criterion::Criterion;

extern crate merlin;
use merlin::Transcript;

extern crate curve25519_dalek;
use curve25519_dalek::scalar::Scalar;

extern crate rand;
use rand::seq::SliceRandom;
use rand::{thread_rng, CryptoRng, Rng};

extern crate spacesuit;
use spacesuit::{cloak, CommittedValue, ProverCommittable, Value, VerifierCommittable};

extern crate bulletproofs;
use bulletproofs::r1cs::{Prover, R1CSError, R1CSProof, Verifier};
use bulletproofs::{BulletproofGens, PedersenGens};

fn prove<R: Rng + CryptoRng>(
    bp_gens: &BulletproofGens,
    pc_gens: &PedersenGens,
    inputs: &Vec<Value>,
    outputs: &Vec<Value>,
    rng: &mut R,
) -> Result<(R1CSProof, Vec<CommittedValue>, Vec<CommittedValue>), R1CSError>
where
    R: rand::RngCore,
{
    let mut prover_transcript = Transcript::new(b"TransactionTest");
    let mut prover = Prover::new(&bp_gens, &pc_gens, &mut prover_transcript);

    let (in_com, in_vars) = inputs.commit(&mut prover, rng);
    let (out_com, out_vars) = outputs.commit(&mut prover, rng);

    cloak(&mut prover, in_vars, out_vars)?;
    let proof = prover.prove()?;

    Ok((proof, in_com, out_com))
}

fn verify(
    bp_gens: &BulletproofGens,
    pc_gens: &PedersenGens,
    proof: &R1CSProof,
    in_com: &Vec<CommittedValue>,
    out_com: &Vec<CommittedValue>,
) -> Result<(), R1CSError> {
    // Verifier makes a `ConstraintSystem` instance representing a merge gadget
    let mut verifier_transcript = Transcript::new(b"TransactionTest");
    let mut verifier = Verifier::new(&bp_gens, &pc_gens, &mut verifier_transcript);

    let in_vars = in_com.commit(&mut verifier);
    let out_vars = out_com.commit(&mut verifier);

    assert!(cloak(&mut verifier, in_vars, out_vars,).is_ok());

    Ok(verifier.verify(&proof)?)
}

fn create_spacesuit_proof_helper(n: usize, c: &mut Criterion) {
    let label = format!("Spacesuit proof creation with {} inputs and outputs", n);

    c.bench_function(&label, move |b| {
        // Generate inputs and outputs to spacesuit prover
        let bp_gens = BulletproofGens::new(10000, 1);
        let pc_gens = PedersenGens::default();

        let mut rng = thread_rng();
        let (min, max) = (0u64, std::u64::MAX);
        let inputs: Vec<Value> = (0..n)
            .map(|_| Value {
                q: rng.gen_range(min, max).into(),
                f: Scalar::random(&mut rng),
            })
            .collect();
        let mut outputs = inputs.clone();
        let mut rng = thread_rng();
        outputs.shuffle(&mut rng);

        // Make spacesuit proof
        b.iter(|| {
            prove(&bp_gens, &pc_gens, &inputs, &outputs, &mut rng).unwrap();
        })
    });
}

fn create_spacesuit_proof_n_2(c: &mut Criterion) {
    create_spacesuit_proof_helper(2, c);
}

fn create_spacesuit_proof_n_8(c: &mut Criterion) {
    create_spacesuit_proof_helper(8, c);
}

fn create_spacesuit_proof_n_16(c: &mut Criterion) {
    create_spacesuit_proof_helper(16, c);
}

fn create_spacesuit_proof_n_32(c: &mut Criterion) {
    create_spacesuit_proof_helper(32, c);
}

fn create_spacesuit_proof_n_64(c: &mut Criterion) {
    create_spacesuit_proof_helper(64, c);
}

fn verify_spacesuit_proof_helper(n: usize, c: &mut Criterion) {
    let label = format!("Spacesuit proof verification with {} inputs and outputs", n);

    c.bench_function(&label, move |b| {
        // Generate inputs and outputs to spacesuit prover
        let bp_gens = BulletproofGens::new(10000, 1);
        let pc_gens = PedersenGens::default();

        let mut rng = thread_rng();
        let (min, max) = (0u64, std::u64::MAX);
        let inputs: Vec<Value> = (0..n)
            .map(|_| Value {
                q: rng.gen_range(min, max).into(),
                f: Scalar::random(&mut rng),
            })
            .collect();
        let mut outputs = inputs.clone();
        outputs.shuffle(&mut thread_rng());
        let mut rng = thread_rng();
        let (proof, tx_in_com, tx_out_com) =
            prove(&bp_gens, &pc_gens, &inputs, &outputs, &mut rng).unwrap();

        b.iter(|| {
            verify(&bp_gens, &pc_gens, &proof, &tx_in_com, &tx_out_com).unwrap();
        })
    });
}

fn verify_spacesuit_proof_n_2(c: &mut Criterion) {
    verify_spacesuit_proof_helper(2, c);
}

fn verify_spacesuit_proof_n_8(c: &mut Criterion) {
    verify_spacesuit_proof_helper(8, c);
}

fn verify_spacesuit_proof_n_16(c: &mut Criterion) {
    verify_spacesuit_proof_helper(16, c);
}

fn verify_spacesuit_proof_n_32(c: &mut Criterion) {
    verify_spacesuit_proof_helper(32, c);
}

fn verify_spacesuit_proof_n_64(c: &mut Criterion) {
    verify_spacesuit_proof_helper(64, c);
}

criterion_group! {
    name = create_spacesuit_proof;
    config = Criterion::default().sample_size(10);
    targets = create_spacesuit_proof_n_2,
        create_spacesuit_proof_n_8,
        create_spacesuit_proof_n_16,
        create_spacesuit_proof_n_32,
        create_spacesuit_proof_n_64,
}

criterion_group! {
    name = verify_spacesuit_proof;
    config = Criterion::default().sample_size(10);
    targets = verify_spacesuit_proof_n_2,
        verify_spacesuit_proof_n_8,
        verify_spacesuit_proof_n_16,
        verify_spacesuit_proof_n_32,
        verify_spacesuit_proof_n_64,
}

criterion_main!(create_spacesuit_proof, verify_spacesuit_proof);
