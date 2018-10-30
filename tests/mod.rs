extern crate spacesuit;
use spacesuit::util::SpacesuitError;
use spacesuit::*;

extern crate bulletproofs;
use bulletproofs::r1cs::{Assignment, ProverCS, VerifierCS};
use bulletproofs::{BulletproofGens, PedersenGens};

extern crate curve25519_dalek;
use curve25519_dalek::scalar::Scalar;

extern crate merlin;
use merlin::Transcript;

extern crate rand;

fn transaction_helper(
    inputs: Vec<(Scalar, Scalar, Scalar)>,
    outputs: Vec<(Scalar, Scalar, Scalar)>,
) -> Result<(), SpacesuitError> {
    // Common
    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(10000, 1);
    let m = inputs.len();
    let n = outputs.len();

    // Prover's scope
    let (proof, commitments) = {
        // Prover makes a `ConstraintSystem` instance representing a transaction gadget
        // Make v vector
        let v = transaction::compute_intermediate_values(inputs, outputs)?;

        // Make v_blinding vector using RNG from transcript
        let mut prover_transcript = Transcript::new(b"TransactionTest");
        let mut rng = {
            let mut builder = prover_transcript.build_rng();

            // Commit the secret values
            for &v_i in &v {
                builder = builder.commit_witness_bytes(b"v_i", v_i.as_bytes());
            }
            use rand::thread_rng;
            builder.finalize(&mut thread_rng())
        };
        let v_blinding: Vec<Scalar> = (0..v.len()).map(|_| Scalar::random(&mut rng)).collect();

        let (mut prover_cs, variables, commitments) = ProverCS::new(
            &bp_gens,
            &pc_gens,
            &mut prover_transcript,
            v.clone(),
            v_blinding,
        );

        // Prover adds constraints to the constraint system
        let v_assignments = v.iter().map(|v_i| Assignment::from(*v_i)).collect();
        let (inp, m_i, m_m, m_o, s_i, s_m, s_o, out) =
            transaction::value_helper(variables, v_assignments, m, n);

        transaction::fill_cs(&mut prover_cs, inp, m_i, m_m, m_o, s_i, s_m, s_o, out)?;
        let proof = prover_cs.prove()?;

        (proof, commitments)
    };

    // Verifier makes a `ConstraintSystem` instance representing a merge gadget
    let mut verifier_transcript = Transcript::new(b"TransactionTest");
    let (mut verifier_cs, variables) =
        VerifierCS::new(&bp_gens, &pc_gens, &mut verifier_transcript, commitments);

    // Verifier allocates variables and adds constraints to the constraint system
    let v_assignments = vec![Assignment::Missing(); variables.len()];
    let (inp, m_i, m_m, m_o, s_i, s_m, s_o, out) =
        transaction::value_helper(variables, v_assignments, m, n);

    assert!(transaction::fill_cs(&mut verifier_cs, inp, m_i, m_m, m_o, s_i, s_m, s_o, out).is_ok());

    Ok(verifier_cs.verify(&proof)?)
}

// Helper functions to make the tests easier to read
fn yuan(val: u64) -> (Scalar, Scalar, Scalar) {
    (
        Scalar::from(val),
        Scalar::from(888u64),
        Scalar::from(999u64),
    )
}
fn peso(val: u64) -> (Scalar, Scalar, Scalar) {
    (
        Scalar::from(val),
        Scalar::from(666u64),
        Scalar::from(777u64),
    )
}
fn euro(val: u64) -> (Scalar, Scalar, Scalar) {
    (
        Scalar::from(val),
        Scalar::from(444u64),
        Scalar::from(555u64),
    )
}
fn zero() -> (Scalar, Scalar, Scalar) {
    (Scalar::zero(), Scalar::zero(), Scalar::zero())
}

// m=1, n=1
#[test]
fn transaction_1_1() {
    assert!(transaction_helper(vec![yuan(1)], vec![yuan(1)]).is_ok());
    assert!(transaction_helper(vec![peso(4)], vec![peso(4)]).is_ok());
    assert!(transaction_helper(vec![yuan(1)], vec![peso(4)]).is_err());
}

// max(m, n) = 2
#[test]
fn transaction_uneven_2() {
    assert!(transaction_helper(vec![yuan(3)], vec![yuan(1), yuan(2)]).is_ok());
    assert!(transaction_helper(vec![yuan(1), yuan(2)], vec![yuan(3)]).is_ok());
}

// m=2, n=2
#[test]
fn transaction_2_2() {
    // Only shuffle (all different flavors)
    assert!(transaction_helper(vec![yuan(1), peso(4)], vec![yuan(1), peso(4)]).is_ok());
    assert!(transaction_helper(vec![yuan(1), peso(4)], vec![peso(4), yuan(1)]).is_ok());

    // Middle shuffle & merge & split (has multiple inputs or outputs of same flavor)
    assert!(transaction_helper(vec![peso(4), peso(4)], vec![peso(4), peso(4)]).is_ok());
    assert!(transaction_helper(vec![peso(5), peso(3)], vec![peso(5), peso(3)]).is_ok());
    assert!(transaction_helper(vec![peso(5), peso(3)], vec![peso(1), peso(7)]).is_ok());
    assert!(transaction_helper(vec![peso(1), peso(8)], vec![peso(0), peso(9)]).is_ok());
    assert!(transaction_helper(vec![yuan(1), yuan(1)], vec![peso(4), yuan(1)]).is_err());
}

// m=3, n=3
#[test]
fn transaction_3_3() {
    // Only shuffle
    assert!(
        transaction_helper(
            vec![yuan(1), peso(4), euro(8)],
            vec![yuan(1), peso(4), euro(8)]
        ).is_ok()
    );
    assert!(
        transaction_helper(
            vec![yuan(1), peso(4), euro(8)],
            vec![yuan(1), euro(8), peso(4)]
        ).is_ok()
    );
    assert!(
        transaction_helper(
            vec![yuan(1), peso(4), euro(8)],
            vec![peso(4), yuan(1), euro(8)]
        ).is_ok()
    );
    assert!(
        transaction_helper(
            vec![yuan(1), peso(4), euro(8)],
            vec![peso(4), euro(8), yuan(1)]
        ).is_ok()
    );
    assert!(
        transaction_helper(
            vec![yuan(1), peso(4), euro(8)],
            vec![euro(8), yuan(1), peso(4)]
        ).is_ok()
    );
    assert!(
        transaction_helper(
            vec![yuan(1), peso(4), euro(8)],
            vec![euro(8), peso(4), yuan(1)]
        ).is_ok()
    );
    assert!(
        transaction_helper(
            vec![yuan(1), peso(4), euro(8)],
            vec![yuan(2), peso(4), euro(8)]
        ).is_err()
    );
    assert!(
        transaction_helper(
            vec![yuan(1), peso(4), euro(8)],
            vec![yuan(1), euro(4), euro(8)]
        ).is_err()
    );
    assert!(
        transaction_helper(
            vec![yuan(1), peso(4), euro(8)],
            vec![yuan(1), peso(4), euro(9)]
        ).is_err()
    );

    // Middle shuffle & merge & split
    assert!(
        transaction_helper(
            vec![yuan(1), yuan(1), peso(4)],
            vec![yuan(1), yuan(1), peso(4)]
        ).is_ok()
    );
    assert!(
        transaction_helper(
            vec![yuan(4), yuan(3), peso(4)],
            vec![yuan(2), yuan(5), peso(4)]
        ).is_ok()
    );
    assert!(
        transaction_helper(
            vec![yuan(4), yuan(3), peso(4)],
            vec![peso(4), yuan(2), yuan(5)]
        ).is_ok()
    );
    assert!(
        transaction_helper(
            vec![yuan(1), yuan(2), yuan(5)],
            vec![yuan(4), yuan(3), yuan(1)]
        ).is_ok()
    );
    assert!(
        transaction_helper(
            vec![yuan(1), yuan(2), yuan(5)],
            vec![yuan(4), yuan(3), yuan(10)]
        ).is_err()
    );

    // End shuffles & merge & split & middle shuffle
    // (multiple asset types that need to be grouped and merged or split)
    assert!(
        transaction_helper(
            vec![yuan(1), peso(4), yuan(1)],
            vec![yuan(1), yuan(1), peso(4)]
        ).is_ok()
    );
    assert!(
        transaction_helper(
            vec![yuan(4), peso(4), yuan(3)],
            vec![peso(3), yuan(7), peso(1)]
        ).is_ok()
    );
}

// max(m, n) = 3
#[test]
fn transaction_uneven_3() {
    assert!(transaction_helper(vec![yuan(4), yuan(4), yuan(3)], vec![yuan(11)]).is_ok());
    assert!(transaction_helper(vec![yuan(11)], vec![yuan(4), yuan(4), yuan(3)],).is_ok());
    assert!(transaction_helper(vec![yuan(11), peso(4)], vec![yuan(4), yuan(7), peso(4)],).is_ok());
    assert!(transaction_helper(vec![yuan(4), yuan(7), peso(4)], vec![yuan(11), peso(4)],).is_ok());
    assert!(transaction_helper(vec![yuan(5), yuan(6)], vec![yuan(4), yuan(4), yuan(3)],).is_ok());
    assert!(transaction_helper(vec![yuan(4), yuan(4), yuan(3)], vec![yuan(5), yuan(6)],).is_ok());
}

// m=4, n=4
#[test]
fn transaction_4_4() {
    // Only shuffle
    assert!(
        transaction_helper(
            vec![yuan(1), peso(4), euro(7), euro(10)],
            vec![yuan(1), peso(4), euro(7), euro(10)]
        ).is_ok()
    );
    assert!(
        transaction_helper(
            vec![yuan(1), peso(4), euro(7), euro(10)],
            vec![euro(7), yuan(1), euro(10), peso(4),]
        ).is_ok()
    );

    // Middle shuffle & merge & split
    assert!(
        transaction_helper(
            vec![yuan(1), yuan(1), peso(4), peso(4)],
            vec![yuan(1), yuan(1), peso(4), peso(4)]
        ).is_ok()
    );
    assert!(
        transaction_helper(
            vec![yuan(4), yuan(3), peso(4), peso(4)],
            vec![yuan(2), yuan(5), peso(1), peso(7)]
        ).is_ok()
    );
    assert!(
        transaction_helper(
            vec![yuan(4), yuan(3), peso(4), peso(4)],
            vec![peso(1), peso(7), yuan(2), yuan(5)]
        ).is_ok()
    );
    assert!(
        transaction_helper(
            vec![yuan(1), yuan(1), yuan(5), yuan(2)],
            vec![yuan(1), yuan(1), yuan(5), yuan(2)]
        ).is_ok()
    );
    assert!(
        transaction_helper(
            vec![yuan(1), yuan(2), yuan(5), yuan(2)],
            vec![yuan(4), yuan(3), yuan(3), zero()]
        ).is_ok()
    );
    assert!(
        transaction_helper(
            vec![yuan(1), yuan(2), yuan(5), yuan(2)],
            vec![yuan(4), yuan(3), yuan(3), yuan(20)]
        ).is_err()
    );

    // End shuffles & merge & split & middle shuffle
    assert!(
        transaction_helper(
            vec![yuan(1), peso(4), yuan(1), peso(4)],
            vec![peso(4), yuan(1), yuan(1), peso(4)]
        ).is_ok()
    );
    assert!(
        transaction_helper(
            vec![yuan(4), peso(4), peso(4), yuan(3)],
            vec![peso(1), yuan(2), yuan(5), peso(7)]
        ).is_ok()
    );
    assert!(
        transaction_helper(
            vec![yuan(10), peso(1), peso(2), peso(3)],
            vec![yuan(5), yuan(4), yuan(1), peso(6)]
        ).is_ok()
    );
}
