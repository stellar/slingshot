use bulletproofs::r1cs::{Assignment, ConstraintSystem, Variable};
use curve25519_dalek::scalar::Scalar;
use gadgets::{merge, pad, range_proof, split, value_shuffle};
use util::{SpacesuitError, Value};

// Enforces that the outputs are a valid rearrangement of the inputs, following the
// soundness and secrecy requirements in the spacesuit spec.
pub fn fill_cs<CS: ConstraintSystem>(
    cs: &mut CS,
    inputs: Vec<Value>,
    outputs: Vec<Value>,
) -> Result<(), SpacesuitError> {
    // Shuffle 1
    // Group the inputs by flavor.

    // Merge
    // Combine all the inputs of the same flavor. If different flavors, do not combine.

    // Pad?
    // Shuffle 2
    // Pad?

    // Split
    // Combine all the outputs of the same flavor. If different flavors, do not combine.

    // Shuffle 3
    // Group the outputs by flavor.

    // Range Proof
    unimplemented!();
}

#[cfg(test)]
mod tests {
    use super::*;
    use bulletproofs::r1cs::{Assignment, ProverCS, VerifierCS};
    use bulletproofs::{BulletproofGens, PedersenGens};
    use merlin::Transcript;

    #[test]
    fn transaction() {
        // k=1
        assert!(transaction_helper(vec![(1, 2, 3)], vec![(1, 2, 3)]).is_ok());
        assert!(transaction_helper(vec![(4, 5, 6)], vec![(4, 5, 6)]).is_ok());
        assert!(transaction_helper(vec![(1, 2, 3)], vec![(4, 5, 6)]).is_err());
        // k=2
        assert!(transaction_helper(vec![(1, 2, 3), (4, 5, 6)], vec![(1, 2, 3), (4, 5, 6)]).is_ok());
        assert!(transaction_helper(vec![(1, 2, 3), (4, 5, 6)], vec![(4, 5, 6), (1, 2, 3)]).is_ok());
        assert!(transaction_helper(vec![(4, 5, 6), (4, 5, 6)], vec![(4, 5, 6), (4, 5, 6)]).is_ok());
        assert!(
            transaction_helper(vec![(1, 2, 3), (1, 2, 3)], vec![(4, 5, 6), (1, 2, 3)]).is_err()
        );
        assert!(transaction_helper(vec![(1, 2, 3), (4, 5, 6)], vec![(1, 2, 3), (4, 5, 6)]).is_ok());
        // k=3
        assert!(
            transaction_helper(
                vec![(1, 2, 3), (4, 5, 6), (8, 9, 10)],
                vec![(1, 2, 3), (4, 5, 6), (8, 9, 10)]
            ).is_ok()
        );
        assert!(
            transaction_helper(
                vec![(1, 2, 3), (4, 5, 6), (8, 9, 10)],
                vec![(1, 2, 3), (8, 9, 10), (4, 5, 6)]
            ).is_ok()
        );
        assert!(
            transaction_helper(
                vec![(1, 2, 3), (4, 5, 6), (8, 9, 10)],
                vec![(4, 5, 6), (1, 2, 3), (8, 9, 10)]
            ).is_ok()
        );
        assert!(
            transaction_helper(
                vec![(1, 2, 3), (4, 5, 6), (8, 9, 10)],
                vec![(4, 5, 6), (8, 9, 10), (1, 2, 3)]
            ).is_ok()
        );
        assert!(
            transaction_helper(
                vec![(1, 2, 3), (4, 5, 6), (8, 9, 10)],
                vec![(8, 9, 10), (1, 2, 3), (4, 5, 6)]
            ).is_ok()
        );
        assert!(
            transaction_helper(
                vec![(1, 2, 3), (4, 5, 6), (8, 9, 10)],
                vec![(8, 9, 10), (4, 5, 6), (1, 2, 3)]
            ).is_ok()
        );
        assert!(
            transaction_helper(
                vec![(1, 2, 3), (4, 5, 6), (8, 9, 10)],
                vec![(10, 20, 30), (4, 5, 6), (8, 9, 10)]
            ).is_err()
        );
        assert!(
            transaction_helper(
                vec![(1, 2, 3), (4, 5, 6), (8, 9, 10)],
                vec![(1, 2, 3), (40, 50, 60), (8, 9, 10)]
            ).is_err()
        );
        assert!(
            transaction_helper(
                vec![(1, 2, 3), (4, 5, 6), (8, 9, 10)],
                vec![(1, 2, 3), (4, 5, 6), (98, 99, 100)]
            ).is_err()
        );
    }

    fn transaction_helper(
        inputs: Vec<(u64, u64, u64)>,
        outputs: Vec<(u64, u64, u64)>,
    ) -> Result<(), SpacesuitError> {
        // Common
        let pc_gens = PedersenGens::default();
        let bp_gens = BulletproofGens::new(128, 1);
        let k = inputs.len(); // TODO: allow different input and output lengths

        // Prover's scope
        let (proof, commitments) = {
            // Prover makes a `ConstraintSystem` instance representing a transaction gadget
            // Make v vector
            let mut v = Vec::with_capacity(6 * k);
            for i in 0..k {
                v.push(Scalar::from(inputs[i].0));
                v.push(Scalar::from(inputs[i].1));
                v.push(Scalar::from(inputs[i].2));
                v.push(Scalar::from(outputs[i].0));
                v.push(Scalar::from(outputs[i].1));
                v.push(Scalar::from(outputs[i].2));
            }

            // Make v_blinding vector using RNG from transcript
            let mut prover_transcript = Transcript::new(b"TransactionTest");
            let mut rng = {
                let mut builder = prover_transcript.build_rng();

                // commit the secret values
                for &v_i in &v {
                    builder = builder.commit_witness_bytes(b"v_i", v_i.as_bytes());
                }

                use rand::thread_rng;
                builder.finalize(&mut thread_rng())
            };
            let v_blinding: Vec<Scalar> = (0..6 * k).map(|_| Scalar::random(&mut rng)).collect();

            let (mut prover_cs, variables, commitments) = ProverCS::new(
                &bp_gens,
                &pc_gens,
                &mut prover_transcript,
                v,
                v_blinding.clone(),
            );

            // Prover adds constraints to the constraint system
            let mut input_vals = Vec::with_capacity(k);
            let mut output_vals = Vec::with_capacity(k);
            for i in 0..k {
                let in_q = variables[i * 6 + 0];
                let in_a = variables[i * 6 + 1];
                let in_t = variables[i * 6 + 2];
                let out_q = variables[i * 6 + 3];
                let out_a = variables[i * 6 + 4];
                let out_t = variables[i * 6 + 5];

                input_vals.push(Value {
                    q: (in_q, Assignment::from(inputs[i].0)),
                    a: (in_a, Assignment::from(inputs[i].1)),
                    t: (in_t, Assignment::from(inputs[i].2)),
                });
                output_vals.push(Value {
                    q: (out_q, Assignment::from(outputs[i].0)),
                    a: (out_a, Assignment::from(outputs[i].1)),
                    t: (out_t, Assignment::from(outputs[i].2)),
                });
            }
            fill_cs(&mut prover_cs, input_vals, output_vals)?;

            let proof = prover_cs.prove()?;

            (proof, commitments)
        };

        // Verifier makes a `ConstraintSystem` instance representing a merge gadget
        let mut verifier_transcript = Transcript::new(b"TransactionTest");
        let (mut verifier_cs, variables) =
            VerifierCS::new(&bp_gens, &pc_gens, &mut verifier_transcript, commitments);

        // Verifier allocates variables and adds constraints to the constraint system
        let mut input_vals = Vec::with_capacity(k);
        let mut output_vals = Vec::with_capacity(k);
        for i in 0..k {
            let in_q = variables[i * 6 + 0];
            let in_a = variables[i * 6 + 1];
            let in_t = variables[i * 6 + 2];
            let out_q = variables[i * 6 + 3];
            let out_a = variables[i * 6 + 4];
            let out_t = variables[i * 6 + 5];

            input_vals.push(Value {
                q: (in_q, Assignment::Missing()),
                a: (in_a, Assignment::Missing()),
                t: (in_t, Assignment::Missing()),
            });
            output_vals.push(Value {
                q: (out_q, Assignment::Missing()),
                a: (out_a, Assignment::Missing()),
                t: (out_t, Assignment::Missing()),
            });
        }

        assert!(fill_cs(&mut verifier_cs, input_vals, output_vals).is_ok());

        Ok(verifier_cs.verify(&proof)?)
    }
}
