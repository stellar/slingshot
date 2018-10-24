use bulletproofs::r1cs::{Assignment, ConstraintSystem, Variable};
use curve25519_dalek::scalar::Scalar;
use gadgets::{merge, pad, range_proof, split, value_shuffle};
use subtle::ConstantTimeEq;
use util::{SpacesuitError, Value};

// Enforces that the outputs are a valid rearrangement of the inputs, following the
// soundness and secrecy requirements in the spacesuit spec.
// TODO: add padding for different input and output sizes. (currently assuming n = m)
pub fn fill_cs<CS: ConstraintSystem>(
    cs: &mut CS,
    inputs: Vec<Value>,
    merge_in: Vec<Value>,
    merge_mid: Vec<Value>,
    merge_out: Vec<Value>,
    split_in: Vec<Value>,
    split_mid: Vec<Value>,
    split_out: Vec<Value>,
    outputs: Vec<Value>,
) -> Result<(), SpacesuitError> {
    let m = inputs.len();
    let n = outputs.len();
    if inputs.len() != merge_in.len()
        || merge_in.len() != merge_out.len()
        || split_in.len() != split_out.len()
        || split_out.len() != outputs.len()
        || merge_mid.len() != m - 2
        || split_mid.len() != n - 2
    {
        return Err(SpacesuitError::InvalidR1CSConstruction);
    }

    // Shuffle 1
    // Group the inputs by flavor.
    // Choice -> Ordering conversion? seems wrong...
    // shuffle1_outputs.sort_by(|cur, next| cur.a.1.ct_eq(&next.a.1));
    value_shuffle::fill_cs(cs, inputs, merge_in)?;

    // Merge
    // Combine all the inputs of the same flavor. If different flavors, do not combine.

    // Shuffle 2

    // Split
    // Combine all the outputs of the same flavor. If different flavors, do not combine.

    // Shuffle 3
    // Group the outputs by flavor.
    value_shuffle::fill_cs(cs, split_out, outputs.clone())?;

    // Range Proof
    for output in outputs {
        range_proof::fill_cs(cs, output.q, 64)?;
    }

    Ok(())
}

pub fn make_commitments(
    inputs: Vec<(u64, u64, u64)>,
    outputs: Vec<(u64, u64, u64)>,
) -> (Vec<u64>, Vec<u64>, Vec<u64>, Vec<u64>, Vec<u64>, Vec<u64>) {
    let m = inputs.len();
    let n = outputs.len();
    let commitment_count = 2 * m + (m - 2) + 2 * n + (n - 2);
    let mut v = Vec::with_capacity(commitment_count);

    for i in 0..n {
        v.push(Scalar::from(inputs[i].0));
        v.push(Scalar::from(inputs[i].1));
        v.push(Scalar::from(inputs[i].2));
    }
    for i in 0..m {
        v.push(Scalar::from(outputs[i].0));
        v.push(Scalar::from(outputs[i].1));
        v.push(Scalar::from(outputs[i].2));
    }
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
        assert!(transaction_helper(vec![(1, 2, 3)], vec![(1, 2, 3)]).is_ok());
    }

    fn transaction_helper(
        inputs: Vec<(u64, u64, u64)>,
        outputs: Vec<(u64, u64, u64)>,
    ) -> Result<(), SpacesuitError> {
        // Common
        let pc_gens = PedersenGens::default();
        let bp_gens = BulletproofGens::new(128, 1);
        let m = inputs.len();
        let n = outputs.len();

        // Prover's scope
        let (proof, commitments) = {
            // Prover makes a `ConstraintSystem` instance representing a transaction gadget
            // Make v vector
            let v = transaction::make_commitments(inputs, outputs);

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
            let v_blinding: Vec<Scalar> = (0..v.len()).map(|_| Scalar::random(&mut rng)).collect();

            let (mut prover_cs, variables, commitments) =
                ProverCS::new(&bp_gens, &pc_gens, &mut prover_transcript, v, v_blinding);

            // Prover adds constraints to the constraint system
            let mut values = value_helper(variables, v);
            let output_vals = values.split_off(n);
            let split_out_vals = values.split_off(n);
            let split_mid_vals = values.split_off(n - 2);
            let split_in_vals = values.split_off(n);
            let merge_out_vals = values.split_off(m);
            let merge_mid_vals = values.split_off(m - 2);
            let merge_in_vals = values.split_off(m);
            let input_vals = values.split_off(m);

            fill_cs(
                &mut prover_cs,
                input_vals,
                merge_in_vals,
                merge_mid_vals,
                merge_out_vals,
                split_in_vals,
                split_mid_vals,
                split_out_vals,
                output_vals,
            )?;

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

    fn value_helper(variables: Vec<Variable>, scalars: Vec<Scalar>) -> Vec<Value> {
        let val_count = variables / 3;
        let mut vals = Vec::with_capacity(val_count);
        for i in 0..val_count {
            vals.push(Value {
                q: (variables[i * 3], Assignment::from(scalars[i * 3])),
                a: (variables[i * 3 + 1], Assignment::from(scalars[i * 3 + 1])),
                t: (variables[i * 3 + 2], Assignment::from(scalars[i * 3 + 2])),
            });
        }
        vals
    }
}
