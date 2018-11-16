use super::scalar_shuffle;
use bulletproofs::r1cs::ConstraintSystem;
use curve25519_dalek::scalar::Scalar;
use error::SpacesuitError;
use value::AllocatedValue;

/// Enforces that the output values `y` are a valid reordering of the inputs values `x`.
/// The inputs and outputs are all of the `AllocatedValue` type, which contains the fields
/// quantity, issuer, and tag. Works for `k` inputs and `k` outputs.
pub fn fill_cs<CS: ConstraintSystem>(
    cs: &mut CS,
    x: Vec<AllocatedValue>,
    y: Vec<AllocatedValue>,
) -> Result<(), SpacesuitError> {
    let one = Scalar::one();

    if x.len() != y.len() {
        return Err(SpacesuitError::InvalidR1CSConstruction);
    }
    let k = x.len();
    if k == 1 {
        let x = x[0];
        let y = y[0];
        cs.constrain(y.q - x.q);
        cs.constrain(y.a - x.a);
        cs.constrain(y.t - x.t);
        return Ok(());
    }

    let w = cs.challenge_scalar(b"k-value shuffle challenge");
    let w2 = w * w;
    let mut x_scalars = Vec::with_capacity(k);
    let mut y_scalars = Vec::with_capacity(k);
    for i in 0..k {
        let (x_i_var, y_i_var, _) = cs.multiply(
            x[i].q + x[i].a * w + x[i].t * w2,
            y[i].q + y[i].a * w + y[i].t * w2
        );

        x_scalars.push(x_i_var);
        y_scalars.push(y_i_var);
    }
    Ok(scalar_shuffle::fill_cs(cs, &x_scalars, &y_scalars))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ::value::SecretValue;
    use bulletproofs::r1cs::{ProverCS, VerifierCS,Variable};
    use bulletproofs::{BulletproofGens, PedersenGens};
    use merlin::Transcript;

    // Helper functions to make the tests easier to read
    fn yuan(q: u64) -> SecretValue {
        SecretValue {
            q,
            a: 888u64.into(),
            t: 999u64.into(),
        }
    }
    fn peso(q: u64) -> SecretValue {
        SecretValue {
            q,
            a: 666u64.into(),
            t: 777u64.into(),
        }
    }
    fn euro(q: u64) -> SecretValue {
        SecretValue {
            q,
            a: 444u64.into(),
            t: 555u64.into(),
        }
    }
    fn wrong() -> SecretValue {
        SecretValue {
            q: 9991u64,
            a: 9992u64.into(),
            t: 9993u64.into(),
        }
    }

    #[test]
    fn value_shuffle() {
        // k=1
        assert!(value_shuffle_helper(vec![peso(1)], vec![peso(1)]).is_ok());
        assert!(value_shuffle_helper(vec![yuan(4)], vec![yuan(4)]).is_ok());
        assert!(value_shuffle_helper(vec![peso(1)], vec![yuan(4)]).is_err());
        // k=2
        assert!(value_shuffle_helper(vec![peso(1), yuan(4)], vec![peso(1), yuan(4)]).is_ok());
        assert!(value_shuffle_helper(vec![peso(1), yuan(4)], vec![yuan(4), peso(1)]).is_ok());
        assert!(value_shuffle_helper(vec![yuan(4), yuan(4)], vec![yuan(4), yuan(4)]).is_ok());
        assert!(value_shuffle_helper(vec![peso(1), peso(1)], vec![yuan(4), peso(1)]).is_err());
        assert!(value_shuffle_helper(vec![peso(1), yuan(4)], vec![peso(1), yuan(4)]).is_ok());
        // k=3
        assert!(
            value_shuffle_helper(
                vec![peso(1), yuan(4), euro(8)],
                vec![peso(1), yuan(4), euro(8)]
            )
            .is_ok()
        );
        assert!(
            value_shuffle_helper(
                vec![peso(1), yuan(4), euro(8)],
                vec![peso(1), euro(8), yuan(4)]
            )
            .is_ok()
        );
        assert!(
            value_shuffle_helper(
                vec![peso(1), yuan(4), euro(8)],
                vec![yuan(4), peso(1), euro(8)]
            )
            .is_ok()
        );
        assert!(
            value_shuffle_helper(
                vec![peso(1), yuan(4), euro(8)],
                vec![yuan(4), euro(8), peso(1)]
            )
            .is_ok()
        );
        assert!(
            value_shuffle_helper(
                vec![peso(1), yuan(4), euro(8)],
                vec![euro(8), peso(1), yuan(4)]
            )
            .is_ok()
        );
        assert!(
            value_shuffle_helper(
                vec![peso(1), yuan(4), euro(8)],
                vec![euro(8), yuan(4), peso(1)]
            )
            .is_ok()
        );
        assert!(
            value_shuffle_helper(
                vec![peso(1), yuan(4), euro(8)],
                vec![wrong(), yuan(4), euro(8)]
            )
            .is_err()
        );
        assert!(
            value_shuffle_helper(
                vec![peso(1), yuan(4), euro(8)],
                vec![peso(1), wrong(), euro(8)]
            )
            .is_err()
        );
        assert!(
            value_shuffle_helper(
                vec![peso(1), yuan(4), euro(8)],
                vec![peso(1), yuan(4), wrong()]
            )
            .is_err()
        );
        assert!(
            value_shuffle_helper(
                vec![
                    SecretValue {
                        q: 0,
                        a: 0u64.into(),
                        t: 0u64.into(),
                    }
                ],
                vec![
                    SecretValue {
                        q: 0,
                        a: 0u64.into(),
                        t: 1u64.into(),
                    }
                ]
            ).is_err()
        );
    }

    fn value_shuffle_helper(
        input: Vec<SecretValue>,
        output: Vec<SecretValue>,
    ) -> Result<(), SpacesuitError> {
        // Common
        let pc_gens = PedersenGens::default();
        let bp_gens = BulletproofGens::new(128, 1);

        // Prover's scope
        let (proof, commitments) = {
            let mut values = input.clone();
            values.append(&mut output.clone());

            let v: Vec<Scalar> = values.iter().fold(
                Vec::new(),
                |vec, value|{
                    vec.push(value.q.into());
                    vec.push(value.a);
                    vec.push(value.t);
                    vec
            });
            let v_blinding: Vec<Scalar> = (0..v.len()).map(|_| {
                Scalar::random(&mut rand::thread_rng())
            }).collect();

            let mut prover_transcript = Transcript::new(b"ValueShuffleTest");
            let (mut prover_cs, variables, commitments) = ProverCS::new(
                &bp_gens,
                &pc_gens,
                &mut prover_transcript,
                v,
                v_blinding.clone(),
            );

            let (ins,outs) = organize_values(variables, &Some(values));
            assert!(fill_cs(&mut prover_cs, ins, outs).is_ok());
            let proof = prover_cs.prove()?;

            (proof, commitments)
        };

        // Verifier makes a `ConstraintSystem` instance representing a shuffle gadget
        let mut verifier_transcript = Transcript::new(b"ValueShuffleTest");
        let (mut verifier_cs, variables) =
            VerifierCS::new(&bp_gens, &pc_gens, &mut verifier_transcript, commitments);

        let (ins,outs) = organize_values(variables, &None);

        assert!(fill_cs(&mut verifier_cs, ins, outs).is_ok());

        // Verifier verifies proof
        Ok(verifier_cs.verify(&proof)?)
    }

    fn organize_values(
        variables: Vec<Variable>,
        assignments: &Option<Vec<SecretValue>>,
    ) -> (Vec<AllocatedValue>, Vec<AllocatedValue>) {
        let n = (variables.len() / 3) / 2;

        let mut inputs: Vec<AllocatedValue> = Vec::with_capacity(n);
        let mut outputs: Vec<AllocatedValue> = Vec::with_capacity(n);
        for i in 0..n {
            inputs.push(AllocatedValue {
                q: variables[i * 3],
                a: variables[i * 3 + 1],
                t: variables[i * 3 + 2],
                assignment: assignments.map(|a| a[i])
            });
            outputs.push(AllocatedValue {
                q: variables[(i + n) * 3],
                a: variables[(i + n) * 3 + 1],
                t: variables[(i + n) * 3 + 2],
                assignment: assignments.map(|a| a[i+n])
            });
        }

        (inputs, outputs)
    }
}
