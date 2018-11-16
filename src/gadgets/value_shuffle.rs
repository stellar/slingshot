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
        )?;

        x_scalars.push(x_i_var);
        y_scalars.push(y_i_var);
    }
    scalar_shuffle::fill_cs(cs, x_scalars, y_scalars)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bulletproofs::r1cs::{ProverCS, VerifierCS};
    use bulletproofs::{BulletproofGens, PedersenGens};
    use merlin::Transcript;

    // Helper functions to make the tests easier to read
    fn yuan(val: u64) -> (u64, u64, u64) {
        (val, 888, 999)
    }
    fn peso(val: u64) -> (u64, u64, u64) {
        (val, 666, 777)
    }
    fn euro(val: u64) -> (u64, u64, u64) {
        (val, 444, 555)
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
                vec![(10, 20, 30), yuan(4), euro(8)]
            )
            .is_err()
        );
        assert!(
            value_shuffle_helper(
                vec![peso(1), yuan(4), euro(8)],
                vec![peso(1), (40, 50, 60), euro(8)]
            )
            .is_err()
        );
        assert!(
            value_shuffle_helper(
                vec![peso(1), yuan(4), euro(8)],
                vec![peso(1), yuan(4), (98, 99, 100)]
            )
            .is_err()
        );
        assert!(value_shuffle_helper(vec![(0, 0, 0)], vec![(0, 0, 1)]).is_err());
    }

    fn value_shuffle_helper(
        input: Vec<(u64, u64, u64)>,
        output: Vec<(u64, u64, u64)>,
    ) -> Result<(), SpacesuitError> {
        // Common
        let pc_gens = PedersenGens::default();
        let bp_gens = BulletproofGens::new(128, 1);

        // Prover's scope
        let (proof, commitments) = {
            // Prover makes a `ConstraintSystem` instance representing a shuffle gadget
            // v and v_blinding empty because we are only testing low-level variable constraints
            let v = vec![];
            let v_blinding = vec![];
            let mut prover_transcript = Transcript::new(b"ValueShuffleTest");
            let (mut prover_cs, _variables, commitments) = ProverCS::new(
                &bp_gens,
                &pc_gens,
                &mut prover_transcript,
                v,
                v_blinding.clone(),
            );

            // Prover allocates variables and adds constraints to the constraint system
            let in_assignments = input
                .iter()
                .map(|in_i| {
                    (
                        Assignment::from(in_i.0.clone()),
                        Assignment::from(in_i.1.clone()),
                        Assignment::from(in_i.2.clone()),
                    )
                })
                .collect();
            let out_assignments = output
                .iter()
                .map(|out_i| {
                    (
                        Assignment::from(out_i.0.clone()),
                        Assignment::from(out_i.1.clone()),
                        Assignment::from(out_i.2.clone()),
                    )
                })
                .collect();
            value_shuffle_cs(&mut prover_cs, in_assignments, out_assignments)?;
            let proof = prover_cs.prove()?;

            (proof, commitments)
        };

        // Verifier makes a `ConstraintSystem` instance representing a shuffle gadget
        let mut verifier_transcript = Transcript::new(b"ValueShuffleTest");
        let (mut verifier_cs, _variables) =
            VerifierCS::new(&bp_gens, &pc_gens, &mut verifier_transcript, commitments);

        // Verifier allocates variables and adds constraints to the constraint system
        let in_assignments = input
            .iter()
            .map(|_| {
                (
                    Assignment::Missing(),
                    Assignment::Missing(),
                    Assignment::Missing(),
                )
            })
            .collect();
        let out_assignments = output
            .iter()
            .map(|_| {
                (
                    Assignment::Missing(),
                    Assignment::Missing(),
                    Assignment::Missing(),
                )
            })
            .collect();
        assert!(value_shuffle_cs(&mut verifier_cs, in_assignments, out_assignments,).is_ok());
        // Verifier verifies proof
        Ok(verifier_cs.verify(&proof)?)
    }

    fn value_shuffle_cs<CS: ConstraintSystem>(
        cs: &mut CS,
        input: Vec<(Assignment, Assignment, Assignment)>,
        output: Vec<(Assignment, Assignment, Assignment)>,
    ) -> Result<(), SpacesuitError> {
        if input.len() != output.len() {
            return Err(SpacesuitError::InvalidR1CSConstruction);
        }
        let k = input.len();
        let mut in_vals = Vec::with_capacity(k);
        let mut out_vals = Vec::with_capacity(k);

        // Allocate pairs of low-level variables and their assignments
        for i in 0..k {
            let (in_q, out_q) = cs.assign_uncommitted(input[i].0, output[i].0)?;
            let (in_a, out_a) = cs.assign_uncommitted(input[i].1, output[i].1)?;
            let (in_t, out_t) = cs.assign_uncommitted(input[i].2, output[i].2)?;
            in_vals.push(Value {
                q: (in_q, input[i].0),
                a: (in_a, input[i].1),
                t: (in_t, input[i].2),
            });
            out_vals.push(Value {
                q: (out_q, output[i].0),
                a: (out_a, output[i].1),
                t: (out_t, output[i].2),
            });
        }

        fill_cs(cs, in_vals, out_vals)
    }
}
