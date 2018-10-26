#![allow(non_snake_case)]

use super::mix;
use bulletproofs::r1cs::ConstraintSystem;
use curve25519_dalek::scalar::Scalar;
use subtle::{ConditionallySelectable, ConstantTimeEq};
use util::{SpacesuitError, Value};

/// NOTE: this version of k-mix is not secure because it creates intermediate variables
/// that are not committed, therefore a malicious prover could choose the intermediate
/// variables in such a way that they cancel out the (predicatable) challenge value.
/// This would be fixed in the future with a "Bulletproofs++" which binds the challenge 
/// value to the intermediate variables as well. The discussion for that is here:
/// https://github.com/dalek-cryptography/bulletproofs/issues/186
///
/// Enforces that the outputs are either a merge of the inputs: `D = A + B && C = 0`,
/// or the outputs are equal to the inputs `C = A && D = B`. See spec for more details.
/// Works for `k` inputs and `k` outputs.
pub fn fill_cs<CS: ConstraintSystem>(
    cs: &mut CS,
    inputs: Vec<Value>,
    outputs: Vec<Value>,
) -> Result<(), SpacesuitError> {
    let one = Scalar::one();

    if inputs.len() == 1 {
        cs.add_constraint(
            [(inputs[0].q.0, -one), (outputs[0].q.0, one)]
                .iter()
                .collect(),
        );
        cs.add_constraint(
            [(inputs[0].a.0, -one), (outputs[0].a.0, one)]
                .iter()
                .collect(),
        );
        cs.add_constraint(
            [(inputs[0].t.0, -one), (outputs[0].t.0, one)]
                .iter()
                .collect(),
        );
        return Ok(());
    }

    let mut A = inputs[0].clone();
    let mut B = inputs[1].clone();
    let mut C = outputs[0].clone();

    for i in 0..inputs.len() - 2 {
        let mut D = B.clone(); // placeholder; will be overwritten

        // Update assignments for D
        // Check that A and C have the same assignments for all fields (q, a, t)
        let is_move = A.q.1.ct_eq(&C.q.1) & A.a.1.ct_eq(&C.a.1) & A.t.1.ct_eq(&C.t.1);
        // Check that A and B have the same type (a and t are the same) and that C.q = 0
        let is_merge =
            A.a.1.ct_eq(&B.a.1) & A.t.1.ct_eq(&B.t.1) & C.q.1.ct_eq(&Scalar::zero().into());

        // Enforce that at least one of is_move and is_merge must be true. If not, error.
        // It is okay that this is not constant-time because the proof will fail to build anyway.
        if bool::from(!is_move & !is_merge) {
            // Misconfigured prover constraint system error
            return Err(SpacesuitError::InvalidR1CSConstruction);
        }

        // If is_move is true, then we perform a "move" operation, so D.quantity = B.quantity
        // Else, we perform a "merge" operation, so D.quantity = A.quantity + B.quantity
        D.q.1 = ConditionallySelectable::conditional_select(&(A.q.1 + B.q.1), &D.q.1, is_move);
        D.a.1 = ConditionallySelectable::conditional_select(&A.a.1, &D.a.1, is_move);
        D.t.1 = ConditionallySelectable::conditional_select(&A.t.1, &D.t.1, is_move);

        // Update variable assignments for D by making new variables
        let (D_q_var, _) = cs.assign_uncommitted(D.q.1, Scalar::zero().into())?;
        let (D_a_var, D_t_var) = cs.assign_uncommitted(D.a.1, D.t.1)?;
        D.q.0 = D_q_var;
        D.a.0 = D_a_var;
        D.t.0 = D_t_var;

        mix::fill_cs(cs, A, B, C, D.clone())?;

        A = D;
        B = inputs[i + 2].clone();
        C = outputs[i + 1].clone();
    }

    let D = outputs[outputs.len() - 1].clone();
    mix::fill_cs(cs, A, B, C, D)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bulletproofs::r1cs::{Assignment, ProverCS, VerifierCS};
    use bulletproofs::{BulletproofGens, PedersenGens};
    use merlin::Transcript;

    #[test]
    fn k_mix_gadget() {
        let peso = 66;
        let yuan = 88;
        let zero = 0; // just so the test case formatting lines up nicely

        // k=1
        // no merge, same asset types
        assert!(k_mix_helper(vec![(6, peso, 0)], vec![(6, peso, 0)]).is_ok());
        // error when merging different asset types
        assert!(k_mix_helper(vec![(3, peso, 0)], vec![(3, yuan, 0)]).is_err());

        // k=2 ... more extensive k=2 tests are in the MixGadget tests
        // no merge, different asset types
        assert!(
            k_mix_helper(
                vec![(3, peso, 0), (6, yuan, 0)],
                vec![(3, peso, 0), (6, yuan, 0)],
            ).is_ok()
        );
        // merge, same asset types
        assert!(
            k_mix_helper(
                vec![(3, peso, 0), (6, peso, 0)],
                vec![(0, peso, 0), (9, peso, 0)],
            ).is_ok()
        );
        // error when merging different asset types
        assert!(
            k_mix_helper(
                vec![(3, peso, 0), (3, yuan, 0)],
                vec![(0, peso, 0), (6, yuan, 0)],
            ).is_err()
        );

        // k=3
        // no merge, same asset types
        assert!(
            k_mix_helper(
                vec![(3, peso, 0), (6, peso, 0), (6, peso, 0)],
                vec![(3, peso, 0), (6, peso, 0), (6, peso, 0)],
            ).is_ok()
        );
        // no merge, different asset types
        assert!(
            k_mix_helper(
                vec![(3, peso, 0), (6, yuan, 0), (6, peso, 0)],
                vec![(3, peso, 0), (6, yuan, 0), (6, peso, 0)],
            ).is_ok()
        );
        // merge first two
        assert!(
            k_mix_helper(
                vec![(3, peso, 0), (6, peso, 0), (1, yuan, 0)],
                vec![(0, peso, 0), (9, peso, 0), (1, yuan, 0)],
            ).is_ok()
        );
        // merge last two
        assert!(
            k_mix_helper(
                vec![(1, yuan, 0), (3, peso, 0), (6, peso, 0)],
                vec![(1, yuan, 0), (0, peso, 0), (9, peso, 0)],
            ).is_ok()
        );
        // merge all, same asset types, zero value is different asset type
        assert!(
            k_mix_helper(
                vec![(3, peso, 0), (6, peso, 0), (1, peso, 0)],
                vec![(0, zero, 0), (0, zero, 0), (10, peso, 0)],
            ).is_ok()
        );
        // incomplete merge, input sum does not equal output sum
        assert!(
            k_mix_helper(
                vec![(3, peso, 0), (6, peso, 0), (1, peso, 0)],
                vec![(1, zero, 0), (0, zero, 0), (9, peso, 0)],
            ).is_err()
        );
        // error when merging with different asset types
        assert!(
            k_mix_helper(
                vec![(3, peso, 0), (6, yuan, 0), (1, peso, 0)],
                vec![(0, zero, 0), (0, zero, 0), (10, peso, 0)],
            ).is_err()
        );

        // k=4
        // merge each of 2 asset types
        assert!(
            k_mix_helper(
                vec![(3, peso, 0), (6, peso, 0), (1, yuan, 0), (2, yuan, 0)],
                vec![(0, zero, 0), (9, peso, 0), (0, zero, 0), (3, yuan, 0)],
            ).is_ok()
        );
        // merge all, same asset
        assert!(
            k_mix_helper(
                vec![(3, peso, 0), (2, peso, 0), (2, peso, 0), (1, peso, 0)],
                vec![(0, zero, 0), (0, zero, 0), (0, zero, 0), (8, peso, 0)],
            ).is_ok()
        );
        // error when merging, output sum not equal to input sum
        assert!(
            k_mix_helper(
                vec![(3, peso, 0), (2, peso, 0), (2, peso, 0), (1, peso, 0)],
                vec![(0, zero, 0), (0, zero, 0), (0, zero, 0), (9, peso, 0)],
            ).is_err()
        );
    }

    fn k_mix_helper(
        inputs: Vec<(u64, u64, u64)>,
        outputs: Vec<(u64, u64, u64)>,
    ) -> Result<(), SpacesuitError> {
        // Common
        let pc_gens = PedersenGens::default();
        let bp_gens = BulletproofGens::new(128, 1);
        let k = inputs.len();

        // Prover's scope
        let (proof, commitments) = {
            // Prover makes a `ConstraintSystem` instance representing a merge gadget
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
            let mut prover_transcript = Transcript::new(b"KMixTest");
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
        let mut verifier_transcript = Transcript::new(b"KMixTest");
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
