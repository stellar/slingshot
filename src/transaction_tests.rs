#[cfg(test)]
mod tests {
    use super::super::transaction;
    use bulletproofs::r1cs::{Assignment, ProverCS, Variable, VerifierCS};
    use bulletproofs::{BulletproofGens, PedersenGens};
    use curve25519_dalek::scalar::Scalar;
    use merlin::Transcript;
    use std::cmp::max;
    use util::{SpacesuitError, Value};

    fn transaction_helper(
        inputs: Vec<(u64, u64, u64)>,
        outputs: Vec<(u64, u64, u64)>,
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
            let v = transaction::make_commitments(inputs, outputs)?;

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
                value_helper(variables, v_assignments, m, n);

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
        let (inp, m_i, m_m, m_o, s_i, s_m, s_o, out) = value_helper(variables, v_assignments, m, n);

        assert!(
            transaction::fill_cs(&mut verifier_cs, inp, m_i, m_m, m_o, s_i, s_m, s_o, out).is_ok()
        );

        Ok(verifier_cs.verify(&proof)?)
    }

    fn value_helper(
        variables: Vec<Variable>,
        assignments: Vec<Assignment>,
        m: usize,
        n: usize,
    ) -> (
        Vec<Value>,
        Vec<Value>,
        Vec<Value>,
        Vec<Value>,
        Vec<Value>,
        Vec<Value>,
        Vec<Value>,
        Vec<Value>,
    ) {
        let inner_merge_count = max(m as isize - 2, 0) as usize;
        let inner_split_count = max(n as isize - 2, 0) as usize;
        let val_count = variables.len() / 3;

        let mut values = Vec::with_capacity(val_count);
        for i in 0..val_count {
            values.push(Value {
                q: (variables[i * 3], assignments[i * 3]),
                a: (variables[i * 3 + 1], assignments[i * 3 + 1]),
                t: (variables[i * 3 + 2], assignments[i * 3 + 2]),
            });
        }

        // TODO: surely there's a better way to do this
        let mut index = 0;
        let inp = &values[index..index + m];
        index = index + m;
        let m_i = &values[index..index + m];
        index = index + m;
        let m_m = &values[index..index + inner_merge_count];
        index = index + inner_merge_count;
        let m_o = &values[index..index + m];
        index = index + m;
        let s_i = &values[index..index + n];
        index = index + n;
        let s_m = &values[index..index + inner_split_count];
        index = index + inner_split_count;
        let s_o = &values[index..index + n];
        index = index + n;
        let out = &values[index..index + n];

        (
            inp.to_vec(),
            m_i.to_vec(),
            m_m.to_vec(),
            m_o.to_vec(),
            s_i.to_vec(),
            s_m.to_vec(),
            s_o.to_vec(),
            out.to_vec(),
        )
    }

    // m=1, n=1
    #[test]
    fn transaction_1_1() {
        assert!(transaction_helper(vec![(1, 2, 3)], vec![(1, 2, 3)]).is_ok());
        assert!(transaction_helper(vec![(4, 5, 6)], vec![(4, 5, 6)]).is_ok());
        assert!(transaction_helper(vec![(1, 2, 3)], vec![(4, 5, 6)]).is_err());
    }

    // m=2, n=2
    #[test]
    fn transaction_2_2() {
        // Only shuffle (all different flavors)
        assert!(transaction_helper(vec![(1, 2, 3), (4, 5, 6)], vec![(1, 2, 3), (4, 5, 6)]).is_ok());
        assert!(transaction_helper(vec![(1, 2, 3), (4, 5, 6)], vec![(4, 5, 6), (1, 2, 3)]).is_ok());

        // Middle shuffle & merge & split (has multiple inputs or outputs of same flavor)
        assert!(transaction_helper(vec![(4, 5, 6), (4, 5, 6)], vec![(4, 5, 6), (4, 5, 6)]).is_ok());
        assert!(transaction_helper(vec![(5, 9, 9), (3, 9, 9)], vec![(5, 9, 9), (3, 9, 9)]).is_ok());
        assert!(transaction_helper(vec![(5, 9, 9), (3, 9, 9)], vec![(1, 9, 9), (7, 9, 9)]).is_ok());
        assert!(transaction_helper(vec![(1, 9, 9), (8, 9, 9)], vec![(0, 9, 9), (9, 9, 9)]).is_ok());
        assert!(
            transaction_helper(vec![(1, 2, 3), (1, 2, 3)], vec![(4, 5, 6), (1, 2, 3)]).is_err()
        );
    }

    // m=3, n=3
    #[test]
    fn transaction_3_3() {
        // only shuffle
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

        // middle shuffle & merge & split
        assert!(
            transaction_helper(
                vec![(1, 2, 3), (1, 2, 3), (4, 5, 6)],
                vec![(1, 2, 3), (1, 2, 3), (4, 5, 6)]
            ).is_ok()
        );
        assert!(
            transaction_helper(
                vec![(4, 2, 3), (3, 2, 3), (4, 5, 6)],
                vec![(2, 2, 3), (5, 2, 3), (4, 5, 6)]
            ).is_ok()
        );
        assert!(
            transaction_helper(
                vec![(4, 2, 3), (3, 2, 3), (4, 5, 6)],
                vec![(4, 5, 6), (2, 2, 3), (5, 2, 3)]
            ).is_ok()
        );
        assert!(
            transaction_helper(
                vec![(1, 2, 3), (2, 2, 3), (5, 2, 3)],
                vec![(4, 2, 3), (3, 2, 3), (1, 2, 3)]
            ).is_ok()
        );
        assert!(
            transaction_helper(
                vec![(1, 2, 3), (2, 2, 3), (5, 2, 3)],
                vec![(4, 2, 3), (3, 2, 3), (10, 2, 3)]
            ).is_err()
        );

        // End shuffles & merge & split & middle shuffle
        // (multiple asset types that need to be grouped and merged or split)
        assert!(
            transaction_helper(
                vec![(1, 2, 3), (4, 5, 6), (1, 2, 3)],
                vec![(1, 2, 3), (1, 2, 3), (4, 5, 6)]
            ).is_ok()
        );
        assert!(
            transaction_helper(
                vec![(4, 2, 3), (4, 5, 6), (3, 2, 3)],
                vec![(3, 5, 6), (7, 2, 3), (1, 5, 6)]
            ).is_ok()
        );
    }

    // m=4, n=4
    #[test]
    fn transaction_4_4() {
        // Only shuffle
        assert!(
            transaction_helper(
                vec![(1, 2, 3), (4, 5, 6), (7, 8, 9), (10, 11, 12)],
                vec![(1, 2, 3), (4, 5, 6), (7, 8, 9), (10, 11, 12)]
            ).is_ok()
        );
        assert!(
            transaction_helper(
                vec![(1, 2, 3), (4, 5, 6), (7, 8, 9), (10, 11, 12)],
                vec![(7, 8, 9), (1, 2, 3), (10, 11, 12), (4, 5, 6),]
            ).is_ok()
        );

        // Middle shuffle & merge & split
        assert!(
            transaction_helper(
                vec![(1, 2, 3), (1, 2, 3), (4, 5, 6), (4, 5, 6)],
                vec![(1, 2, 3), (1, 2, 3), (4, 5, 6), (4, 5, 6)]
            ).is_ok()
        );
        assert!(
            transaction_helper(
                vec![(4, 2, 3), (3, 2, 3), (4, 5, 6), (4, 5, 6)],
                vec![(2, 2, 3), (5, 2, 3), (1, 5, 6), (7, 5, 6)]
            ).is_ok()
        );
        assert!(
            transaction_helper(
                vec![(4, 2, 3), (3, 2, 3), (4, 5, 6), (4, 5, 6)],
                vec![(1, 5, 6), (7, 5, 6), (2, 2, 3), (5, 2, 3)]
            ).is_ok()
        );
        assert!(
            transaction_helper(
                vec![(1, 2, 3), (1, 2, 3), (5, 2, 3), (2, 2, 3)],
                vec![(1, 2, 3), (1, 2, 3), (5, 2, 3), (2, 2, 3)]
            ).is_ok()
        );
        assert!(
            transaction_helper(
                vec![(1, 2, 3), (2, 2, 3), (5, 2, 3), (2, 2, 3)],
                vec![(4, 2, 3), (3, 2, 3), (3, 2, 3), (0, 0, 0)]
            ).is_ok()
        );
        assert!(
            transaction_helper(
                vec![(1, 2, 3), (2, 2, 3), (5, 2, 3), (2, 2, 3)],
                vec![(4, 2, 3), (3, 2, 3), (3, 2, 3), (20, 2, 3)]
            ).is_err()
        );

        // End shuffles & merge & split & middle shuffle
        assert!(
            transaction_helper(
                vec![(1, 2, 3), (4, 5, 6), (1, 2, 3), (4, 5, 6)],
                vec![(4, 5, 6), (1, 2, 3), (1, 2, 3), (4, 5, 6)]
            ).is_ok()
        );
        assert!(
            transaction_helper(
                vec![(4, 2, 3), (4, 5, 6), (4, 5, 6), (3, 2, 3)],
                vec![(1, 5, 6), (2, 2, 3), (5, 2, 3), (7, 5, 6)]
            ).is_ok()
        );
    }
}
