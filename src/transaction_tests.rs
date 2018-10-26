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
        // only shuffle
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
                vec![yuan(1), (40, 50, 60), euro(8)]
            ).is_err()
        );
        assert!(
            transaction_helper(
                vec![yuan(1), peso(4), euro(8)],
                vec![yuan(1), peso(4), euro(9)]
            ).is_err()
        );

        // middle shuffle & merge & split
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
        assert!(
            transaction_helper(vec![yuan(11), peso(4)], vec![yuan(4), yuan(7), peso(4)],).is_ok()
        );
        assert!(
            transaction_helper(vec![yuan(4), yuan(7), peso(4)], vec![yuan(11), peso(4)],).is_ok()
        );
        assert!(
            transaction_helper(vec![yuan(5), yuan(6)], vec![yuan(4), yuan(4), yuan(3)],).is_ok()
        );
        assert!(
            transaction_helper(vec![yuan(4), yuan(4), yuan(3)], vec![yuan(5), yuan(6)],).is_ok()
        );
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
                vec![yuan(4), yuan(3), yuan(3), (0, 0, 0)]
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
}
