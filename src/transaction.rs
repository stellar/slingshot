#![allow(non_snake_case)]

use bulletproofs::r1cs::ConstraintSystem;
use curve25519_dalek::scalar::Scalar;
use gadgets::{merge, pad, range_proof, split, value_shuffle};
use std::cmp::{max, min};
use subtle::{ConditionallySelectable, ConstantTimeEq};
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
    let inner_merge_count = max(m as isize - 2, 0) as usize;
    let inner_split_count = max(n as isize - 2, 0) as usize;
    if inputs.len() != merge_in.len()
        || merge_in.len() != merge_out.len()
        || split_in.len() != split_out.len()
        || split_out.len() != outputs.len()
        || merge_mid.len() != inner_merge_count
        || split_mid.len() != inner_split_count
    {
        return Err(SpacesuitError::InvalidR1CSConstruction);
    }

    // Shuffle 1
    // Group the inputs by flavor.
    // Choice -> Ordering conversion? seems wrong...
    value_shuffle::fill_cs(cs, inputs, merge_in.clone())?;

    // Merge
    // Combine all the merge_in of the same flavor. If different flavors, do not combine.
    merge::fill_cs(cs, merge_in, merge_mid, merge_out.clone())?;

    // Shuffle 2
    value_shuffle::fill_cs(cs, merge_out, split_in.clone())?;

    // Split
    // Combine all the split_out of the same flavor. If different flavors, do not combine.
    split::fill_cs(cs, split_in, split_mid, split_out.clone())?;

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
) -> Result<Vec<Scalar>, SpacesuitError> {
    let m = inputs.len();
    let n = outputs.len();
    let merge_mid_count = max(m as isize - 2, 0) as usize;
    let split_mid_count = max(n as isize - 2, 0) as usize;
    let commitment_count = 2 * m + merge_mid_count + 2 * n + split_mid_count;
    let mut v = Vec::with_capacity(commitment_count);

    // Input to transaction
    append_values(&mut v, &inputs);

    // Inputs, intermediates, and outputs of merge gadget
    let merge_in = shuffle_helper(&inputs);
    let (merge_mid, merge_out) = merge_helper(&merge_in);
    append_values(&mut v, &merge_in);
    append_values(&mut v, &merge_mid);
    append_values(&mut v, &merge_out);

    // Inputs, intermediates, and outputs of split gadget
    let split_out = shuffle_helper(&outputs);
    let (split_mid, split_in) = split_helper(&split_out);
    append_values(&mut v, &split_in);
    append_values(&mut v, &split_mid);
    append_values(&mut v, &split_out);

    // Output of transaction
    append_values(&mut v, &outputs);

    Ok(v)
}

// Takes in the ungrouped side of shuffle, returns the values grouped by flavor.
// TODO: do this in constant time
fn shuffle_helper(shuffle_in: &Vec<(u64, u64, u64)>) -> Vec<(u64, u64, u64)> {
    let mut shuffle_out = shuffle_in.clone();
    shuffle_out.sort_unstable_by_key(|(_q, a, t)| (a.clone(), t.clone()));
    shuffle_out
}

// takes in split_out, returns split_mid and split_in
fn split_helper(split_out: &Vec<(u64, u64, u64)>) -> (Vec<(u64, u64, u64)>, Vec<(u64, u64, u64)>) {
    let mut split_out_rev = split_out.clone();
    split_out_rev.reverse();
    let (mut split_mid, mut split_in) = merge_helper(&split_out_rev);
    split_mid.reverse();
    split_in.reverse();

    (split_mid, split_in)
}

// takes in merge_in, returns merge_mid and merge_out
fn merge_helper(merge_in: &Vec<(u64, u64, u64)>) -> (Vec<(u64, u64, u64)>, Vec<(u64, u64, u64)>) {
    if merge_in.len() < 2 {
        return (vec![], merge_in.clone());
    }

    let merge_count = merge_in.len() - 1;
    let mut merge_mid = Vec::with_capacity(merge_count);
    let mut merge_out = Vec::with_capacity(merge_in.len());

    let mut A = merge_in[0];
    let mut B = merge_in[1];
    for i in 0..merge_count {
        // Check if A and B have the same flavors
        let same_flavor = A.1.ct_eq(&B.1) & A.2.ct_eq(&B.2);

        // If same_flavor, merge: C.q, C.a, C.t = 0.
        // Else, move: C = A.
        let C_q = ConditionallySelectable::conditional_select(&A.0, &0, same_flavor);
        let C_a = ConditionallySelectable::conditional_select(&A.1, &0, same_flavor);
        let C_t = ConditionallySelectable::conditional_select(&A.2, &0, same_flavor);

        // If same_flavor, merge: D.q = A.q + B.q, D.a = A.a, D.t = A.t.
        // Else, move: D = B.
        let D_q = ConditionallySelectable::conditional_select(&B.0, &(A.0 + B.0), same_flavor);
        let D_a = ConditionallySelectable::conditional_select(&B.1, &A.1, same_flavor);
        let D_t = ConditionallySelectable::conditional_select(&B.2, &A.2, same_flavor);

        merge_out.push((C_q, C_a, C_t));
        merge_mid.push((D_q, D_a, D_t));

        A = (D_q, D_a, D_t);
        B = merge_in[min(i + 2, merge_count)];
    }

    // Move the last merge_mid to be the last merge_out, to match the protocol
    merge_out.push(merge_mid.pop().unwrap()); // TODO: handle this error

    (merge_mid, merge_out)
}

fn append_values(values: &mut Vec<Scalar>, list: &Vec<(u64, u64, u64)>) {
    for i in 0..list.len() {
        values.push(Scalar::from(list[i].0));
        values.push(Scalar::from(list[i].1));
        values.push(Scalar::from(list[i].2));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bulletproofs::r1cs::{Assignment, ProverCS, Variable, VerifierCS};
    use bulletproofs::{BulletproofGens, PedersenGens};
    use merlin::Transcript;

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
            let v = make_commitments(inputs, outputs)?;

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

            fill_cs(&mut prover_cs, inp, m_i, m_m, m_o, s_i, s_m, s_o, out)?;
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

        assert!(fill_cs(&mut verifier_cs, inp, m_i, m_m, m_o, s_i, s_m, s_o, out).is_ok());

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

    #[test]
    fn transaction_test() {
        // m=1, n=1
        assert!(transaction_helper(vec![(1, 2, 3)], vec![(1, 2, 3)]).is_ok());
        assert!(transaction_helper(vec![(4, 5, 6)], vec![(4, 5, 6)]).is_ok());
        assert!(transaction_helper(vec![(1, 2, 3)], vec![(4, 5, 6)]).is_err());

        // m=2, n=2, only shuffle (all different flavors)
        assert!(transaction_helper(vec![(1, 2, 3), (4, 5, 6)], vec![(1, 2, 3), (4, 5, 6)]).is_ok());
        assert!(transaction_helper(vec![(1, 2, 3), (4, 5, 6)], vec![(4, 5, 6), (1, 2, 3)]).is_ok());

        // m=2, n=2, middle shuffle & merge & split (has multiple inputs or outputs of same flavor)
        assert!(transaction_helper(vec![(4, 5, 6), (4, 5, 6)], vec![(4, 5, 6), (4, 5, 6)]).is_ok());
        assert!(transaction_helper(vec![(5, 9, 9), (3, 9, 9)], vec![(5, 9, 9), (3, 9, 9)]).is_ok());
        assert!(transaction_helper(vec![(5, 9, 9), (3, 9, 9)], vec![(1, 9, 9), (7, 9, 9)]).is_ok());
        assert!(transaction_helper(vec![(1, 9, 9), (8, 9, 9)], vec![(0, 9, 9), (9, 9, 9)]).is_ok());
        assert!(
            transaction_helper(vec![(1, 2, 3), (1, 2, 3)], vec![(4, 5, 6), (1, 2, 3)]).is_err()
        );

        // m=3, n=3, only shuffle
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

        // m=3, n=3, middle shuffle & merge & split
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

        // m=3, n=3, uses end shuffles & merge & split & middle shuffle
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

        // m=4, n=4, only shuffle
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

        // m=4, n=4, middle shuffle & merge & split
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
    }

    // Note: the output vector for shuffle_helper does not have to be in a particular order,
    // it just has to be grouped by flavor. Thus, it is possible to make a valid change to
    // shuffle_helper but break the tests.
    #[test]
    fn shuffle_helper_test() {
        // k = 1
        assert_eq!(shuffle_helper(&vec![(1, 9, 9)]), vec![(1, 9, 9)]);
        // k = 2
        assert_eq!(
            shuffle_helper(&vec![(1, 9, 9), (2, 9, 9)]),
            vec![(1, 9, 9), (2, 9, 9)]
        );
        assert_eq!(
            shuffle_helper(&vec![(1, 9, 9), (2, 8, 8)]),
            vec![(2, 8, 8), (1, 9, 9)]
        );
        // k = 3
        assert_eq!(
            shuffle_helper(&vec![(1, 9, 9), (3, 8, 8), (2, 9, 9)]),
            vec![(3, 8, 8), (1, 9, 9), (2, 9, 9)]
        );
        // k = 4
        assert_eq!(
            shuffle_helper(&vec![(1, 9, 9), (3, 8, 8), (2, 9, 9), (4, 8, 8)]),
            vec![(3, 8, 8), (4, 8, 8), (1, 9, 9), (2, 9, 9)]
        );
        assert_eq!(
            shuffle_helper(&vec![(1, 9, 9), (3, 8, 8), (4, 8, 8), (2, 9, 9)]),
            vec![(3, 8, 8), (4, 8, 8), (1, 9, 9), (2, 9, 9)]
        );
        assert_eq!(
            shuffle_helper(&vec![(1, 9, 9), (3, 8, 8), (4, 7, 7), (2, 9, 9)]),
            vec![(4, 7, 7), (3, 8, 8), (1, 9, 9), (2, 9, 9)]
        );
    }

    #[test]
    fn merge_helper_test() {
        // k = 2
        assert_eq!(
            merge_helper(&vec![(1, 2, 3), (4, 5, 6)]),
            (vec![], vec![(1, 2, 3), (4, 5, 6)])
        );
        assert_eq!(
            merge_helper(&vec![(1, 9, 9), (3, 9, 9)]),
            (vec![], vec![(0, 0, 0), (4, 9, 9)])
        );
        // k = 3
        assert_eq!(
            merge_helper(&vec![(1, 2, 3), (4, 5, 6), (7, 8, 9)]),
            (vec![(4, 5, 6)], vec![(1, 2, 3), (4, 5, 6), (7, 8, 9)])
        );
        assert_eq!(
            merge_helper(&vec![(1, 9, 9), (3, 9, 9), (2, 8, 8)]),
            (vec![(4, 9, 9)], vec![(0, 0, 0), (4, 9, 9), (2, 8, 8)])
        );
        assert_eq!(
            merge_helper(&vec![(2, 8, 8), (1, 9, 9), (3, 9, 9)]),
            (vec![(1, 9, 9)], vec![(2, 8, 8), (0, 0, 0), (4, 9, 9)])
        );
        // k = 4
        assert_eq!(
            merge_helper(&vec![(1, 2, 3), (1, 2, 3), (4, 5, 6), (4, 5, 6)]),
            (
                vec![(2, 2, 3), (4, 5, 6)],
                vec![(0, 0, 0), (2, 2, 3), (0, 0, 0), (8, 5, 6)]
            )
        );
        assert_eq!(
            merge_helper(&vec![(1, 9, 9), (2, 9, 9), (3, 9, 9), (4, 9, 9)]),
            (
                vec![(3, 9, 9), (6, 9, 9)],
                vec![(0, 0, 0), (0, 0, 0), (0, 0, 0), (10, 9, 9)]
            )
        );
    }
}
