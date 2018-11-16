#![allow(non_snake_case)]

use bulletproofs::r1cs::{ProverCS, R1CSProof, Variable, VerifierCS};
use bulletproofs::{BulletproofGens, PedersenGens};
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use error::SpacesuitError;
use gadgets::transaction;
use merlin::Transcript;
use std::cmp::max;
use subtle::{ConditionallySelectable, ConstantTimeEq};
use value::{AllocatedValue, Value};

pub struct SpacesuitProof(R1CSProof);

pub fn prove(
    bp_gens: &BulletproofGens,
    pc_gens: &PedersenGens,
    inputs: &Vec<Value>,
    outputs: &Vec<Value>,
) -> Result<(SpacesuitProof, Vec<CompressedRistretto>), SpacesuitError> {
    let m = inputs.len();
    let n = outputs.len();

    // Compute all intermediate values and add them to inputs and outputs,
    // returning raw variable assignments to be passed to the prover.
    let all_values = compute_committed_values(inputs, outputs)?;

    // Flatten the values into a list of raw scalars to compute the Pedersen commitments.
    // TBD: would be nice if ProverCS had an API to do this per-value, so we can avoid
    // flattening the structure of our input data and then unflattening it via `organize_values`.
    let v: Vec<Scalar> = all_values.iter().fold(
        Vec::with_capacity(3 * all_values.len()),
        |mut vec, value| {
            vec.push(value.q.into());
            vec.push(value.a);
            vec.push(value.t);
            vec
        },
    );

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
    let (inp, m_i, m_m, m_o, s_i, s_m, s_o, out) =
        organize_values(variables, &Some(all_values), m, n);

    transaction::fill_cs(&mut prover_cs, inp, m_i, m_m, m_o, s_i, s_m, s_o, out)?;
    let proof = SpacesuitProof(prover_cs.prove()?);

    Ok((proof, commitments))
}

pub fn verify(
    bp_gens: &BulletproofGens,
    pc_gens: &PedersenGens,
    proof: &SpacesuitProof,
    commitments: Vec<CompressedRistretto>,
    m: usize,
    n: usize,
) -> Result<(), SpacesuitError> {
    // TBD: check the correctness of the size of the commitments

    // Verifier makes a `ConstraintSystem` instance representing a merge gadget
    let mut verifier_transcript = Transcript::new(b"TransactionTest");
    let (mut verifier_cs, variables) =
        VerifierCS::new(&bp_gens, &pc_gens, &mut verifier_transcript, commitments);

    // Verifier allocates variables and adds constraints to the constraint system
    let (inp, m_i, m_m, m_o, s_i, s_m, s_o, out) = organize_values(variables, &None, m, n);

    assert!(transaction::fill_cs(&mut verifier_cs, inp, m_i, m_m, m_o, s_i, s_m, s_o, out).is_ok());

    Ok(verifier_cs.verify(&proof.0)?)
}

/// Given the input and output values for a spacesuit transaction, determine
/// what the intermediate commitments need to be.
///
/// Note: It is essential that we create commitments to the intermediate variables,
/// because the challenges used in the `shuffle`, `merge`, and `split` gadgets are
/// generated from these commitments. If we do not commit to the intermediate variables,
/// then the intermediate variables can have malleable quantities and as a result it
/// could be possible to choose them maliciously to cancel out the challenge variables.
/// This will be fixed in the future with a "Bulletproofs++" which binds the challenge
/// value to the intermediate variables as well. The discussion for that is here:
/// https://github.com/dalek-cryptography/bulletproofs/issues/186
fn compute_committed_values(
    inputs: &Vec<Value>,
    outputs: &Vec<Value>,
) -> Result<Vec<Value>, SpacesuitError> {
    let m = inputs.len();
    let n = outputs.len();
    let merge_mid_count = max(m, 2) - 2; // max(m - 2, 0)
    let split_mid_count = max(n, 2) - 2; // max(n - 2, 0)
    let commitment_count = 2 * m + merge_mid_count + 2 * n + split_mid_count;

    let mut v = Vec::<Value>::with_capacity(commitment_count);

    // Input to transaction
    v.extend_from_slice(inputs);

    // Inputs, intermediates, and outputs of merge gadget
    let merge_in = shuffle_helper(inputs);
    let (merge_mid, merge_out) = merge_helper(&merge_in)?;

    v.extend_from_slice(&merge_in);
    v.extend_from_slice(&merge_mid);
    v.extend_from_slice(&merge_out);

    // Inputs, intermediates, and outputs of split gadget
    let split_out = shuffle_helper(outputs);
    let (split_mid, split_in) = split_helper(&split_out)?;

    v.extend_from_slice(&split_in);
    v.extend_from_slice(&split_mid);
    v.extend_from_slice(&split_out);

    // Output of transaction
    v.extend_from_slice(&outputs);

    Ok(v)
}

/// Organizes a flat list of variables into the collections
/// of variables for each gadget.
fn organize_values(
    variables: Vec<Variable>,
    assignments: &Option<Vec<Value>>,
    m: usize,
    n: usize,
) -> (
    Vec<AllocatedValue>,
    Vec<AllocatedValue>,
    Vec<AllocatedValue>,
    Vec<AllocatedValue>,
    Vec<AllocatedValue>,
    Vec<AllocatedValue>,
    Vec<AllocatedValue>,
    Vec<AllocatedValue>,
) {
    let inner_merge_count = max(m, 2) - 2; // max(m - 2, 0)
    let inner_split_count = max(n, 2) - 2; // max(n - 2, 0)
    let val_count = variables.len() / 3;

    let mut values = Vec::with_capacity(val_count);
    for i in 0..val_count {
        values.push(AllocatedValue {
            q: variables[i * 3],
            a: variables[i * 3 + 1],
            t: variables[i * 3 + 2],
            assignment: match assignments {
                Some(ref a) => Some(a[i]),
                None => None,
            },
        });
    }

    let (inp, values) = values.split_at(m);
    let (m_i, values) = values.split_at(m);
    let (m_m, values) = values.split_at(inner_merge_count);
    let (m_o, values) = values.split_at(m);
    let (s_i, values) = values.split_at(n);
    let (s_m, values) = values.split_at(inner_split_count);
    let (s_o, values) = values.split_at(n);
    let (out, _) = values.split_at(n);

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

// Takes in shuffle_in, returns shuffle_out which is a reordering of the tuples in shuffle_in
// where they have been grouped according to flavor.
fn shuffle_helper(shuffle_in: &Vec<Value>) -> Vec<Value> {
    let k = shuffle_in.len();
    let mut shuffle_out = shuffle_in.clone();

    for i in 0..k - 1 {
        // This tuple has the flavor that we are trying to group by in this loop
        let flav = shuffle_out[i];
        // This tuple may be swapped with another tuple (`comp`)
        // if `comp` and `flav` have the same flavor.
        let mut swap = shuffle_out[i + 1];

        for j in i + 2..k {
            // Iterate over all following tuples, assigning them to `comp`.
            let mut comp = shuffle_out[j];
            // Check if `flav` and `comp` have the same flavor.
            let same_flavor = flav.a.ct_eq(&comp.a) & flav.t.ct_eq(&comp.t);

            // If same_flavor, then swap `comp` and `swap`. Else, keep the same.
            u64::conditional_swap(&mut swap.q, &mut comp.q, same_flavor);
            Scalar::conditional_swap(&mut swap.a, &mut comp.a, same_flavor);
            Scalar::conditional_swap(&mut swap.t, &mut comp.t, same_flavor);
            shuffle_out[i + 1] = swap;
            shuffle_out[j] = comp;
        }
    }
    shuffle_out
}

// Takes in split_out, returns split_mid and split_in
// Runs in constant time - runtime does not reveal anything about input values
// except for how many there are (which is public knowledge).
fn split_helper(split_out: &Vec<Value>) -> Result<(Vec<Value>, Vec<Value>), SpacesuitError> {
    let mut split_out_rev = split_out.clone();
    split_out_rev.reverse();
    let (mut split_mid, mut split_in) = merge_helper(&split_out_rev)?;
    split_mid.reverse();
    split_in.reverse();

    Ok((split_mid, split_in))
}

// Takes in merge_in, returns merge_mid and merge_out
// Runs in constant time - runtime does not reveal anything about input values
// except for how many there are (which is public knowledge).
fn merge_helper(merge_in: &Vec<Value>) -> Result<(Vec<Value>, Vec<Value>), SpacesuitError> {
    if merge_in.len() < 2 {
        return Ok((vec![], merge_in.clone()));
    }

    // The number of 2-merge gadgets that will be created
    let merge_count = merge_in.len() - 1;
    let mut merge_mid = Vec::with_capacity(merge_count);
    let mut merge_out = Vec::with_capacity(merge_in.len());

    let mut A = merge_in[0];
    for B in merge_in.into_iter().skip(1) {
        // Check if A and B have the same flavors
        let same_flavor = A.a.ct_eq(&B.a) & A.t.ct_eq(&B.t);

        // If same_flavor, merge: C.0, C.1, C.2 = 0.
        // Else, move: C = A.
        let mut C = A.clone();
        C.q.conditional_assign(&0u64, same_flavor);
        C.a.conditional_assign(&Scalar::zero(), same_flavor);
        C.t.conditional_assign(&Scalar::zero(), same_flavor);
        merge_out.push(C);

        // If same_flavor, merge: D.0 = A.0 + B.0, D.1 = A.1, D.2 = A.2.
        // Else, move: D = B.
        let mut D = B.clone();
        D.q.conditional_assign(&(A.q + B.q), same_flavor);
        D.a.conditional_assign(&A.a, same_flavor);
        D.t.conditional_assign(&A.t, same_flavor);
        merge_mid.push(D);

        A = D;
    }

    // Move the last merge_mid to be the last merge_out, to match the protocol definition
    match merge_mid.pop() {
        Some(val) => merge_out.push(val),
        None => return Err(SpacesuitError::InvalidR1CSConstruction),
    }

    Ok((merge_mid, merge_out))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Helper functions to make the tests easier to read
    fn yuan(val: u64) -> Value {
        Value {
            q: val,
            a: Scalar::from(888u64),
            t: Scalar::from(999u64),
        }
    }
    fn peso(val: u64) -> Value {
        Value {
            q: val,
            a: Scalar::from(666u64),
            t: Scalar::from(777u64),
        }
    }
    fn zero() -> Value {
        Value::zero()
    }

    // Note: the output vector for shuffle_helper does not have to be in a particular order,
    // it just has to be grouped by flavor. Thus, it is possible to make a valid change to
    // shuffle_helper but break the tests.
    #[test]
    fn shuffle_helper_test() {
        // k = 1
        assert_eq!(shuffle_helper(&vec![yuan(1)]), vec![yuan(1)]);
        // k = 2
        assert_eq!(
            shuffle_helper(&vec![yuan(1), yuan(2)]),
            vec![yuan(1), yuan(2)]
        );
        assert_eq!(
            shuffle_helper(&vec![yuan(1), peso(2)]),
            vec![yuan(1), peso(2)]
        );
        // k = 3
        assert_eq!(
            shuffle_helper(&vec![yuan(1), peso(3), yuan(2)]),
            vec![yuan(1), yuan(2), peso(3)]
        );
        // k = 4
        assert_eq!(
            shuffle_helper(&vec![yuan(1), peso(3), yuan(2), peso(4)]),
            vec![yuan(1), yuan(2), peso(3), peso(4)]
        );
        assert_eq!(
            shuffle_helper(&vec![yuan(1), peso(3), peso(4), yuan(2)]),
            vec![yuan(1), yuan(2), peso(4), peso(3)]
        );
        assert_eq!(
            shuffle_helper(&vec![yuan(1), peso(3), zero(), yuan(2)]),
            vec![yuan(1), yuan(2), zero(), peso(3)]
        );
        assert_eq!(
            shuffle_helper(&vec![yuan(1), yuan(2), yuan(3), yuan(4)]),
            vec![yuan(1), yuan(4), yuan(3), yuan(2)]
        );
        // k = 5
        assert_eq!(
            shuffle_helper(&vec![yuan(1), yuan(2), yuan(3), yuan(4), yuan(5)]),
            vec![yuan(1), yuan(5), yuan(4), yuan(3), yuan(2)]
        );
        assert_eq!(
            shuffle_helper(&vec![yuan(1), peso(2), yuan(3), peso(4), yuan(5)]),
            vec![yuan(1), yuan(5), yuan(3), peso(4), peso(2)]
        );
        assert_eq!(
            shuffle_helper(&vec![yuan(1), peso(2), zero(), peso(4), yuan(5)]),
            vec![yuan(1), yuan(5), zero(), peso(4), peso(2)]
        );
    }

    #[test]
    fn merge_helper_test() {
        // k = 2
        assert_eq!(
            merge_helper(&vec![yuan(1), peso(4)]).unwrap(),
            (vec![], vec![yuan(1), peso(4)])
        );
        assert_eq!(
            merge_helper(&vec![yuan(1), yuan(3)]).unwrap(),
            (vec![], vec![zero(), yuan(4)])
        );
        // k = 3
        assert_eq!(
            merge_helper(&vec![yuan(1), peso(4), zero()]).unwrap(),
            (vec![peso(4)], vec![yuan(1), peso(4), zero()])
        );
        assert_eq!(
            merge_helper(&vec![yuan(1), yuan(3), peso(2)]).unwrap(),
            (vec![yuan(4)], vec![zero(), yuan(4), peso(2)])
        );
        assert_eq!(
            merge_helper(&vec![peso(2), yuan(1), yuan(3)]).unwrap(),
            (vec![yuan(1)], vec![peso(2), zero(), yuan(4)])
        );
        // k = 4
        assert_eq!(
            merge_helper(&vec![yuan(1), yuan(1), peso(4), peso(4)]).unwrap(),
            (
                vec![yuan(2), peso(4)],
                vec![zero(), yuan(2), zero(), peso(8)]
            )
        );
        assert_eq!(
            merge_helper(&vec![yuan(1), yuan(2), yuan(3), yuan(4)]).unwrap(),
            (
                vec![yuan(3), yuan(6)],
                vec![zero(), zero(), zero(), yuan(10)]
            )
        );
    }
}
