#![allow(non_snake_case)]

use bulletproofs::r1cs::{Assignment, ConstraintSystem, Variable};
use curve25519_dalek::scalar::Scalar;
use gadgets::{merge, padded_shuffle, range_proof, split, value_shuffle};
use std::cmp::{max, min};
use subtle::{ConditionallyAssignable, ConstantTimeEq};
use util::{SpacesuitError, Value};

/// Enforces that the outputs are a valid rearrangement of the inputs, following the
/// soundness and secrecy requirements in the spacesuit transaction spec:
/// https://github.com/interstellar/spacesuit/blob/master/spec.md
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
    let inner_merge_count = max(m, 2) - 2; // max(m - 2, 0)
    let inner_split_count = max(n, 2) - 2; // max(n - 2, 0)
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
    // Check that `merge_in` is a valid reordering of `inputs`
    // when `inputs` are grouped by flavor.
    value_shuffle::fill_cs(cs, inputs, merge_in.clone())?;

    // Merge
    // Check that `merge_out` is a valid combination of `merge_in`,
    // when all values of the same flavor in `merge_in` are combined.
    merge::fill_cs(cs, merge_in, merge_mid, merge_out.clone())?;

    // Shuffle 2
    // Check that `split_in` is a valid reordering of `merge_out`, allowing for
    // the adding or dropping of padding values (quantity = 0) if m != n.
    padded_shuffle::fill_cs(cs, merge_out, split_in.clone())?;

    // Split
    // Check that `split_in` is a valid combination of `split_out`,
    // when all values of the same flavor in `split_out` are combined.
    split::fill_cs(cs, split_in, split_mid, split_out.clone())?;

    // Shuffle 3
    // Check that `split_out` is a valid reordering of `outputs`
    // when `outputs` are grouped by flavor.
    value_shuffle::fill_cs(cs, split_out, outputs.clone())?;

    // Range Proof
    // Check that each of the quantities in `outputs` lies in [0, 2^64).
    for output in outputs {
        range_proof::fill_cs(cs, output.q, 64)?;
    }

    Ok(())
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
pub fn compute_intermediate_values(
    inputs: Vec<(Scalar, Scalar, Scalar)>,
    outputs: Vec<(Scalar, Scalar, Scalar)>,
) -> Result<Vec<Scalar>, SpacesuitError> {
    let m = inputs.len();
    let n = outputs.len();
    let merge_mid_count = max(m, 2) - 2; // max(m - 2, 0)
    let split_mid_count = max(n, 2) - 2; // max(n - 2, 0)
    let commitment_count = 2 * m + merge_mid_count + 2 * n + split_mid_count;
    let mut v = Vec::with_capacity(commitment_count);

    // Input to transaction
    append_values(&mut v, &inputs);

    // Inputs, intermediates, and outputs of merge gadget
    let merge_in = shuffle_helper(&inputs);
    let (merge_mid, merge_out) = merge_helper(&merge_in)?;
    append_values(&mut v, &merge_in);
    append_values(&mut v, &merge_mid);
    append_values(&mut v, &merge_out);

    // Inputs, intermediates, and outputs of split gadget
    let split_out = shuffle_helper(&outputs);
    let (split_mid, split_in) = split_helper(&split_out)?;
    append_values(&mut v, &split_in);
    append_values(&mut v, &split_mid);
    append_values(&mut v, &split_out);

    // Output of transaction
    append_values(&mut v, &outputs);

    Ok(v)
}

pub fn value_helper(
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
    let inner_merge_count = max(m, 2) - 2; // max(m - 2, 0)
    let inner_split_count = max(n, 2) - 2; // max(n - 2, 0)
    let val_count = variables.len() / 3;

    let mut values = Vec::with_capacity(val_count);
    for i in 0..val_count {
        values.push(Value {
            q: (variables[i * 3], assignments[i * 3]),
            a: (variables[i * 3 + 1], assignments[i * 3 + 1]),
            t: (variables[i * 3 + 2], assignments[i * 3 + 2]),
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

// Takes in the ungrouped side of shuffle, returns the values grouped by flavor.
// TODO: do this in constant time
fn shuffle_helper(shuffle_in: &Vec<(Scalar, Scalar, Scalar)>) -> Vec<(Scalar, Scalar, Scalar)> {
    let mut shuffle_out = shuffle_in.clone();
    shuffle_out.sort_unstable_by_key(|(_q, a, t)| (a.to_bytes(), t.to_bytes()));
    shuffle_out
}

// Takes in split_out, returns split_mid and split_in
// Runs in constant time - runtime does not reveal anything about input values
// except for how many there are (which is public knowledge).
fn split_helper(
    split_out: &Vec<(Scalar, Scalar, Scalar)>,
) -> Result<(Vec<(Scalar, Scalar, Scalar)>, Vec<(Scalar, Scalar, Scalar)>), SpacesuitError> {
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
fn merge_helper(
    merge_in: &Vec<(Scalar, Scalar, Scalar)>,
) -> Result<(Vec<(Scalar, Scalar, Scalar)>, Vec<(Scalar, Scalar, Scalar)>), SpacesuitError> {
    if merge_in.len() < 2 {
        return Ok((vec![], merge_in.clone()));
    }

    // The number of 2-merge gadgets that will be created
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
        let mut C = A.clone();
        C.0.conditional_assign(&Scalar::zero(), same_flavor);
        C.1.conditional_assign(&Scalar::zero(), same_flavor);
        C.2.conditional_assign(&Scalar::zero(), same_flavor);
        merge_out.push(C);

        // If same_flavor, merge: D.q = A.q + B.q, D.a = A.a, D.t = A.t.
        // Else, move: D = B.
        let mut D = B.clone();
        D.0.conditional_assign(&(A.0 + B.0), same_flavor);
        D.1.conditional_assign(&A.1, same_flavor);
        D.2.conditional_assign(&A.2, same_flavor);
        merge_mid.push(D);

        A = D;
        B = merge_in[min(i + 2, merge_count)];
    }

    // Move the last merge_mid to be the last merge_out, to match the protocol definition
    match merge_mid.pop() {
        Some(val) => merge_out.push(val),
        None => return Err(SpacesuitError::InvalidR1CSConstruction),
    }

    Ok((merge_mid, merge_out))
}

fn append_values(values: &mut Vec<Scalar>, list: &Vec<(Scalar, Scalar, Scalar)>) {
    for i in 0..list.len() {
        values.push(list[i].0);
        values.push(list[i].1);
        values.push(list[i].2);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn zero() -> (Scalar, Scalar, Scalar) {
        (Scalar::zero(), Scalar::zero(), Scalar::zero())
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
            vec![peso(2), yuan(1)]
        );
        // k = 3
        assert_eq!(
            shuffle_helper(&vec![yuan(1), peso(3), yuan(2)]),
            vec![peso(3), yuan(1), yuan(2)]
        );
        // k = 4
        assert_eq!(
            shuffle_helper(&vec![yuan(1), peso(3), yuan(2), peso(4)]),
            vec![peso(3), peso(4), yuan(1), yuan(2)]
        );
        assert_eq!(
            shuffle_helper(&vec![yuan(1), peso(3), peso(4), yuan(2)]),
            vec![peso(3), peso(4), yuan(1), yuan(2)]
        );
        assert_eq!(
            shuffle_helper(&vec![yuan(1), peso(3), zero(), yuan(2)]),
            vec![zero(), peso(3), yuan(1), yuan(2)]
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
