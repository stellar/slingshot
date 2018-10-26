#![allow(non_snake_case)]

use bulletproofs::r1cs::ConstraintSystem;
use curve25519_dalek::scalar::Scalar;
use gadgets::{merge, padded_shuffle, range_proof, split, value_shuffle};
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
    padded_shuffle::fill_cs(cs, merge_out, split_in.clone())?;

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

// Takes in the ungrouped side of shuffle, returns the values grouped by flavor.
// TODO: do this in constant time
fn shuffle_helper(shuffle_in: &Vec<(u64, u64, u64)>) -> Vec<(u64, u64, u64)> {
    let mut shuffle_out = shuffle_in.clone();
    shuffle_out.sort_unstable_by_key(|(_q, a, t)| (a.clone(), t.clone()));
    shuffle_out
}

// takes in split_out, returns split_mid and split_in
fn split_helper(
    split_out: &Vec<(u64, u64, u64)>,
) -> Result<(Vec<(u64, u64, u64)>, Vec<(u64, u64, u64)>), SpacesuitError> {
    let mut split_out_rev = split_out.clone();
    split_out_rev.reverse();
    let (mut split_mid, mut split_in) = merge_helper(&split_out_rev)?;
    split_mid.reverse();
    split_in.reverse();

    Ok((split_mid, split_in))
}

// takes in merge_in, returns merge_mid and merge_out
fn merge_helper(
    merge_in: &Vec<(u64, u64, u64)>,
) -> Result<(Vec<(u64, u64, u64)>, Vec<(u64, u64, u64)>), SpacesuitError> {
    if merge_in.len() < 2 {
        return Ok((vec![], merge_in.clone()));
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
    match merge_mid.pop() {
        Some(val) => merge_out.push(val),
        None => return Err(SpacesuitError::InvalidR1CSConstruction),
    }

    Ok((merge_mid, merge_out))
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
            merge_helper(&vec![(1, 2, 3), (4, 5, 6)]).unwrap(),
            (vec![], vec![(1, 2, 3), (4, 5, 6)])
        );
        assert_eq!(
            merge_helper(&vec![(1, 9, 9), (3, 9, 9)]).unwrap(),
            (vec![], vec![(0, 0, 0), (4, 9, 9)])
        );
        // k = 3
        assert_eq!(
            merge_helper(&vec![(1, 2, 3), (4, 5, 6), (7, 8, 9)]).unwrap(),
            (vec![(4, 5, 6)], vec![(1, 2, 3), (4, 5, 6), (7, 8, 9)])
        );
        assert_eq!(
            merge_helper(&vec![(1, 9, 9), (3, 9, 9), (2, 8, 8)]).unwrap(),
            (vec![(4, 9, 9)], vec![(0, 0, 0), (4, 9, 9), (2, 8, 8)])
        );
        assert_eq!(
            merge_helper(&vec![(2, 8, 8), (1, 9, 9), (3, 9, 9)]).unwrap(),
            (vec![(1, 9, 9)], vec![(2, 8, 8), (0, 0, 0), (4, 9, 9)])
        );
        // k = 4
        assert_eq!(
            merge_helper(&vec![(1, 2, 3), (1, 2, 3), (4, 5, 6), (4, 5, 6)]).unwrap(),
            (
                vec![(2, 2, 3), (4, 5, 6)],
                vec![(0, 0, 0), (2, 2, 3), (0, 0, 0), (8, 5, 6)]
            )
        );
        assert_eq!(
            merge_helper(&vec![(1, 9, 9), (2, 9, 9), (3, 9, 9), (4, 9, 9)]).unwrap(),
            (
                vec![(3, 9, 9), (6, 9, 9)],
                vec![(0, 0, 0), (0, 0, 0), (0, 0, 0), (10, 9, 9)]
            )
        );
    }
}
