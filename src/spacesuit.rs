#![allow(non_snake_case)]

use bulletproofs::r1cs::{Prover, R1CSProof, Verifier};
use bulletproofs::{BulletproofGens, PedersenGens};
use curve25519_dalek::scalar::Scalar;
use error::SpacesuitError;
use gadgets::transaction;
use merlin::Transcript;
use rand::CryptoRng;
use rand::Rng;
use subtle::{ConditionallySelectable, ConstantTimeEq};
use value::*;

pub struct SpacesuitProof(R1CSProof);

pub fn prove<R: Rng + CryptoRng>(
    bp_gens: &BulletproofGens,
    pc_gens: &PedersenGens,
    inputs: &Vec<Value>,
    outputs: &Vec<Value>,
    rng: &mut R,
) -> Result<
    (
        SpacesuitProof,
        Vec<CommittedValue>,
        Vec<CommittedValue>,
        Vec<CommittedValue>,
        Vec<CommittedValue>,
        Vec<CommittedValue>,
        Vec<CommittedValue>,
        Vec<CommittedValue>,
        Vec<CommittedValue>,
    ),
    SpacesuitError,
>
where
    R: rand::RngCore,
{
    // Compute all intermediate values and add them to inputs and outputs,
    // returning raw variable assignments to be passed to the prover.
    let (tx_in, merge_in, merge_mid, merge_out, split_in, split_mid, split_out, tx_out) =
        compute_committed_values(inputs, outputs)?;

    let mut prover_transcript = Transcript::new(b"TransactionTest");
    let mut prover = Prover::new(&bp_gens, &pc_gens, &mut prover_transcript);

    let (tx_in_com, tx_in_vars) = tx_in.commit(&mut prover, rng);
    let (merge_in_com, merge_in_vars) = merge_in.commit(&mut prover, rng);
    let (merge_mid_com, merge_mid_vars) = merge_mid.commit(&mut prover, rng);
    let (merge_out_com, merge_out_vars) = merge_out.commit(&mut prover, rng);
    let (split_in_com, split_in_vars) = split_in.commit(&mut prover, rng);
    let (split_mid_com, split_mid_vars) = split_mid.commit(&mut prover, rng);
    let (split_out_com, split_out_vars) = split_out.commit(&mut prover, rng);
    let (tx_out_com, tx_out_vars) = tx_out.commit(&mut prover, rng);

    transaction::fill_cs(
        &mut prover,
        tx_in_vars,
        merge_in_vars,
        merge_mid_vars,
        merge_out_vars,
        split_in_vars,
        split_mid_vars,
        split_out_vars,
        tx_out_vars,
    )?;
    let proof = SpacesuitProof(prover.prove()?);

    Ok((
        proof,
        tx_in_com,
        merge_in_com,
        merge_mid_com,
        merge_out_com,
        split_in_com,
        split_mid_com,
        split_out_com,
        tx_out_com,
    ))
}

pub fn verify(
    bp_gens: &BulletproofGens,
    pc_gens: &PedersenGens,
    proof: &SpacesuitProof,
    tx_in_com: &Vec<CommittedValue>,
    merge_in_com: &Vec<CommittedValue>,
    merge_mid_com: &Vec<CommittedValue>,
    merge_out_com: &Vec<CommittedValue>,
    split_in_com: &Vec<CommittedValue>,
    split_mid_com: &Vec<CommittedValue>,
    split_out_com: &Vec<CommittedValue>,
    tx_out_com: &Vec<CommittedValue>,
) -> Result<(), SpacesuitError> {
    // TBD: check the correctness of the size of the commitments

    // Verifier makes a `ConstraintSystem` instance representing a merge gadget
    let mut verifier_transcript = Transcript::new(b"TransactionTest");
    let mut verifier = Verifier::new(&bp_gens, &pc_gens, &mut verifier_transcript);

    let tx_in_vars = tx_in_com.commit(&mut verifier);
    let merge_in_vars = merge_in_com.commit(&mut verifier);
    let merge_mid_vars = merge_mid_com.commit(&mut verifier);
    let merge_out_vars = merge_out_com.commit(&mut verifier);
    let split_in_vars = split_in_com.commit(&mut verifier);
    let split_mid_vars = split_mid_com.commit(&mut verifier);
    let split_out_vars = split_out_com.commit(&mut verifier);
    let tx_out_vars = tx_out_com.commit(&mut verifier);

    assert!(
        transaction::fill_cs(
            &mut verifier,
            tx_in_vars,
            merge_in_vars,
            merge_mid_vars,
            merge_out_vars,
            split_in_vars,
            split_mid_vars,
            split_out_vars,
            tx_out_vars,
        )
        .is_ok()
    );

    Ok(verifier.verify(&proof.0)?)
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
) -> Result<
    (
        Vec<Value>,
        Vec<Value>,
        Vec<Value>,
        Vec<Value>,
        Vec<Value>,
        Vec<Value>,
        Vec<Value>,
        Vec<Value>,
    ),
    SpacesuitError,
> {
    // Inputs, intermediates, and outputs of merge gadget
    let merge_in = shuffle_helper(inputs);
    let (merge_mid, merge_out) = merge_helper(&merge_in)?;

    // Inputs, intermediates, and outputs of split gadget
    let split_out = shuffle_helper(outputs);
    let (split_mid, split_in) = split_helper(&split_out)?;

    Ok((
        inputs.to_vec(),
        merge_in,
        merge_mid,
        merge_out,
        split_in,
        split_mid,
        split_out,
        outputs.to_vec(),
    ))
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
