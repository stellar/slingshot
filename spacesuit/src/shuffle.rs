use bulletproofs::r1cs::{ConstraintSystem, R1CSError, RandomizedConstraintSystem, Variable};
use core::cmp::{max, min};
use value::{AllocatedValue, Value};

/// Enforces that the output variables `y` are a valid reordering of the inputs variables `x`.
pub fn scalar_shuffle<CS: ConstraintSystem>(
    cs: &mut CS,
    x: Vec<Variable>,
    y: Vec<Variable>,
) -> Result<(), R1CSError> {
    if x.len() != y.len() {
        return Err(R1CSError::GadgetError {
            description: "x and y vector lengths do not match in scalar shuffle".to_string(),
        });
    }

    let k = x.len();
    if k == 1 {
        cs.constrain(y[0] - x[0]);
        return Ok(());
    }

    cs.specify_randomized_constraints(move |cs| {
        let z = cs.challenge_scalar(b"shuffle challenge");

        // Make last x multiplier for i = k-1 and k-2
        let (_, _, last_mulx_out) = cs.multiply(x[k - 1] - z, x[k - 2] - z);

        // Make multipliers for x from i == [0, k-3]
        let first_mulx_out = (0..k - 2).rev().fold(last_mulx_out, |prev_out, i| {
            let (_, _, o) = cs.multiply(prev_out.into(), x[i] - z);
            o
        });

        // Make last y multiplier for i = k-1 and k-2
        let (_, _, last_muly_out) = cs.multiply(y[k - 1] - z, y[k - 2] - z);

        // Make multipliers for y from i == [0, k-3]
        let first_muly_out = (0..k - 2).rev().fold(last_muly_out, |prev_out, i| {
            let (_, _, o) = cs.multiply(prev_out.into(), y[i] - z);
            o
        });

        // Constrain last x mul output and last y mul output to be equal
        cs.constrain(first_mulx_out - first_muly_out);

        Ok(())
    })
}

/// Enforces that the output values `y` are a valid reordering of the inputs values `x`.
/// The inputs and outputs are all of the `AllocatedValue` type, which contains the fields
/// quantity, issuer, and tag. Works for `k` inputs and `k` outputs.
pub fn value_shuffle<CS: ConstraintSystem>(
    cs: &mut CS,
    x: Vec<AllocatedValue>,
    y: Vec<AllocatedValue>,
) -> Result<(), R1CSError> {
    if x.len() != y.len() {
        return Err(R1CSError::GadgetError {
            description: "x and y vector lengths do not match in value shuffle".to_string(),
        });
    }
    let k = x.len();
    if k == 1 {
        let x = x[0];
        let y = y[0];
        cs.constrain(y.q - x.q);
        cs.constrain(y.f - x.f);
        return Ok(());
    }

    cs.specify_randomized_constraints(move |cs| {
        let w = cs.challenge_scalar(b"k-value shuffle challenge");
        let mut x_scalars = Vec::with_capacity(k);
        let mut y_scalars = Vec::with_capacity(k);

        for i in 0..k {
            let (x_i_var, y_i_var, _) = cs.multiply(x[i].q + x[i].f * w, y[i].q + y[i].f * w);
            x_scalars.push(x_i_var);
            y_scalars.push(y_i_var);
        }

        scalar_shuffle(cs, x_scalars, y_scalars)
    })
}

/// Enforces that the values in `y` are a valid reordering of the values in `x`,
/// allowing for padding (zero values) in x that can be omitted in y (or the other way around).
pub fn padded_shuffle<CS: ConstraintSystem>(
    cs: &mut CS,
    mut x: Vec<AllocatedValue>,
    mut y: Vec<AllocatedValue>,
) -> Result<(), R1CSError> {
    let m = x.len();
    let n = y.len();

    // Number of values to be padded on one side of the shuffle
    let pad_count = max(m, n) - min(m, n);
    let mut values = Vec::with_capacity(pad_count);

    for _ in 0..pad_count {
        // Make an allocated value whose fields are all zero.
        let zero_val = Value::zero().allocate(cs)?;
        // Constrain each of the variables to be equal to zero.
        cs.constrain(zero_val.q.into());
        cs.constrain(zero_val.f.into());
        values.push(zero_val);
    }

    if m > n {
        y.append(&mut values);
    } else if m < n {
        x.append(&mut values);
    }

    value_shuffle(cs, x, y)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bulletproofs::r1cs::{Prover, Verifier};
    use bulletproofs::{BulletproofGens, PedersenGens};
    use curve25519_dalek::ristretto::CompressedRistretto;
    use curve25519_dalek::scalar::Scalar;
    use merlin::Transcript;
    use value::{ProverCommittable, VerifierCommittable};

    #[test]
    fn test_scalar_shuffle() {
        // k=1
        assert!(scalar_shuffle_helper(vec![3], vec![3]).is_ok());
        assert!(scalar_shuffle_helper(vec![6], vec![6]).is_ok());
        assert!(scalar_shuffle_helper(vec![3], vec![6]).is_err());
        // k=2
        assert!(scalar_shuffle_helper(vec![3, 6], vec![3, 6]).is_ok());
        assert!(scalar_shuffle_helper(vec![3, 6], vec![6, 3]).is_ok());
        assert!(scalar_shuffle_helper(vec![6, 6], vec![6, 6]).is_ok());
        assert!(scalar_shuffle_helper(vec![3, 3], vec![6, 3]).is_err());
        // k=3
        assert!(scalar_shuffle_helper(vec![3, 6, 10], vec![3, 6, 10]).is_ok());
        assert!(scalar_shuffle_helper(vec![3, 6, 10], vec![3, 10, 6]).is_ok());
        assert!(scalar_shuffle_helper(vec![3, 6, 10], vec![6, 3, 10]).is_ok());
        assert!(scalar_shuffle_helper(vec![3, 6, 10], vec![6, 10, 3]).is_ok());
        assert!(scalar_shuffle_helper(vec![3, 6, 10], vec![10, 3, 6]).is_ok());
        assert!(scalar_shuffle_helper(vec![3, 6, 10], vec![10, 6, 3]).is_ok());
        assert!(scalar_shuffle_helper(vec![3, 6, 10], vec![30, 6, 10]).is_err());
        assert!(scalar_shuffle_helper(vec![3, 6, 10], vec![3, 60, 10]).is_err());
        assert!(scalar_shuffle_helper(vec![3, 6, 10], vec![3, 6, 100]).is_err());
        // k=4
        assert!(scalar_shuffle_helper(vec![3, 6, 10, 15], vec![3, 6, 10, 15]).is_ok());
        assert!(scalar_shuffle_helper(vec![3, 6, 10, 15], vec![15, 6, 10, 3]).is_ok());
        assert!(scalar_shuffle_helper(vec![3, 6, 10, 15], vec![3, 6, 10, 3]).is_err());
        // k=5
        assert!(scalar_shuffle_helper(vec![3, 6, 10, 15, 17], vec![3, 6, 10, 15, 17]).is_ok());
        assert!(scalar_shuffle_helper(vec![3, 6, 10, 15, 17], vec![10, 17, 3, 15, 6]).is_ok());
        assert!(scalar_shuffle_helper(vec![3, 6, 10, 15, 17], vec![3, 6, 10, 15, 3]).is_err());
    }

    // This test allocates variables for the high-level variables, to check that high-level
    // variable allocation and commitment works.
    fn scalar_shuffle_helper(input: Vec<u64>, output: Vec<u64>) -> Result<(), R1CSError> {
        // Common
        let pc_gens = PedersenGens::default();
        let bp_gens = BulletproofGens::new(128, 1);

        // Prover's scope
        let (proof, input_com, output_com) = {
            // Prover makes a `ConstraintSystem` instance representing a shuffle gadget
            let mut prover_transcript = Transcript::new(b"ShuffleTest");
            let mut rng = rand::thread_rng();

            let mut prover = Prover::new(&bp_gens, &pc_gens, &mut prover_transcript);

            let (input_com, input_vars): (Vec<CompressedRistretto>, Vec<Variable>) = input
                .iter()
                .map(|v| prover.commit(Scalar::from(*v), Scalar::random(&mut rng)))
                .unzip();
            let (output_com, output_vars): (Vec<CompressedRistretto>, Vec<Variable>) = output
                .iter()
                .map(|v| prover.commit(Scalar::from(*v), Scalar::random(&mut rng)))
                .unzip();

            scalar_shuffle(&mut prover, input_vars, output_vars)?;
            let proof = prover.prove()?;

            (proof, input_com, output_com)
        };

        // Verifier makes a `ConstraintSystem` instance representing a shuffle gadget
        let mut verifier_transcript = Transcript::new(b"ShuffleTest");
        let mut verifier = Verifier::new(&bp_gens, &pc_gens, &mut verifier_transcript);

        let input_vars: Vec<Variable> = input_com.iter().map(|com| verifier.commit(*com)).collect();
        let output_vars: Vec<Variable> =
            output_com.iter().map(|com| verifier.commit(*com)).collect();

        // Verifier adds constraints to the constraint system
        scalar_shuffle(&mut verifier, input_vars, output_vars)?;

        Ok(verifier.verify(&proof)?)
    }

    // Helper functions to make the tests easier to read
    fn yuan(q: u64) -> Value {
        Value {
            q: q.into(),
            f: 888u64.into(),
        }
    }
    fn peso(q: u64) -> Value {
        Value {
            q: q.into(),
            f: 666u64.into(),
        }
    }
    fn euro(q: u64) -> Value {
        Value {
            q: q.into(),
            f: 444u64.into(),
        }
    }
    fn wrong() -> Value {
        Value {
            q: 999u64.into(),
            f: 222u64.into(),
        }
    }
    fn zero() -> Value {
        Value::zero()
    }

    #[test]
    fn test_value_shuffle() {
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
        assert!(value_shuffle_helper(
            vec![peso(1), yuan(4), euro(8)],
            vec![peso(1), yuan(4), euro(8)]
        )
        .is_ok());
        assert!(value_shuffle_helper(
            vec![peso(1), yuan(4), euro(8)],
            vec![peso(1), euro(8), yuan(4)]
        )
        .is_ok());
        assert!(value_shuffle_helper(
            vec![peso(1), yuan(4), euro(8)],
            vec![yuan(4), peso(1), euro(8)]
        )
        .is_ok());
        assert!(value_shuffle_helper(
            vec![peso(1), yuan(4), euro(8)],
            vec![yuan(4), euro(8), peso(1)]
        )
        .is_ok());
        assert!(value_shuffle_helper(
            vec![peso(1), yuan(4), euro(8)],
            vec![euro(8), peso(1), yuan(4)]
        )
        .is_ok());
        assert!(value_shuffle_helper(
            vec![peso(1), yuan(4), euro(8)],
            vec![euro(8), yuan(4), peso(1)]
        )
        .is_ok());
        assert!(value_shuffle_helper(
            vec![peso(1), yuan(4), euro(8)],
            vec![wrong(), yuan(4), euro(8)]
        )
        .is_err());
        assert!(value_shuffle_helper(
            vec![peso(1), yuan(4), euro(8)],
            vec![peso(1), wrong(), euro(8)]
        )
        .is_err());
        assert!(value_shuffle_helper(
            vec![peso(1), yuan(4), euro(8)],
            vec![peso(1), yuan(4), wrong()]
        )
        .is_err());
    }

    fn value_shuffle_helper(input: Vec<Value>, output: Vec<Value>) -> Result<(), R1CSError> {
        // Common
        let pc_gens = PedersenGens::default();
        let bp_gens = BulletproofGens::new(128, 1);

        // Prover's scope
        let (proof, input_com, output_com) = {
            let mut prover_transcript = Transcript::new(b"ValueShuffleTest");
            let mut rng = rand::thread_rng();

            let mut prover = Prover::new(&bp_gens, &pc_gens, &mut prover_transcript);
            let (input_com, input_vars) = input.commit(&mut prover, &mut rng);
            let (output_com, output_vars) = output.commit(&mut prover, &mut rng);

            assert!(value_shuffle(&mut prover, input_vars, output_vars).is_ok());

            let proof = prover.prove()?;
            (proof, input_com, output_com)
        };

        // Verifier makes a `ConstraintSystem` instance representing a shuffle gadget
        let mut verifier_transcript = Transcript::new(b"ValueShuffleTest");
        let mut verifier = Verifier::new(&bp_gens, &pc_gens, &mut verifier_transcript);

        let input_vars = input_com.commit(&mut verifier);
        let output_vars = output_com.commit(&mut verifier);

        // Verifier adds constraints to the constraint system
        assert!(value_shuffle(&mut verifier, input_vars, output_vars).is_ok());

        // Verifier verifies proof
        Ok(verifier.verify(&proof)?)
    }

    #[test]
    fn test_padded_shuffle() {
        // k=2, with interspersed empty values
        assert!(
            padded_shuffle_helper(vec![peso(1), zero(), yuan(4)], vec![peso(1), yuan(4)]).is_ok()
        );
        assert!(padded_shuffle_helper(
            vec![peso(1), yuan(4)],
            vec![zero(), yuan(4), zero(), peso(1)]
        )
        .is_ok());
        assert!(padded_shuffle_helper(
            vec![yuan(4), zero(), zero(), yuan(4)],
            vec![zero(), yuan(4), yuan(4)]
        )
        .is_ok());

        // k=3, with interspersed empty values
        assert!(padded_shuffle_helper(
            vec![yuan(1), yuan(4), zero(), peso(8)],
            vec![yuan(1), yuan(4), peso(8)]
        )
        .is_ok());
        assert!(padded_shuffle_helper(
            vec![yuan(1), yuan(4), peso(8)],
            vec![yuan(1), zero(), peso(8), zero(), yuan(4)]
        )
        .is_ok());
        assert!(padded_shuffle_helper(
            vec![yuan(1), yuan(4), zero(), peso(8)],
            vec![zero(), zero(), yuan(4), yuan(1), peso(8)]
        )
        .is_ok());
        assert!(padded_shuffle_helper(vec![peso(1), yuan(4)], vec![yuan(4), peso(2)]).is_err());
        assert!(padded_shuffle_helper(
            vec![yuan(1), yuan(4), peso(8)],
            vec![
                zero(),
                Value {
                    q: 1u64.into(),
                    f: 0u64.into(),
                },
                yuan(4),
                yuan(1),
                peso(8)
            ]
        )
        .is_err());
    }

    fn padded_shuffle_helper(input: Vec<Value>, output: Vec<Value>) -> Result<(), R1CSError> {
        // Common
        let pc_gens = PedersenGens::default();
        let bp_gens = BulletproofGens::new(128, 1);

        // Prover's scope
        let (proof, input_com, output_com) = {
            let mut prover_transcript = Transcript::new(b"PaddedShuffleTest");
            let mut rng = rand::thread_rng();

            let mut prover = Prover::new(&bp_gens, &pc_gens, &mut prover_transcript);
            let (input_com, input_vars) = input.commit(&mut prover, &mut rng);
            let (output_com, output_vars) = output.commit(&mut prover, &mut rng);

            assert!(padded_shuffle(&mut prover, input_vars, output_vars).is_ok());

            let proof = prover.prove()?;
            (proof, input_com, output_com)
        };

        // Verifier makes a `ConstraintSystem` instance representing a shuffle gadget
        let mut verifier_transcript = Transcript::new(b"PaddedShuffleTest");
        let mut verifier = Verifier::new(&bp_gens, &pc_gens, &mut verifier_transcript);

        let input_vars = input_com.commit(&mut verifier);
        let output_vars = output_com.commit(&mut verifier);

        // Verifier adds constraints to the constraint system
        assert!(padded_shuffle(&mut verifier, input_vars, output_vars).is_ok());

        // Verifier verifies proof
        Ok(verifier.verify(&proof)?)
    }
}
