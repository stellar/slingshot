use super::value_shuffle;
use bulletproofs::r1cs::{ConstraintSystem, R1CSError};
use std::cmp::{max, min};
use value::{AllocatedValue, Value};

/// Enforces that the values in `y` are a valid reordering of the values in `x`,
/// allowing for padding (zero values) in x that can be omitted in y (or the other way around).
pub fn fill_cs<CS: ConstraintSystem>(
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

    value_shuffle::fill_cs(cs, x, y)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bulletproofs::r1cs::{Prover, Verifier};
    use bulletproofs::{BulletproofGens, PedersenGens};
    use merlin::Transcript;
    use value::{ProverCommittable, VerifierCommittable};

    #[test]
    fn padded_shuffle() {
        // k=2, with interspersed empty values
        assert!(
            padded_shuffle_helper(vec![peso(1), zero(), yuan(4)], vec![peso(1), yuan(4)]).is_ok()
        );
        assert!(
            padded_shuffle_helper(
                vec![peso(1), yuan(4)],
                vec![zero(), yuan(4), zero(), peso(1)]
            )
            .is_ok()
        );
        assert!(
            padded_shuffle_helper(
                vec![yuan(4), zero(), zero(), yuan(4)],
                vec![zero(), yuan(4), yuan(4)]
            )
            .is_ok()
        );

        // k=3, with interspersed empty values
        assert!(
            padded_shuffle_helper(
                vec![yuan(1), yuan(4), zero(), peso(8)],
                vec![yuan(1), yuan(4), peso(8)]
            )
            .is_ok()
        );
        assert!(
            padded_shuffle_helper(
                vec![yuan(1), yuan(4), peso(8)],
                vec![yuan(1), zero(), peso(8), zero(), yuan(4)]
            )
            .is_ok()
        );
        assert!(
            padded_shuffle_helper(
                vec![yuan(1), yuan(4), zero(), peso(8)],
                vec![zero(), zero(), yuan(4), yuan(1), peso(8)]
            )
            .is_ok()
        );
        assert!(padded_shuffle_helper(vec![peso(1), yuan(4)], vec![yuan(4), peso(2)]).is_err());
        assert!(
            padded_shuffle_helper(
                vec![yuan(1), yuan(4), peso(8)],
                vec![
                    zero(),
                    Value {
                        q: 1,
                        f: 0u64.into(),
                    },
                    yuan(4),
                    yuan(1),
                    peso(8)
                ]
            )
            .is_err()
        );
    }

    // Helper functions to make the tests easier to read
    fn yuan(q: u64) -> Value {
        Value {
            q,
            f: 888u64.into(),
        }
    }
    fn peso(q: u64) -> Value {
        Value {
            q,
            f: 666u64.into(),
        }
    }
    fn zero() -> Value {
        Value::zero()
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

            assert!(fill_cs(&mut prover, input_vars, output_vars).is_ok());

            let proof = prover.prove()?;
            (proof, input_com, output_com)
        };

        // Verifier makes a `ConstraintSystem` instance representing a shuffle gadget
        let mut verifier_transcript = Transcript::new(b"PaddedShuffleTest");
        let mut verifier = Verifier::new(&bp_gens, &pc_gens, &mut verifier_transcript);

        let input_vars = input_com.commit(&mut verifier);
        let output_vars = output_com.commit(&mut verifier);

        // Verifier adds constraints to the constraint system
        assert!(fill_cs(&mut verifier, input_vars, output_vars).is_ok());

        // Verifier verifies proof
        Ok(verifier.verify(&proof)?)
    }
}
