use bulletproofs::circuit_proof::assignment::Assignment;
use bulletproofs::circuit_proof::r1cs::{ConstraintSystem, LinearCombination, Variable};
use bulletproofs::transcript::TranscriptProtocol;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;

pub struct Shuffle {}

impl Shuffle {
    fn fill_cs(
        cs: &mut ConstraintSystem,
        transcript: &mut Transcript,
        in_0: (Variable, Assignment),
        in_1: (Variable, Assignment),
        out_0: (Variable, Assignment),
        out_1: (Variable, Assignment),
    ) {
        let one = Scalar::one();
        let zer = Scalar::zero();
        let r = transcript.challenge_scalar(b"shuffle challenge");

        // create variables for multiplication 1
        let (mul1_left, mul1_right, mul1_out) =
            cs.assign_multiplier(in_0.1 - r, in_1.1 - r, (in_0.1 - r) * (in_1.1 - r));
        // mul1_left = in_0 - r
        cs.add_constraint(LinearCombination::new(
            vec![(in_0.0, one), (mul1_left, -one)],
            -r,
        ));
        // mul1_right = in_1 - r
        cs.add_constraint(LinearCombination::new(
            vec![(in_1.0, one), (mul1_right, -one)],
            -r,
        ));

        // create variables for multiplication 2
        let (mul2_left, mul2_right, mul2_out) =
            cs.assign_multiplier(out_0.1 - r, out_1.1 - r, (out_0.1 - r) * (out_1.1 - r));
        // mul2_left = out_0 - r
        cs.add_constraint(LinearCombination::new(
            vec![(out_0.0, one), (mul2_left, -one)],
            -r,
        ));
        // mul2_right = out_1 - r
        cs.add_constraint(LinearCombination::new(
            vec![(out_1.0, one), (mul2_right, -one)],
            -r,
        ));
        // mul1_out = mul2_out
        cs.add_constraint(LinearCombination::new(
            vec![(mul1_out, one), (mul2_out, -one)],
            zer,
        ));
    }
}

pub struct Merge {}

impl Merge {
    fn fill_cs(
        cs: &mut ConstraintSystem,
        transcript: &mut Transcript,
        in_0: (Variable, Assignment),
        in_1: (Variable, Assignment),
        out_0: (Variable, Assignment),
        out_1: (Variable, Assignment),
        type_0: (Variable, Assignment),
        type_1: (Variable, Assignment),
    ) {
        let one = Scalar::one();
        let zer = Scalar::zero();
        let r = transcript.challenge_scalar(b"merge challenge");

        // create variables for multiplication
        let (mul_left, mul_right, mul_out) = cs.assign_multiplier(
            in_0.1 * (-one) + in_1.1 * (-r) + out_0.1 + out_1.1 * (r),
            in_0.1 + in_1.1 + out_1.1 * (-one) + out_0.1 * (r) + type_0.1 * (-r * r) + type_1.1 * (r * r),
            Assignment::zero(),
        );
        // mul_left = in_0 * (-1) + in_1 * (-r) + out_0 + out_1 * (r)
        cs.add_constraint(LinearCombination::new(
            vec![
                (in_0.0.clone(), -one),
                (in_1.0.clone(), -r),
                (out_0.0.clone(), one),
                (out_1.0.clone(), r),
                (mul_left, -one),
            ],
            zer,
        ));
        // mul_right = in_0 + in_1 + out_1 * (-1) + out_0 * (r) + type_0 * (-r*r) + type_1 * (r*r)
        cs.add_constraint(LinearCombination::new(
            vec![
                (in_0.0, one),
                (in_1.0, one),
                (out_1.0, -one),
                (out_0.0, r),
                (type_0.0, -r * r),
                (type_1.0, r * r),
                (mul_right, -one),
            ],
            zer,
        ));
        // mul_out = 0
        cs.add_constraint(LinearCombination::new(vec![(mul_out, -one)], zer));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bulletproofs::R1CSError;
    use bulletproofs::{Generators, PedersenGenerators};
    use rand::rngs::OsRng;

    #[test]
    fn shuffle_gadget() {
        assert!(shuffle_helper(3, 6, 3, 6).is_ok());
        assert!(shuffle_helper(3, 6, 6, 3).is_ok());
        assert!(shuffle_helper(6, 6, 6, 6).is_ok());
        assert!(shuffle_helper(3, 3, 6, 3).is_err());
    }

    fn shuffle_helper(
        in_0: u64,
        in_1: u64,
        out_0: u64,
        out_1: u64,
    ) -> Result<(), R1CSError> {
        let mut rng = OsRng::new().unwrap();

        // Prover makes a `ConstraintSystem` instance representing a shuffle gadget
        let (prover_cs, mut prover_transcript, prover_gens) = shuffle_cs(
            Assignment::from(in_0),
            Assignment::from(in_1),
            Assignment::from(out_0),
            Assignment::from(out_1),
        );
        // Prover makes a proof using prover_cs
        let v_blinding: Vec<Scalar> = (0..prover_cs.commitments_count())
            .map(|_| Scalar::random(&mut rng))
            .collect();
        let (proof, verifier_input) =
            prover_cs.prove(&v_blinding, &prover_gens, &mut prover_transcript, &mut rng)?;

        // Verifier makes a `ConstraintSystem` instance representing a shuffle gadget
        let (verifier_cs, mut verifier_transcript, verifier_gens) = shuffle_cs(
            Assignment::Missing(),
            Assignment::Missing(),
            Assignment::Missing(),
            Assignment::Missing(),
        );
        Ok(verifier_cs.verify(
            &proof,
            &verifier_input,
            &verifier_gens,
            &mut verifier_transcript,
            &mut rng,
        )?)
    }

    fn shuffle_cs(
        in_0: Assignment,
        in_1: Assignment,
        out_0: Assignment,
        out_1: Assignment,
    ) -> (ConstraintSystem, Transcript, Generators) {
        let mut cs = ConstraintSystem::new();
        let mut transcript = Transcript::new(b"ShuffleTest");
        let (in_0_var, in_1_var) = cs.assign_uncommitted(in_0, in_1);
        let (out_0_var, out_1_var) = cs.assign_uncommitted(out_0, out_1);

        Shuffle::fill_cs(
            &mut cs,
            &mut transcript,
            (in_0_var, in_0),
            (in_1_var, in_1),
            (out_0_var, out_0),
            (out_1_var, out_1),
        );
        let generators =
            Generators::new(PedersenGenerators::default(), cs.multiplications_count(), 1);

        (cs, transcript, generators)
    }

    #[test]
    fn merge_gadget() {
        let dollar = 77;
        let yuan = 88;
        // no merge, different asset types
        assert!(merge_helper(3, 6, 3, 6, dollar, yuan).is_ok());
        // merge, same asset types
        assert!(merge_helper(3, 6, 0, 9, dollar, dollar).is_ok());
        // no merge, same asset types
        assert!(merge_helper(6, 6, 6, 6, dollar, yuan).is_ok());
        // error when merging different asset types
        assert!(merge_helper(3, 3, 0, 6, dollar, yuan).is_err());
        // error when creating more value (same asset types)
        assert!(merge_helper(3, 3, 3, 6, dollar, dollar).is_err());
        // error when creating more value (different asset types)
        assert!(merge_helper(3, 3, 3, 6, dollar, yuan).is_err());
        // error when not merging same asset types
        // assert!(merge_helper(3, 3, 3, 3, dollar, dollar).is_err());    
    }

    fn merge_helper(
        in_0: u64,
        in_1: u64,
        out_0: u64,
        out_1: u64,
        type_0: u64, 
        type_1: u64,
    ) -> Result<(), R1CSError> {
        let mut rng = OsRng::new().unwrap();

        // Prover makes a `ConstraintSystem` instance representing a merge gadget
        let (prover_cs, mut prover_transcript, prover_gens) = merge_cs(
            Assignment::from(in_0),
            Assignment::from(in_1),
            Assignment::from(out_0),
            Assignment::from(out_1),
            Assignment::from(type_0),
            Assignment::from(type_1),
        );
        // Prover makes a proof using prover_cs
        let v_blinding: Vec<Scalar> = (0..prover_cs.commitments_count())
            .map(|_| Scalar::random(&mut rng))
            .collect();
        let (proof, verifier_input) =
            prover_cs.prove(&v_blinding, &prover_gens, &mut prover_transcript, &mut rng)?;

        // Verifier makes a `ConstraintSystem` instance representing a merge gadget
        let (verifier_cs, mut verifier_transcript, verifier_gens) = merge_cs(
            Assignment::Missing(),
            Assignment::Missing(),
            Assignment::Missing(),
            Assignment::Missing(),
            Assignment::Missing(),
            Assignment::Missing(),
        );
        Ok(verifier_cs.verify(
            &proof,
            &verifier_input,
            &verifier_gens,
            &mut verifier_transcript,
            &mut rng,
        )?)
    }

    fn merge_cs(
        in_0: Assignment,
        in_1: Assignment,
        out_0: Assignment,
        out_1: Assignment,
        type_0: Assignment,
        type_1: Assignment,
    ) -> (ConstraintSystem, Transcript, Generators) {
        let mut cs = ConstraintSystem::new();
        let mut transcript = Transcript::new(b"MergeTest");
        let (in_0_var, in_1_var) = cs.assign_uncommitted(in_0, in_1);
        let (out_0_var, out_1_var) = cs.assign_uncommitted(out_0, out_1);
        let (type_0_var, type_1_var) = cs.assign_uncommitted(type_0, type_1);

        Merge::fill_cs(
            &mut cs,
            &mut transcript,
            (in_0_var, in_0),
            (in_1_var, in_1),
            (out_0_var, out_0),
            (out_1_var, out_1),
            (type_0_var, type_0),
            (type_1_var, type_1),
        ); 
        let generators =
            Generators::new(PedersenGenerators::default(), cs.multiplications_count(), 1);

        (cs, transcript, generators)        
    }
}
