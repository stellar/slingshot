use bulletproofs::circuit_proof::r1cs::{ConstraintSystem, LinearCombination, Variable, Assignment};
use bulletproofs::Generators;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::ristretto::RistrettoPoint;
use rand::{CryptoRng, Rng};
use merlin::Transcript;
use super::assignment_holder::AssignmentHolder;

pub struct Shuffle {}

impl Shuffle {
    pub fn fill_prover_cs<R: Rng + CryptoRng>(
        gen: &Generators,
        rng: &mut R,
        transcript: &mut Transcript,
        cs: &mut ConstraintSystem,
        in_0: Scalar,
        in_1: Scalar,
        out_0: Scalar,
        out_1: Scalar,
    ) -> (Vec<Scalar>, Vec<RistrettoPoint>) {
        let v_blinding: Vec<Scalar> = (0..cs.commitments_count()).map(|_| Scalar::random(rng)).collect();
        // todo: propogate error
        // let V = v_blinding.iter().zip(map()gen.pedersen_generators.commit()
        let V = cs.make_V(gen, &v_blinding).unwrap();
        for V_i in V.iter() {
            transcript.commit(V_i.compress().as_bytes());
        }
        let r = transcript.challenge_scalar();

        Merge::fill_cs(cs, r, Ok(in_0), Ok(in_1), Ok(out_0), Ok(out_1));

        (v_blinding, V)
    }

    fn fill_cs(
        cs: &mut ConstraintSystem,
        r: Scalar,
        in_0: AssignmentHolder,
        in_1: AssignmentHolder,
        out_0: AssignmentHolder,
        out_1: AssignmentHolder,
    ) {
    	let (in_0_var, in_1_var) = cs.assign_uncommitted_variables(in_0, in_1);
    	let (in_0_var, in_1_var) = cs.assign_uncommitted_variables(in_0, in_1);

    	let (mul1_left, mul1_right, mul1_out) = cs.assign_multiplier();
    	let (mul2_left, mul2_right, mul2_out) = cs.assign_multiplier();

    	let lc1 = LinearCombination::new(())
        // lc_a: in_0 * (-1) + in_1 * (-c) + out_0 + out_1 * (c)
        let lc_a = LinearCombination::new(
            vec![
                (in_0.clone(), -Scalar::one()),
                (in_1.clone(), -r),
                (out_0.clone(), Scalar::one()),
                (out_1.clone(), r),
            ],
            Scalar::zero(),
        );
        // lc_b: in_0 + in_1 + out_1 * (-1) + out_0 * (c) + t_0 * (-c*c) + t_1 * (c*c)
        let lc_b = LinearCombination::new(
            vec![
                (in_0, Scalar::one()),
                (in_1, Scalar::one()),
                (out_1, -Scalar::one()),
                (out_0, r),
                (t_0, -r * r),
                (t_1, r * r),
            ],
            Scalar::zero(),
        );
        let lc_c = LinearCombination::new(vec![], Scalar::zero());

        cs.constrain(lc_a, lc_b, lc_c);
    }
}

#[cfg(test)]
mod tests {
	use super::*;

    #[test]
    fn it_works() {
    	// let r1cs_1 = ConstraintSystem::new();
    	let r1cs_2 = ConstraintSystem::new();
        assert_eq!(2 + 2, 4);
    }
}