use bulletproofs::circuit_proof::assignment::Assignment;
use bulletproofs::circuit_proof::r1cs::{ConstraintSystem, LinearCombination};
use bulletproofs::transcript::TranscriptProtocol;
// use bulletproofs::Generators;
// use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;

pub struct Shuffle {}

impl Shuffle {
    pub fn fill_prover_cs(
        transcript: &mut Transcript,
        cs: &mut ConstraintSystem,
        in_0: Scalar,
        in_1: Scalar,
        out_0: Scalar,
        out_1: Scalar,
    ) {
        // let v_blinding: Vec<Scalar> = (0..cs.commitments_count())
        //     .map(|_| Scalar::random(rng))
        //     .collect();
        // for V_i in V.iter() {
        //     transcript.commit_bytes(b"v", V_i.compress().as_bytes());
        // }

        let r = transcript.challenge_scalar(b"shuffle challenge");

        Shuffle::fill_cs(
            cs,
            r,
            Assignment::new(in_0),
            Assignment::new(in_1),
            Assignment::new(out_0),
            Assignment::new(out_1),
        );
    }

    fn fill_cs(
        cs: &mut ConstraintSystem,
        r: Scalar,
        in_0: Assignment,
        in_1: Assignment,
        out_0: Assignment,
        out_1: Assignment,
    ) {
        let one = Scalar::one();
        let zer = Scalar::zero();

        let (in_0_var, in_1_var) = cs.assign_uncommitted(in_0, in_1);
        let (out_0_var, out_1_var) = cs.assign_uncommitted(out_0, out_1);

        let (mul1_left, mul1_right, mul1_out) = cs.assign_multiplier(
            in_0.clone() - r,
            in_1.clone() - r,
            (in_0.clone() - r) * (in_1.clone() - r),
        );
        let (mul2_left, mul2_right, mul2_out) = cs.assign_multiplier(
            out_0.clone() - r,
            out_1.clone() - r,
            (out_0.clone() - r) * (out_1.clone() - r),
        );

        // mul1_left = in_0_var - r
        cs.add_constraint(LinearCombination::new(
            vec![(in_0_var, one), (mul1_left, one)],
            -r,
        ));
        // mul1_right = in_1_var - r
        cs.add_constraint(LinearCombination::new(
            vec![(in_1_var, one), (mul1_right, one)],
            -r,
        ));
        // mul2_left = out_0_var - r
        cs.add_constraint(LinearCombination::new(
            vec![(out_0_var, one), (mul2_left, one)],
            -r,
        ));
        // mul2_right = out_1_var - r
        cs.add_constraint(LinearCombination::new(
            vec![(out_1_var, one), (mul2_right, one)],
            -r,
        ));
        // mul1_out = mul2_out
        cs.add_constraint(LinearCombination::new(
            vec![(mul1_out, one), (mul2_out, one)],
            zer,
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
