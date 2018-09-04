use super::assignment_holder::AssignmentHolder;
use bulletproofs::circuit_proof::r1cs::{ConstraintSystem, LinearCombination};
use bulletproofs::Generators;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use rand::{CryptoRng, Rng};

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
        let v_blinding: Vec<Scalar> = (0..cs.commitments_count())
            .map(|_| Scalar::random(rng))
            .collect();
            
        // todo: propogate error
        let V = cs.make_V(gen, &v_blinding).unwrap();
        for V_i in V.iter() {
            transcript.commit_bytes(b"v", V_i.compress().as_bytes());
        }

        let mut buf = [0u8; 64];
        transcript.challenge_bytes(b"shuffle", &mut buf);
        let r = Scalar::from_bytes_mod_order_wide(&buf);

        Shuffle::fill_cs(
            cs,
            r,
            AssignmentHolder::new(in_0),
            AssignmentHolder::new(in_1),
            AssignmentHolder::new(out_0),
            AssignmentHolder::new(out_1),
        );

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
        let one = Scalar::one();
        let zer = Scalar::zero();

        let (in_0_var, in_1_var) = cs.assign_uncommitted(in_0.0, in_1.0);
        let (out_0_var, out_1_var) = cs.assign_uncommitted(out_0.0, out_1.0);

        let (mul1_left, mul1_right, mul1_out) =
            cs.assign_multiplier((in_0 - r).0, (in_1 - r).0, ((in_0 - r) * (in_1 - r)).0);
        let (mul2_left, mul2_right, mul2_out) =
            cs.assign_multiplier((out_0 - r).0, (out_1 - r).0, ((out_0 - r) * (out_1 - r)).0);

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
        // let r1cs_1 = ConstraintSystem::new();
        let r1cs_2 = ConstraintSystem::new();
        assert_eq!(2 + 2, 4);
    }
}
