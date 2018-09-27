#![allow(non_snake_case)]

use bulletproofs::circuit_proof::assignment::Assignment;
use bulletproofs::circuit_proof::{ConstraintSystem, Variable};
use bulletproofs::R1CSError;
use curve25519_dalek::scalar::Scalar;
use subtle::{ConditionallySelectable, ConstantTimeEq};
use util::Value;

struct KShuffleGadget {}

impl KShuffleGadget {
    fn fill_cs<CS: ConstraintSystem>(
        cs: &mut CS,
        x: Vec<(Variable, Assignment)>,
        y: Vec<(Variable, Assignment)>,
    ) -> Result<(), R1CSError> {
        let one = Scalar::one();
        let z = cs.challenge_scalar(b"k-shuffle challenge");
        let neg_z = -z;

        if x.len() != y.len() {
            return Err(R1CSError::InvalidR1CSConstruction);
        }
        let k = x.len();
        if k == 1 {
            cs.add_constraint([(x[0].0, -one), (y[0].0, one)].iter().collect());
            return Ok(());
        }

        // Make last x multiplier for i = k-1 and k-2
        let mut mulx_left = x[k - 1].1 + neg_z;
        let mut mulx_right = x[k - 2].1 + neg_z;
        let mut mulx_out = mulx_left * mulx_right;

        let mut mulx_out_var_prev = KShuffleGadget::multiplier_helper(
            cs,
            neg_z,
            mulx_left,
            mulx_right,
            mulx_out,
            x[k - 1].0,
            x[k - 2].0,
            true,
        )?;

        // Make multipliers for x from i == [0, k-3]
        for i in (0..k - 2).rev() {
            mulx_left = mulx_out;
            mulx_right = x[i].1 + neg_z;
            mulx_out = mulx_left * mulx_right;

            mulx_out_var_prev = KShuffleGadget::multiplier_helper(
                cs,
                neg_z,
                mulx_left,
                mulx_right,
                mulx_out,
                mulx_out_var_prev,
                x[i].0,
                false,
            )?;
        }

        // Make last y multiplier for i = k-1 and k-2
        let mut muly_left = y[k - 1].1 - z;
        let mut muly_right = y[k - 2].1 - z;
        let mut muly_out = muly_left * muly_right;

        let mut muly_out_var_prev = KShuffleGadget::multiplier_helper(
            cs,
            neg_z,
            muly_left,
            muly_right,
            muly_out,
            y[k - 1].0,
            y[k - 2].0,
            true,
        )?;

        // Make multipliers for y from i == [0, k-3]
        for i in (0..k - 2).rev() {
            muly_left = muly_out;
            muly_right = y[i].1 + neg_z;
            muly_out = muly_left * muly_right;

            muly_out_var_prev = KShuffleGadget::multiplier_helper(
                cs,
                neg_z,
                muly_left,
                muly_right,
                muly_out,
                muly_out_var_prev,
                y[i].0,
                false,
            )?;
        }

        // Check equality between last x mul output and last y mul output
        cs.add_constraint(
            [(muly_out_var_prev, -one), (mulx_out_var_prev, one)]
                .iter()
                .collect(),
        );

        Ok(())
    }

    fn multiplier_helper<CS: ConstraintSystem>(
        cs: &mut CS,
        neg_z: Scalar,
        left: Assignment,
        right: Assignment,
        out: Assignment,
        left_var: Variable,
        right_var: Variable,
        is_last_mul: bool,
    ) -> Result<Variable, R1CSError> {
        let one = Scalar::one();
        let var_one = Variable::One();

        // Make multiplier gate variables
        let (left_mul_var, right_mul_var, out_mul_var) = cs.assign_multiplier(left, right, out)?;

        if is_last_mul {
            // Make last multiplier
            cs.add_constraint(
                [(left_mul_var, -one), (var_one, neg_z), (left_var, one)]
                    .iter()
                    .collect(),
            );
        } else {
            // Make intermediate multiplier
            cs.add_constraint([(left_mul_var, -one), (left_var, one)].iter().collect());
        }
        cs.add_constraint(
            [(right_mul_var, -one), (var_one, neg_z), (right_var, one)]
                .iter()
                .collect(),
        );

        Ok(out_mul_var)
    }
}

pub struct KValueShuffleGadget {}

impl KValueShuffleGadget {
    pub fn fill_cs<CS: ConstraintSystem>(
        cs: &mut CS,
        x: Vec<Value>,
        y: Vec<Value>,
    ) -> Result<(), R1CSError> {
        let one = Scalar::one();

        if x.len() != y.len() {
            return Err(R1CSError::InvalidR1CSConstruction);
        }
        let k = x.len();
        if k == 1 {
            cs.add_constraint([(x[0].q.0, -one), (y[0].q.0, one)].iter().collect());
            cs.add_constraint([(x[0].a.0, -one), (y[0].a.0, one)].iter().collect());
            cs.add_constraint([(x[0].t.0, -one), (y[0].t.0, one)].iter().collect());
            return Ok(());
        }

        let w = cs.challenge_scalar(b"k-value-shuffle challenge");
        let w2 = w * w;
        let mut x_pairs = Vec::with_capacity(k);
        let mut y_pairs = Vec::with_capacity(k);
        for i in 0..k {
            let x_i = x[i].q.1 + x[i].a.1 * w + x[i].t.1 * w2;
            let y_i = y[i].q.1 + y[i].a.1 * w + y[i].t.1 * w2;
            let (x_i_var, y_i_var) = cs.assign_uncommitted(x_i, y_i)?;
            cs.add_constraint(
                [
                    (x_i_var, -one),
                    (x[i].q.0, one),
                    (x[i].a.0, w),
                    (x[i].t.0, w2),
                ]
                    .iter()
                    .collect(),
            );
            cs.add_constraint(
                [
                    (y_i_var, -one),
                    (y[i].q.0, one),
                    (y[i].a.0, w),
                    (y[i].t.0, w2),
                ]
                    .iter()
                    .collect(),
            );
            x_pairs.push((x_i_var, x_i));
            y_pairs.push((y_i_var, y_i));
        }
        KShuffleGadget::fill_cs(cs, x_pairs, y_pairs)
    }
}

struct MixGadget {}

impl MixGadget {
    fn fill_cs<CS: ConstraintSystem>(
        cs: &mut CS,
        A: Value,
        B: Value,
        C: Value,
        D: Value,
    ) -> Result<(), R1CSError> {
        let one = Scalar::one();
        let w = cs.challenge_scalar(b"mix challenge");
        let w2 = w * w;
        let w3 = w2 * w;
        let w4 = w3 * w;
        let w5 = w4 * w;

        // create variables for multiplication
        let (mul_left, mul_right, mul_out) = cs.assign_multiplier(
            // left gate to multiplier
            (A.q.1 - C.q.1)
                + (A.a.1 - C.a.1) * w
                + (A.t.1 - C.t.1) * w2
                + (B.q.1 - D.q.1) * w3
                + (B.a.1 - D.a.1) * w4
                + (B.t.1 - D.t.1) * w5,
            // right gate to multiplier
            C.q.1
                + (A.a.1 - B.a.1) * w
                + (A.t.1 - B.t.1) * w2
                + (D.q.1 - A.q.1 - B.q.1) * w3
                + (D.a.1 - A.a.1) * w4
                + (D.t.1 - A.t.1) * w5,
            // out gate to multiplier
            Assignment::zero(),
        )?;
        // mul_left  = (A.q - C.q) +
        //             (A.a - C.a) * w +
        //             (A.t - C.t) * w^2 +
        //             (B.q - D.q) * w^3 +
        //             (B.a - D.a) * w^4 +
        //             (B.t - D.t) * w^5
        cs.add_constraint(
            [
                (mul_left, -one),
                (A.q.0, one),
                (C.q.0, -one),
                (A.a.0, w),
                (C.a.0, -w),
                (A.t.0, w2),
                (C.t.0, -w2),
                (B.q.0, w3),
                (D.q.0, -w3),
                (B.a.0, w4),
                (D.a.0, -w4),
                (B.t.0, w5),
                (D.t.0, -w5),
            ]
                .iter()
                .collect(),
        );
        // mul_right = (C.q - 0) +
        //             (A.a - B.a) * w +
        //             (A.t - B.t) * w^2 +
        //             (D.q - A.q - B.q) * w^3 +
        //             (D.a - A.a) * w^4
        //             (D.t - A.t) * w^5
        cs.add_constraint(
            [
                (mul_right, -one),
                (C.q.0, one),
                (A.a.0, w),
                (B.a.0, -w),
                (A.t.0, w2),
                (B.t.0, -w2),
                (D.q.0, w3),
                (A.q.0, -w3),
                (B.q.0, -w3),
                (D.a.0, w4),
                (A.a.0, -w4),
                (D.t.0, w5),
                (A.t.0, -w5),
            ]
                .iter()
                .collect(),
        );
        // mul_out   = 0
        cs.add_constraint([(mul_out, one)].iter().collect());

        Ok(())
    }
}

struct KMixGadget {}

impl KMixGadget {
    fn fill_cs<CS: ConstraintSystem>(
        cs: &mut CS,
        inputs: Vec<Value>,
        outputs: Vec<Value>,
    ) -> Result<(), R1CSError> {
        let one = Scalar::one();

        if inputs.len() == 1 {
            cs.add_constraint(
                [(inputs[0].q.0, -one), (outputs[0].q.0, one)]
                    .iter()
                    .collect(),
            );
            cs.add_constraint(
                [(inputs[0].a.0, -one), (outputs[0].a.0, one)]
                    .iter()
                    .collect(),
            );
            cs.add_constraint(
                [(inputs[0].t.0, -one), (outputs[0].t.0, one)]
                    .iter()
                    .collect(),
            );
            return Ok(());
        }

        let mut A = inputs[0].clone();
        let mut B = inputs[1].clone();
        let mut C = outputs[0].clone();

        for i in 0..inputs.len() - 2 {
            let mut D = B.clone(); // placeholder; will be overwritten

            // Update assignments for D
            // Check that A and C have the same assignments for all fields (q, a, t)
            let is_move = A.q.1.ct_eq(&C.q.1) & A.a.1.ct_eq(&C.a.1) & A.t.1.ct_eq(&C.t.1);
            // Check that A and B have the same type (a and t are the same) and that C.q = 0
            let is_merge =
                A.a.1.ct_eq(&B.a.1) & A.t.1.ct_eq(&B.t.1) & C.q.1.ct_eq(&Assignment::zero());

            // Enforce that at least one of is_move and is_merge must be true. If not, error.
            // It is okay that this is not constant-time because the proof will fail to build anyway.
            if bool::from(!is_move & !is_merge) {
                // Misconfigured prover constraint system error
                return Err(R1CSError::InvalidR1CSConstruction);
            }

            // If is_move is true, then we perform a "move" operation, so D.quantity = B.quantity
            // Else, we perform a "merge" operation, so D.quantity = A.quantity + B.quantity
            D.q.1 = ConditionallySelectable::conditional_select(&(A.q.1 + B.q.1), &D.q.1, is_move);
            D.a.1 = ConditionallySelectable::conditional_select(&A.a.1, &D.a.1, is_move);
            D.t.1 = ConditionallySelectable::conditional_select(&A.t.1, &D.t.1, is_move);

            // Update variable assignments for D by making new variables
            let (D_q_var, _) = cs.assign_uncommitted(D.q.1, Assignment::zero())?;
            let (D_a_var, D_t_var) = cs.assign_uncommitted(D.a.1, D.t.1)?;
            D.q.0 = D_q_var;
            D.a.0 = D_a_var;
            D.t.0 = D_t_var;

            MixGadget::fill_cs(cs, A, B, C, D.clone())?;

            A = D;
            B = inputs[i + 2].clone();
            C = outputs[i + 1].clone();
        }

        let D = outputs[outputs.len() - 1].clone();
        MixGadget::fill_cs(cs, A, B, C, D)
    }
}

pub struct KMergeGadget {}

impl KMergeGadget {
    pub fn fill_cs<CS: ConstraintSystem>(
        cs: &mut CS,
        inputs: Vec<Value>,
        outputs: Vec<Value>,
    ) -> Result<(), R1CSError> {
        KMixGadget::fill_cs(cs, inputs, outputs)
    }
}

pub struct KSplitGadget {}

impl KSplitGadget {
    pub fn fill_cs<CS: ConstraintSystem>(
        cs: &mut CS,
        inputs: Vec<Value>,
        outputs: Vec<Value>,
    ) -> Result<(), R1CSError> {
        inputs.clone().reverse();
        outputs.clone().reverse();
        KMergeGadget::fill_cs(cs, outputs, inputs)
    }
}

pub struct RangeProofGadget {}

impl RangeProofGadget {
    // Enforce that the quantity of v is in the range [0, 2^n)
    pub fn fill_cs<CS: ConstraintSystem>(
        cs: &mut CS,
        v: (Variable, Assignment),
        n: usize,
    ) -> Result<(), R1CSError> {
        let one = Scalar::one();
        let one_var = Variable::One();

        let mut constraint = vec![(v.0, -one)];
        let mut exp_2 = Scalar::one();
        for i in 0..n {
            // Create low-level variables and add them to constraints
            let (a_i_var, b_i_var, out_var) = match v.1 {
                Assignment::Value(v_val) => {
                    let bit = (v_val[i / 8] >> (i % 8)) & 1;
                    cs.assign_multiplier(
                        Assignment::from(1 - bit as u64),
                        Assignment::from(bit as u64),
                        Assignment::zero(),
                    )?
                }
                Assignment::Missing() => cs.assign_multiplier(
                    Assignment::Missing(),
                    Assignment::Missing(),
                    Assignment::Missing(),
                )?,
            };

            // Enforce a_i * b_i = 0
            cs.add_constraint([(out_var, one)].iter().collect());

            // Enforce that a_i = 1 - b_i
            cs.add_constraint(
                [(a_i_var, one), (b_i_var, one), (one_var, -one)]
                    .iter()
                    .collect(),
            );

            constraint.push((b_i_var, exp_2));
            exp_2 = exp_2 + exp_2;
        }

        // Enforce that v = Sum(b_i * 2^i, i = 0..n-1)
        cs.add_constraint(constraint.iter().collect());

        Ok(())
    }
}

pub struct PadGadget {}

impl PadGadget {
    // Enforces that all variables are equal to zero.
    pub fn fill_cs<CS: ConstraintSystem>(
        cs: &mut CS,
        vars: Vec<Variable>,
    ) -> Result<(), R1CSError> {
        for var in vars {
            cs.add_constraint(
                [(var, Scalar::one()), (Variable::One(), Scalar::zero())]
                    .iter()
                    .collect(),
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bulletproofs::circuit_proof::{prover, verifier};
    use bulletproofs::{BulletproofGens, PedersenGens, Transcript};

    #[test]
    fn shuffle_gadget() {
        // k=1
        assert!(shuffle_helper(vec![3], vec![3]).is_ok());
        assert!(shuffle_helper(vec![6], vec![6]).is_ok());
        assert!(shuffle_helper(vec![3], vec![6]).is_err());
        // k=2
        assert!(shuffle_helper(vec![3, 6], vec![3, 6]).is_ok());
        assert!(shuffle_helper(vec![3, 6], vec![6, 3]).is_ok());
        assert!(shuffle_helper(vec![6, 6], vec![6, 6]).is_ok());
        assert!(shuffle_helper(vec![3, 3], vec![6, 3]).is_err());
        // k=3
        assert!(shuffle_helper(vec![3, 6, 10], vec![3, 6, 10]).is_ok());
        assert!(shuffle_helper(vec![3, 6, 10], vec![3, 10, 6]).is_ok());
        assert!(shuffle_helper(vec![3, 6, 10], vec![6, 3, 10]).is_ok());
        assert!(shuffle_helper(vec![3, 6, 10], vec![6, 10, 3]).is_ok());
        assert!(shuffle_helper(vec![3, 6, 10], vec![10, 3, 6]).is_ok());
        assert!(shuffle_helper(vec![3, 6, 10], vec![10, 6, 3]).is_ok());
        assert!(shuffle_helper(vec![3, 6, 10], vec![30, 6, 10]).is_err());
        assert!(shuffle_helper(vec![3, 6, 10], vec![3, 60, 10]).is_err());
        assert!(shuffle_helper(vec![3, 6, 10], vec![3, 6, 100]).is_err());
        // k=4
        assert!(shuffle_helper(vec![3, 6, 10, 15], vec![3, 6, 10, 15]).is_ok());
        assert!(shuffle_helper(vec![3, 6, 10, 15], vec![15, 6, 10, 3]).is_ok());
        assert!(shuffle_helper(vec![3, 6, 10, 15], vec![3, 6, 10, 3]).is_err());
        // k=5
        assert!(shuffle_helper(vec![3, 6, 10, 15, 17], vec![3, 6, 10, 15, 17]).is_ok());
        assert!(shuffle_helper(vec![3, 6, 10, 15, 17], vec![10, 17, 3, 15, 6]).is_ok());
        assert!(shuffle_helper(vec![3, 6, 10, 15, 17], vec![3, 6, 10, 15, 3]).is_err());
    }

    fn shuffle_helper(input: Vec<u64>, output: Vec<u64>) -> Result<(), R1CSError> {
        // Common
        let pc_gens = PedersenGens::default();
        let bp_gens = BulletproofGens::new(128, 1);

        // Prover's scope
        let (proof, commitments) = {
            // Prover makes a `ConstraintSystem` instance representing a shuffle gadget
            // v and v_blinding empty because we are only testing low-level variable constraints
            let v = vec![];
            let v_blinding = vec![];
            let mut prover_transcript = Transcript::new(b"ShuffleTest");
            let (mut prover_cs, _variables, commitments) = prover::ProverCS::new(
                &bp_gens,
                &pc_gens,
                &mut prover_transcript,
                v,
                v_blinding.clone(),
            );

            // Prover allocates variables and adds constraints to the constraint system
            let in_assignments = input
                .iter()
                .map(|in_i| Assignment::from(in_i.clone()))
                .collect();
            let out_assignments = output
                .iter()
                .map(|out_i| Assignment::from(out_i.clone()))
                .collect();
            shuffle_cs(&mut prover_cs, in_assignments, out_assignments)?;
            let proof = prover_cs.prove()?;

            (proof, commitments)
        };

        // Verifier makes a `ConstraintSystem` instance representing a shuffle gadget
        let mut verifier_transcript = Transcript::new(b"ShuffleTest");
        let (mut verifier_cs, _variables) =
            verifier::VerifierCS::new(&bp_gens, &pc_gens, &mut verifier_transcript, commitments);

        // Verifier allocates variables and adds constraints to the constraint system
        let in_assignments = input.iter().map(|_| Assignment::Missing()).collect();
        let out_assignments = output.iter().map(|_| Assignment::Missing()).collect();
        assert!(shuffle_cs(&mut verifier_cs, in_assignments, out_assignments,).is_ok());
        // Verifier verifies proof
        Ok(verifier_cs.verify(&proof)?)
    }

    fn shuffle_cs<CS: ConstraintSystem>(
        cs: &mut CS,
        input: Vec<Assignment>,
        output: Vec<Assignment>,
    ) -> Result<(), R1CSError> {
        if input.len() != output.len() {
            return Err(R1CSError::InvalidR1CSConstruction);
        }
        let k = input.len();
        let mut in_pairs = Vec::with_capacity(k);
        let mut out_pairs = Vec::with_capacity(k);

        // Allocate pairs of low-level variables and their assignments
        for i in 0..k / 2 {
            let idx_l = i * 2;
            let idx_r = idx_l + 1;
            let (in_var_left, in_var_right) = cs.assign_uncommitted(input[idx_l], input[idx_r])?;
            in_pairs.push((in_var_left, input[idx_l]));
            in_pairs.push((in_var_right, input[idx_r]));

            let (out_var_left, out_var_right) =
                cs.assign_uncommitted(output[idx_l], output[idx_r])?;
            out_pairs.push((out_var_left, output[idx_l]));
            out_pairs.push((out_var_right, output[idx_r]));
        }
        if k % 2 == 1 {
            let idx = k - 1;
            let (in_var_left, _) = cs.assign_uncommitted(input[idx], Assignment::zero())?;
            in_pairs.push((in_var_left, input[idx]));
            let (out_var_left, _) = cs.assign_uncommitted(output[idx], Assignment::zero())?;
            out_pairs.push((out_var_left, output[idx]));
        }

        KShuffleGadget::fill_cs(cs, in_pairs, out_pairs)
    }

    #[test]
    fn value_shuffle() {
        // k=1
        assert!(value_shuffle_helper(vec![(1, 2, 3)], vec![(1, 2, 3)]).is_ok());
        assert!(value_shuffle_helper(vec![(4, 5, 6)], vec![(4, 5, 6)]).is_ok());
        assert!(value_shuffle_helper(vec![(1, 2, 3)], vec![(4, 5, 6)]).is_err());
        // k=2
        assert!(
            value_shuffle_helper(vec![(1, 2, 3), (4, 5, 6)], vec![(1, 2, 3), (4, 5, 6)]).is_ok()
        );
        assert!(
            value_shuffle_helper(vec![(1, 2, 3), (4, 5, 6)], vec![(4, 5, 6), (1, 2, 3)]).is_ok()
        );
        assert!(
            value_shuffle_helper(vec![(4, 5, 6), (4, 5, 6)], vec![(4, 5, 6), (4, 5, 6)]).is_ok()
        );
        assert!(
            value_shuffle_helper(vec![(1, 2, 3), (1, 2, 3)], vec![(4, 5, 6), (1, 2, 3)]).is_err()
        );
        assert!(
            value_shuffle_helper(vec![(1, 2, 3), (4, 5, 6)], vec![(1, 2, 3), (4, 5, 6)]).is_ok()
        );
        // k=3
        assert!(
            value_shuffle_helper(
                vec![(1, 2, 3), (4, 5, 6), (8, 9, 10)],
                vec![(1, 2, 3), (4, 5, 6), (8, 9, 10)]
            ).is_ok()
        );
        assert!(
            value_shuffle_helper(
                vec![(1, 2, 3), (4, 5, 6), (8, 9, 10)],
                vec![(1, 2, 3), (8, 9, 10), (4, 5, 6)]
            ).is_ok()
        );
        assert!(
            value_shuffle_helper(
                vec![(1, 2, 3), (4, 5, 6), (8, 9, 10)],
                vec![(4, 5, 6), (1, 2, 3), (8, 9, 10)]
            ).is_ok()
        );
        assert!(
            value_shuffle_helper(
                vec![(1, 2, 3), (4, 5, 6), (8, 9, 10)],
                vec![(4, 5, 6), (8, 9, 10), (1, 2, 3)]
            ).is_ok()
        );
        assert!(
            value_shuffle_helper(
                vec![(1, 2, 3), (4, 5, 6), (8, 9, 10)],
                vec![(8, 9, 10), (1, 2, 3), (4, 5, 6)]
            ).is_ok()
        );
        assert!(
            value_shuffle_helper(
                vec![(1, 2, 3), (4, 5, 6), (8, 9, 10)],
                vec![(8, 9, 10), (4, 5, 6), (1, 2, 3)]
            ).is_ok()
        );
        assert!(
            value_shuffle_helper(
                vec![(1, 2, 3), (4, 5, 6), (8, 9, 10)],
                vec![(10, 20, 30), (4, 5, 6), (8, 9, 10)]
            ).is_err()
        );
        assert!(
            value_shuffle_helper(
                vec![(1, 2, 3), (4, 5, 6), (8, 9, 10)],
                vec![(1, 2, 3), (40, 50, 60), (8, 9, 10)]
            ).is_err()
        );
        assert!(
            value_shuffle_helper(
                vec![(1, 2, 3), (4, 5, 6), (8, 9, 10)],
                vec![(1, 2, 3), (4, 5, 6), (98, 99, 100)]
            ).is_err()
        );
    }

    fn value_shuffle_helper(
        input: Vec<(u64, u64, u64)>,
        output: Vec<(u64, u64, u64)>,
    ) -> Result<(), R1CSError> {
        // Common
        let pc_gens = PedersenGens::default();
        let bp_gens = BulletproofGens::new(128, 1);

        // Prover's scope
        let (proof, commitments) = {
            // Prover makes a `ConstraintSystem` instance representing a shuffle gadget
            // v and v_blinding empty because we are only testing low-level variable constraints
            let v = vec![];
            let v_blinding = vec![];
            let mut prover_transcript = Transcript::new(b"ValueShuffleTest");
            let (mut prover_cs, _variables, commitments) = prover::ProverCS::new(
                &bp_gens,
                &pc_gens,
                &mut prover_transcript,
                v,
                v_blinding.clone(),
            );

            // Prover allocates variables and adds constraints to the constraint system
            let in_assignments = input
                .iter()
                .map(|in_i| {
                    (
                        Assignment::from(in_i.0.clone()),
                        Assignment::from(in_i.1.clone()),
                        Assignment::from(in_i.2.clone()),
                    )
                }).collect();
            let out_assignments = output
                .iter()
                .map(|out_i| {
                    (
                        Assignment::from(out_i.0.clone()),
                        Assignment::from(out_i.1.clone()),
                        Assignment::from(out_i.2.clone()),
                    )
                }).collect();
            value_shuffle_cs(&mut prover_cs, in_assignments, out_assignments)?;
            let proof = prover_cs.prove()?;

            (proof, commitments)
        };

        // Verifier makes a `ConstraintSystem` instance representing a shuffle gadget
        let mut verifier_transcript = Transcript::new(b"ValueShuffleTest");
        let (mut verifier_cs, _variables) =
            verifier::VerifierCS::new(&bp_gens, &pc_gens, &mut verifier_transcript, commitments);

        // Verifier allocates variables and adds constraints to the constraint system
        let in_assignments = input
            .iter()
            .map(|_| {
                (
                    Assignment::Missing(),
                    Assignment::Missing(),
                    Assignment::Missing(),
                )
            }).collect();
        let out_assignments = output
            .iter()
            .map(|_| {
                (
                    Assignment::Missing(),
                    Assignment::Missing(),
                    Assignment::Missing(),
                )
            }).collect();
        assert!(value_shuffle_cs(&mut verifier_cs, in_assignments, out_assignments,).is_ok());
        // Verifier verifies proof
        Ok(verifier_cs.verify(&proof)?)
    }

    fn value_shuffle_cs<CS: ConstraintSystem>(
        cs: &mut CS,
        input: Vec<(Assignment, Assignment, Assignment)>,
        output: Vec<(Assignment, Assignment, Assignment)>,
    ) -> Result<(), R1CSError> {
        if input.len() != output.len() {
            return Err(R1CSError::InvalidR1CSConstruction);
        }
        let k = input.len();
        let mut in_vals = Vec::with_capacity(k);
        let mut out_vals = Vec::with_capacity(k);

        // Allocate pairs of low-level variables and their assignments
        for i in 0..k {
            let (in_q, out_q) = cs.assign_uncommitted(input[i].0, output[i].0)?;
            let (in_a, out_a) = cs.assign_uncommitted(input[i].1, output[i].1)?;
            let (in_t, out_t) = cs.assign_uncommitted(input[i].2, output[i].2)?;
            in_vals.push(Value {
                q: (in_q, input[i].0),
                a: (in_a, input[i].1),
                t: (in_t, input[i].2),
            });
            out_vals.push(Value {
                q: (out_q, output[i].0),
                a: (out_a, output[i].1),
                t: (out_t, output[i].2),
            });
        }

        KValueShuffleGadget::fill_cs(cs, in_vals, out_vals)
    }

    #[test]
    fn mix_gadget() {
        let peso = 66;
        let peso_tag = 77;
        let yuan = 88;
        let yuan_tag = 99;

        // no merge, same asset types
        assert!(
            mix_helper(
                (6, peso, peso_tag),
                (6, peso, peso_tag),
                (6, peso, peso_tag),
                (6, peso, peso_tag),
            ).is_ok()
        );
        // no merge, different asset types
        assert!(
            mix_helper(
                (3, peso, peso_tag),
                (6, yuan, yuan_tag),
                (3, peso, peso_tag),
                (6, yuan, yuan_tag),
            ).is_ok()
        );
        // merge, same asset types
        assert!(
            mix_helper(
                (3, peso, peso_tag),
                (6, peso, peso_tag),
                (0, peso, peso_tag),
                (9, peso, peso_tag),
            ).is_ok()
        );
        // merge, zero value is different asset type
        assert!(
            mix_helper(
                (3, peso, peso_tag),
                (6, peso, peso_tag),
                (0, yuan, yuan_tag),
                (9, peso, peso_tag),
            ).is_ok()
        );
        // error when merging different asset types
        assert!(
            mix_helper(
                (3, peso, peso_tag),
                (3, yuan, yuan_tag),
                (0, peso, peso_tag),
                (6, yuan, yuan_tag),
            ).is_err()
        );
        // error when not merging, but asset type changes
        assert!(
            mix_helper(
                (3, peso, peso_tag),
                (3, yuan, yuan_tag),
                (3, peso, peso_tag),
                (3, peso, peso_tag),
            ).is_err()
        );
        // error when creating more value (same asset types)
        assert!(
            mix_helper(
                (3, peso, peso_tag),
                (3, peso, peso_tag),
                (3, peso, peso_tag),
                (6, peso, peso_tag),
            ).is_err()
        );
        // error when creating more value (different asset types)
        assert!(
            mix_helper(
                (3, peso, peso_tag),
                (3, yuan, yuan_tag),
                (3, peso, peso_tag),
                (6, yuan, yuan_tag),
            ).is_err()
        );
    }

    fn mix_helper(
        A: (u64, u64, u64),
        B: (u64, u64, u64),
        C: (u64, u64, u64),
        D: (u64, u64, u64),
    ) -> Result<(), R1CSError> {
        // Common
        let pc_gens = PedersenGens::default();
        let bp_gens = BulletproofGens::new(128, 1);

        // Prover's scope
        let (proof, commitments) = {
            // Prover makes a `ConstraintSystem` instance representing a merge gadget
            // v and v_blinding emptpy because we are only testing low-level variable constraints
            let v = vec![];
            let v_blinding = vec![];
            let mut prover_transcript = Transcript::new(b"MixTest");
            let (mut prover_cs, _variables, commitments) = prover::ProverCS::new(
                &bp_gens,
                &pc_gens,
                &mut prover_transcript,
                v,
                v_blinding.clone(),
            );

            // Prover allocates variables and adds constraints to the constraint system
            let (A_q, B_q) =
                prover_cs.assign_uncommitted(Assignment::from(A.0), Assignment::from(B.0))?;
            let (C_q, D_q) =
                prover_cs.assign_uncommitted(Assignment::from(C.0), Assignment::from(D.0))?;
            let (A_a, B_a) =
                prover_cs.assign_uncommitted(Assignment::from(A.1), Assignment::from(B.1))?;
            let (C_a, D_a) =
                prover_cs.assign_uncommitted(Assignment::from(C.1), Assignment::from(D.1))?;
            let (A_t, B_t) =
                prover_cs.assign_uncommitted(Assignment::from(A.2), Assignment::from(B.2))?;
            let (C_t, D_t) =
                prover_cs.assign_uncommitted(Assignment::from(C.2), Assignment::from(D.2))?;
            let A = Value {
                q: (A_q, Assignment::from(A.0)),
                a: (A_a, Assignment::from(A.1)),
                t: (A_t, Assignment::from(A.2)),
            };
            let B = Value {
                q: (B_q, Assignment::from(B.0)),
                a: (B_a, Assignment::from(B.1)),
                t: (B_t, Assignment::from(B.2)),
            };
            let C = Value {
                q: (C_q, Assignment::from(C.0)),
                a: (C_a, Assignment::from(C.1)),
                t: (C_t, Assignment::from(C.2)),
            };
            let D = Value {
                q: (D_q, Assignment::from(D.0)),
                a: (D_a, Assignment::from(D.1)),
                t: (D_t, Assignment::from(D.2)),
            };
            assert!(MixGadget::fill_cs(&mut prover_cs, A, B, C, D).is_ok());

            let proof = prover_cs.prove()?;

            (proof, commitments)
        };

        // Verifier makes a `ConstraintSystem` instance representing a merge gadget
        let mut verifier_transcript = Transcript::new(b"MixTest");
        let (mut verifier_cs, _variables) =
            verifier::VerifierCS::new(&bp_gens, &pc_gens, &mut verifier_transcript, commitments);
        // Verifier allocates variables and adds constraints to the constraint system
        let (A_q, B_q) =
            verifier_cs.assign_uncommitted(Assignment::Missing(), Assignment::Missing())?;
        let (C_q, D_q) =
            verifier_cs.assign_uncommitted(Assignment::Missing(), Assignment::Missing())?;
        let (A_a, B_a) =
            verifier_cs.assign_uncommitted(Assignment::Missing(), Assignment::Missing())?;
        let (C_a, D_a) =
            verifier_cs.assign_uncommitted(Assignment::Missing(), Assignment::Missing())?;
        let (A_t, B_t) =
            verifier_cs.assign_uncommitted(Assignment::Missing(), Assignment::Missing())?;
        let (C_t, D_t) =
            verifier_cs.assign_uncommitted(Assignment::Missing(), Assignment::Missing())?;
        let A = Value {
            q: (A_q, Assignment::Missing()),
            a: (A_a, Assignment::Missing()),
            t: (A_t, Assignment::Missing()),
        };
        let B = Value {
            q: (B_q, Assignment::Missing()),
            a: (B_a, Assignment::Missing()),
            t: (B_t, Assignment::Missing()),
        };
        let C = Value {
            q: (C_q, Assignment::Missing()),
            a: (C_a, Assignment::Missing()),
            t: (C_t, Assignment::Missing()),
        };
        let D = Value {
            q: (D_q, Assignment::Missing()),
            a: (D_a, Assignment::Missing()),
            t: (D_t, Assignment::Missing()),
        };
        assert!(MixGadget::fill_cs(&mut verifier_cs, A, B, C, D).is_ok());

        verifier_cs.verify(&proof)
    }

    #[test]
    fn kmix_gadget() {
        let peso = 66;
        let ptag = 77;
        let yuan = 88;
        let ytag = 99;
        let zero = 0;

        // k=1
        // no merge, same asset types
        assert!(kmix_helper(vec![(6, peso, ptag)], vec![(6, peso, ptag)]).is_ok());
        // error when merging different asset types
        assert!(kmix_helper(vec![(3, peso, ptag)], vec![(3, yuan, ytag)]).is_err());

        // k=2 ... more extensive k=2 tests are in the MixGadget tests
        // no merge, different asset types
        assert!(
            kmix_helper(
                vec![(3, peso, ptag), (6, yuan, ytag)],
                vec![(3, peso, ptag), (6, yuan, ytag)],
            ).is_ok()
        );
        // merge, same asset types
        assert!(
            kmix_helper(
                vec![(3, peso, ptag), (6, peso, ptag)],
                vec![(0, peso, ptag), (9, peso, ptag)],
            ).is_ok()
        );
        // error when merging different asset types
        assert!(
            kmix_helper(
                vec![(3, peso, ptag), (3, yuan, ytag)],
                vec![(0, peso, ptag), (6, yuan, ytag)],
            ).is_err()
        );

        // k=3
        // no merge, same asset types
        assert!(
            kmix_helper(
                vec![(3, peso, ptag), (6, peso, ptag), (6, peso, ptag)],
                vec![(3, peso, ptag), (6, peso, ptag), (6, peso, ptag)],
            ).is_ok()
        );
        // no merge, different asset types
        assert!(
            kmix_helper(
                vec![(3, peso, ptag), (6, yuan, ytag), (6, peso, ptag)],
                vec![(3, peso, ptag), (6, yuan, ytag), (6, peso, ptag)],
            ).is_ok()
        );
        // merge first two
        assert!(
            kmix_helper(
                vec![(3, peso, ptag), (6, peso, ptag), (1, yuan, ytag)],
                vec![(0, peso, ptag), (9, peso, ptag), (1, yuan, ytag)],
            ).is_ok()
        );
        // merge last two
        assert!(
            kmix_helper(
                vec![(1, yuan, ytag), (3, peso, ptag), (6, peso, ptag)],
                vec![(1, yuan, ytag), (0, peso, ptag), (9, peso, ptag)],
            ).is_ok()
        );
        // merge all, same asset types, zero value is different asset type
        assert!(
            kmix_helper(
                vec![(3, peso, ptag), (6, peso, ptag), (1, peso, ptag)],
                vec![(0, zero, zero), (0, zero, zero), (10, peso, ptag)],
            ).is_ok()
        );
        // incomplete merge, input sum does not equal output sum
        assert!(
            kmix_helper(
                vec![(3, peso, ptag), (6, peso, ptag), (1, peso, ptag)],
                vec![(1, zero, zero), (0, zero, zero), (9, peso, ptag)],
            ).is_err()
        );
        // error when merging with different asset types
        assert!(
            kmix_helper(
                vec![(3, peso, ptag), (6, yuan, ytag), (1, peso, ptag)],
                vec![(0, zero, zero), (0, zero, zero), (10, peso, ptag)],
            ).is_err()
        );

        // k=4
        // merge each of 2 asset types
        assert!(
            kmix_helper(
                vec![
                    (3, peso, ptag),
                    (6, peso, ptag),
                    (1, yuan, ytag),
                    (2, yuan, ytag)
                ],
                vec![
                    (0, zero, zero),
                    (9, peso, ptag),
                    (0, zero, zero),
                    (3, yuan, ytag)
                ],
            ).is_ok()
        );
        // merge all, same asset
        assert!(
            kmix_helper(
                vec![
                    (3, peso, ptag),
                    (6, peso, ptag),
                    (2, peso, ptag),
                    (1, peso, ptag)
                ],
                vec![
                    (0, zero, zero),
                    (0, zero, zero),
                    (0, zero, zero),
                    (12, peso, ptag)
                ],
            ).is_ok()
        );
        // error when merging, output sum not equal to input sum
        assert!(
            kmix_helper(
                vec![
                    (3, peso, ptag),
                    (6, peso, ptag),
                    (2, peso, ptag),
                    (1, peso, ptag)
                ],
                vec![
                    (0, zero, zero),
                    (0, zero, zero),
                    (0, zero, zero),
                    (10, peso, ptag)
                ],
            ).is_err()
        );
    }

    fn kmix_helper(
        inputs: Vec<(u64, u64, u64)>,
        outputs: Vec<(u64, u64, u64)>,
    ) -> Result<(), R1CSError> {
        // Common
        let pc_gens = PedersenGens::default();
        let bp_gens = BulletproofGens::new(128, 1);
        let k = inputs.len();

        // Prover's scope
        let (proof, commitments) = {
            // Prover makes a `ConstraintSystem` instance representing a merge gadget
            // v and v_blinding emptpy because we are only testing low-level variable constraints
            let v = vec![];
            let v_blinding = vec![];
            let mut prover_transcript = Transcript::new(b"KMixTest");
            let (mut prover_cs, _variables, commitments) = prover::ProverCS::new(
                &bp_gens,
                &pc_gens,
                &mut prover_transcript,
                v,
                v_blinding.clone(),
            );

            // Prover allocates variables and adds constraints to the constraint system
            let mut input_vals = Vec::with_capacity(k);
            let mut output_vals = Vec::with_capacity(k);
            for i in 0..k {
                let (in_q, out_q) = prover_cs.assign_uncommitted(
                    Assignment::from(inputs[i].0),
                    Assignment::from(outputs[i].0),
                )?;
                let (in_a, out_a) = prover_cs.assign_uncommitted(
                    Assignment::from(inputs[i].1),
                    Assignment::from(outputs[i].1),
                )?;
                let (in_t, out_t) = prover_cs.assign_uncommitted(
                    Assignment::from(inputs[i].2),
                    Assignment::from(outputs[i].2),
                )?;
                input_vals.push(Value {
                    q: (in_q, Assignment::from(inputs[i].0)),
                    a: (in_a, Assignment::from(inputs[i].1)),
                    t: (in_t, Assignment::from(inputs[i].2)),
                });
                output_vals.push(Value {
                    q: (out_q, Assignment::from(outputs[i].0)),
                    a: (out_a, Assignment::from(outputs[i].1)),
                    t: (out_t, Assignment::from(outputs[i].2)),
                });
            }

            KMixGadget::fill_cs(&mut prover_cs, input_vals, output_vals)?;

            let proof = prover_cs.prove()?;

            (proof, commitments)
        };

        // Verifier makes a `ConstraintSystem` instance representing a merge gadget
        let mut verifier_transcript = Transcript::new(b"KMixTest");
        let (mut verifier_cs, _variables) =
            verifier::VerifierCS::new(&bp_gens, &pc_gens, &mut verifier_transcript, commitments);

        // Verifier allocates variables and adds constraints to the constraint system
        let mut input_vals = Vec::with_capacity(k);
        let mut output_vals = Vec::with_capacity(k);
        for _ in 0..k {
            let (in_q, out_q) =
                verifier_cs.assign_uncommitted(Assignment::Missing(), Assignment::Missing())?;
            let (in_a, out_a) =
                verifier_cs.assign_uncommitted(Assignment::Missing(), Assignment::Missing())?;
            let (in_t, out_t) =
                verifier_cs.assign_uncommitted(Assignment::Missing(), Assignment::Missing())?;
            input_vals.push(Value {
                q: (in_q, Assignment::Missing()),
                a: (in_a, Assignment::Missing()),
                t: (in_t, Assignment::Missing()),
            });
            output_vals.push(Value {
                q: (out_q, Assignment::Missing()),
                a: (out_a, Assignment::Missing()),
                t: (out_t, Assignment::Missing()),
            });
        }

        assert!(KMixGadget::fill_cs(&mut verifier_cs, input_vals, output_vals).is_ok());

        verifier_cs.verify(&proof)
    }

    #[test]
    fn range_proof_gadget() {
        use rand::rngs::OsRng;
        use rand::Rng;

        let mut rng = OsRng::new().unwrap();
        let m = 3; // number of values to test per `n`

        for n in [2, 10, 32, 63].iter() {
            let (min, max) = (0u64, ((1u128 << n) - 1) as u64);
            let values: Vec<u64> = (0..m).map(|_| rng.gen_range(min, max)).collect();
            for v in values {
                assert!(range_proof_helper(v, *n).is_ok());
            }
            assert!(range_proof_helper(max + 1, *n).is_err());
        }
    }

    fn range_proof_helper(v_val: u64, n: usize) -> Result<(), R1CSError> {
        // Common
        let pc_gens = PedersenGens::default();
        let bp_gens = BulletproofGens::new(128, 1);

        // Prover's scope
        let (proof, commitments) = {
            // Prover makes a `ConstraintSystem` instance representing a merge gadget
            // v and v_blinding emptpy because we are only testing low-level variable constraints
            let v = vec![];
            let v_blinding = vec![];
            let mut prover_transcript = Transcript::new(b"RangeProofTest");
            let (mut prover_cs, _variables, commitments) = prover::ProverCS::new(
                &bp_gens,
                &pc_gens,
                &mut prover_transcript,
                v,
                v_blinding.clone(),
            );

            // Prover allocates variables and adds constraints to the constraint system
            let (v_var, _) =
                prover_cs.assign_uncommitted(Assignment::from(v_val), Assignment::zero())?;

            RangeProofGadget::fill_cs(&mut prover_cs, (v_var, Assignment::from(v_val)), n)?;

            let proof = prover_cs.prove()?;

            (proof, commitments)
        };

        // Verifier makes a `ConstraintSystem` instance representing a merge gadget
        let mut verifier_transcript = Transcript::new(b"RangeProofTest");
        let (mut verifier_cs, _variables) =
            verifier::VerifierCS::new(&bp_gens, &pc_gens, &mut verifier_transcript, commitments);

        // Verifier allocates variables and adds constraints to the constraint system
        let (v_var, _) =
            verifier_cs.assign_uncommitted(Assignment::Missing(), Assignment::Missing())?;

        assert!(
            RangeProofGadget::fill_cs(&mut verifier_cs, (v_var, Assignment::Missing()), n).is_ok()
        );

        verifier_cs.verify(&proof)
    }

    #[test]
    fn pad_gadget() {
        assert!(pad_helper(vec![0]).is_ok());
        assert!(pad_helper(vec![0; 5]).is_ok());
        assert!(pad_helper(vec![0; 10]).is_ok());
        assert!(pad_helper(vec![1]).is_err());
        assert!(pad_helper(vec![0, 2, 0, 0, 0]).is_err());
    }

    fn pad_helper(vals: Vec<u64>) -> Result<(), R1CSError> {
        // Common
        let pc_gens = PedersenGens::default();
        let bp_gens = BulletproofGens::new(128, 1);
        let k = vals.len();

        // Prover's scope
        let (proof, commitments) = {
            // Prover makes a `ConstraintSystem` instance representing a merge gadget
            // v and v_blinding emptpy because we are only testing low-level variable constraints
            let v = vec![];
            let v_blinding = vec![];
            let mut prover_transcript = Transcript::new(b"PadTest");
            let (mut prover_cs, _variables, commitments) = prover::ProverCS::new(
                &bp_gens,
                &pc_gens,
                &mut prover_transcript,
                v,
                v_blinding.clone(),
            );

            // Prover allocates variables and adds constraints to the constraint system
            let mut vars = Vec::with_capacity(k);
            for i in 0..k / 2 {
                let (var_a, var_b) = prover_cs
                    .assign_uncommitted(Assignment::from(vals[i]), Assignment::from(vals[i + 1]))?;
                vars.push(var_a);
                vars.push(var_b);
            }
            if k % 2 == 1 {
                let (var, _) = prover_cs.assign_uncommitted(
                    Assignment::from(vals[vals.len() - 1]),
                    Assignment::zero(),
                )?;
                vars.push(var);
            }

            PadGadget::fill_cs(&mut prover_cs, vars)?;

            let proof = prover_cs.prove()?;

            (proof, commitments)
        };

        // Verifier makes a `ConstraintSystem` instance representing a merge gadget
        let mut verifier_transcript = Transcript::new(b"PadTest");
        let (mut verifier_cs, _variables) =
            verifier::VerifierCS::new(&bp_gens, &pc_gens, &mut verifier_transcript, commitments);

        // Verifier allocates variables and adds constraints to the constraint system
        let mut vars = Vec::with_capacity(k);
        for _ in 0..k / 2 {
            let (var_a, var_b) =
                verifier_cs.assign_uncommitted(Assignment::Missing(), Assignment::Missing())?;
            vars.push(var_a);
            vars.push(var_b);
        }
        if k % 2 == 1 {
            let (var, _) =
                verifier_cs.assign_uncommitted(Assignment::Missing(), Assignment::zero())?;
            vars.push(var);
        }

        assert!(PadGadget::fill_cs(&mut verifier_cs, vars).is_ok());

        verifier_cs.verify(&proof)
    }
}
