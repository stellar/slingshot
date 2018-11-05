#![allow(non_snake_case)]

use bulletproofs::r1cs::ConstraintSystem;
use curve25519_dalek::scalar::Scalar;
use error::SpacesuitError;
use value::Value;

/// Enforces that the outputs are either a merge of the inputs :`D = A + B && C = 0`,
/// or the outputs are equal to the inputs `C = A && D = B`. See spec for more details.
/// Works for 2 inputs and 2 outputs.
pub fn fill_cs<CS: ConstraintSystem>(
    cs: &mut CS,
    A: Value,
    B: Value,
    C: Value,
    D: Value,
) -> Result<(), SpacesuitError> {
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
        Scalar::zero().into(),
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

#[cfg(test)]
mod tests {
    use super::*;
    use bulletproofs::r1cs::{Assignment, ProverCS, VerifierCS};
    use bulletproofs::{BulletproofGens, PedersenGens};
    use merlin::Transcript;

    #[test]
    fn mix_gadget() {
        let peso = 66;
        let yuan = 88;

        // no merge, same asset types
        assert!(mix_helper((6, peso, 0), (6, peso, 0), (6, peso, 0), (6, peso, 0),).is_ok());
        // no merge, different asset types
        assert!(mix_helper((3, peso, 0), (6, yuan, 0), (3, peso, 0), (6, yuan, 0),).is_ok());
        // merge, same asset types
        assert!(mix_helper((3, peso, 0), (6, peso, 0), (0, peso, 0), (9, peso, 0),).is_ok());
        // merge, zero value is different asset type
        assert!(mix_helper((3, peso, 0), (6, peso, 0), (0, yuan, 0), (9, peso, 0),).is_ok());
        // error when merging different asset types
        assert!(mix_helper((3, peso, 0), (3, yuan, 0), (0, peso, 0), (6, yuan, 0),).is_err());
        // error when not merging, but asset type changes
        assert!(mix_helper((3, peso, 0), (3, yuan, 0), (3, peso, 0), (3, peso, 0),).is_err());
        // error when creating more value (same asset types)
        assert!(mix_helper((3, peso, 0), (3, peso, 0), (3, peso, 0), (6, peso, 0),).is_err());
        // error when creating more value (different asset types)
        assert!(mix_helper((3, peso, 0), (3, yuan, 0), (3, peso, 0), (6, yuan, 0),).is_err());
    }

    fn mix_helper(
        A: (u64, u64, u64),
        B: (u64, u64, u64),
        C: (u64, u64, u64),
        D: (u64, u64, u64),
    ) -> Result<(), SpacesuitError> {
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
            let (mut prover_cs, _variables, commitments) = ProverCS::new(
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
            assert!(fill_cs(&mut prover_cs, A, B, C, D).is_ok());

            let proof = prover_cs.prove()?;

            (proof, commitments)
        };

        // Verifier makes a `ConstraintSystem` instance representing a merge gadget
        let mut verifier_transcript = Transcript::new(b"MixTest");
        let (mut verifier_cs, _variables) =
            VerifierCS::new(&bp_gens, &pc_gens, &mut verifier_transcript, commitments);
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
        assert!(fill_cs(&mut verifier_cs, A, B, C, D).is_ok());

        Ok(verifier_cs.verify(&proof)?)
    }
}
