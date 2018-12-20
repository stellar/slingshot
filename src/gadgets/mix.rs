#![allow(non_snake_case)]

use bulletproofs::r1cs::{ConstraintSystem, R1CSError, RandomizedConstraintSystem};
use value::AllocatedValue;

/// Enforces that the outputs are either a merge of the inputs :`D = A + B && C = 0`,
/// or the outputs are equal to the inputs `C = A && D = B`. See spec for more details.
/// Works for 2 inputs and 2 outputs.
pub fn fill_cs<CS: ConstraintSystem>(
    cs: &mut CS,
    A: AllocatedValue,
    B: AllocatedValue,
    C: AllocatedValue,
    D: AllocatedValue,
) -> Result<(), R1CSError> {
    cs.specify_randomized_constraints(move |cs| {
        let w = cs.challenge_scalar(b"mix challenge");
        let w2 = w * w;
        let w3 = w2 * w;
        let w4 = w3 * w;
        let w5 = w4 * w;

        let (_, _, mul_out) = cs.multiply(
            (A.q - C.q)
                + (A.a - C.a) * w
                + (A.t - C.t) * w2
                + (B.q - D.q) * w3
                + (B.a - D.a) * w4
                + (B.t - D.t) * w5,
            C.q + (A.a - B.a) * w
                + (A.t - B.t) * w2
                + (D.q - A.q - B.q) * w3
                + (D.a - A.a) * w4
                + (D.t - A.t) * w5,
        );

        // multiplication output is zero
        cs.constrain(mul_out.into());

        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use bulletproofs::r1cs::{Prover, R1CSError, Verifier};
    use bulletproofs::{BulletproofGens, PedersenGens};
    use merlin::Transcript;

    use value::{ProverCommittable, Value, VerifierCommittable};

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
    ) -> Result<(), R1CSError> {
        // Common
        let pc_gens = PedersenGens::default();
        let bp_gens = BulletproofGens::new(128, 1);

        let A = Value {
            q: A.0,
            a: A.1.into(),
            t: A.2.into(),
        };
        let B = Value {
            q: B.0,
            a: B.1.into(),
            t: B.2.into(),
        };
        let C = Value {
            q: C.0,
            a: C.1.into(),
            t: C.2.into(),
        };
        let D = Value {
            q: D.0,
            a: D.1.into(),
            t: D.2.into(),
        };

        // Prover's scope
        let (proof, A_com, B_com, C_com, D_com) = {
            // Prover makes a `ConstraintSystem` instance representing a merge gadget
            let mut prover_transcript = Transcript::new(b"MixTest");
            let mut rng = rand::thread_rng();

            let mut prover = Prover::new(&bp_gens, &pc_gens, &mut prover_transcript);
            let (A_com, A_var) = A.commit(&mut prover, &mut rng);
            let (B_com, B_var) = B.commit(&mut prover, &mut rng);
            let (C_com, C_var) = C.commit(&mut prover, &mut rng);
            let (D_com, D_var) = D.commit(&mut prover, &mut rng);

            fill_cs(&mut prover, A_var, B_var, C_var, D_var)?;

            let proof = prover.prove()?;
            (proof, A_com, B_com, C_com, D_com)
        };

        // Verifier makes a `ConstraintSystem` instance representing a merge gadget
        let mut verifier_transcript = Transcript::new(b"MixTest");
        let mut verifier = Verifier::new(&bp_gens, &pc_gens, &mut verifier_transcript);

        let A_var = A_com.commit(&mut verifier);
        let B_var = B_com.commit(&mut verifier);
        let C_var = C_com.commit(&mut verifier);
        let D_var = D_com.commit(&mut verifier);

        fill_cs(&mut verifier, A_var, B_var, C_var, D_var)?;

        Ok(verifier.verify(&proof)?)
    }
}
