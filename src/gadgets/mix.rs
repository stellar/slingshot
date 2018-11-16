#![allow(non_snake_case)]

use bulletproofs::r1cs::ConstraintSystem;
use error::SpacesuitError;
use value::{AllocatedValue};

/// Enforces that the outputs are either a merge of the inputs :`D = A + B && C = 0`,
/// or the outputs are equal to the inputs `C = A && D = B`. See spec for more details.
/// Works for 2 inputs and 2 outputs.
pub fn fill_cs<CS: ConstraintSystem>(
    cs: &mut CS,
    A: AllocatedValue,
    B: AllocatedValue,
    C: AllocatedValue,
    D: AllocatedValue,
) -> Result<(), SpacesuitError> {
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

        C.q
        + (A.a - B.a) * w
        + (A.t - B.t) * w2
        + (D.q - A.q - B.q) * w3
        + (D.a - A.a) * w4
        + (D.t - A.t) * w5
    );

    // multiplication output is zero
    cs.constrain(mul_out.into());

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::scalar::Scalar;
    use bulletproofs::r1cs::{ProverCS, VerifierCS};
    use bulletproofs::{BulletproofGens, PedersenGens};
    use merlin::Transcript;

    use value::SecretValue;

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

        let A = SecretValue{ q: A.0, a: A.1.into(), t: A.2.into() };
        let B = SecretValue{ q: B.0, a: B.1.into(), t: B.2.into() };
        let C = SecretValue{ q: C.0, a: C.1.into(), t: C.2.into() };
        let D = SecretValue{ q: D.0, a: D.1.into(), t: D.2.into() };

        // Prover's scope
        let (proof, commitments) = {
            // Prover makes a `ConstraintSystem` instance representing a merge gadget
            // v and v_blinding emptpy because we are only testing low-level variable constraints
            let values = vec![A,B,C,D];
            let v: Vec<Scalar> = values.iter().fold(
                Vec::new(),
                |mut vec, value|{
                    vec.push(value.q.into());
                    vec.push(value.a);
                    vec.push(value.t);
                    vec
            });
            let v_blinding: Vec<Scalar> = (0..v.len()).map(|_| {
                Scalar::random(&mut rand::thread_rng())
            }).collect();

            let mut prover_transcript = Transcript::new(b"MixTest");
            let (mut prover_cs, variables, commitments) = ProverCS::new(
                &bp_gens,
                &pc_gens,
                &mut prover_transcript,
                v,
                v_blinding.clone(),
            );

            let A = AllocatedValue {
                q: variables[0],
                a: variables[1],
                t: variables[2],
                assignment: Some(A),
            };
            let B = AllocatedValue {
                q: variables[3],
                a: variables[4],
                t: variables[5],
                assignment: Some(B),
            };
            let C = AllocatedValue {
                q: variables[6],
                a: variables[7],
                t: variables[8],
                assignment: Some(C),
            };
            let D = AllocatedValue {
                q: variables[9],
                a: variables[10],
                t: variables[11],
                assignment: Some(D),
            };
            assert!(fill_cs(&mut prover_cs, A, B, C, D).is_ok());

            let proof = prover_cs.prove()?;

            (proof, commitments)
        };

        // Verifier makes a `ConstraintSystem` instance representing a merge gadget
        let mut verifier_transcript = Transcript::new(b"MixTest");
        let (mut verifier_cs, variables) =
            VerifierCS::new(&bp_gens, &pc_gens, &mut verifier_transcript, commitments);
        
        let A = AllocatedValue {
            q: variables[0],
            a: variables[1],
            t: variables[2],
            assignment: None,
        };
        let B = AllocatedValue {
            q: variables[3],
            a: variables[4],
            t: variables[5],
            assignment: None,
        };
        let C = AllocatedValue {
            q: variables[6],
            a: variables[7],
            t: variables[8],
            assignment: None,
        };
        let D = AllocatedValue {
            q: variables[9],
            a: variables[10],
            t: variables[11],
            assignment: None,
        };
        assert!(fill_cs(&mut verifier_cs, A, B, C, D).is_ok());

        Ok(verifier_cs.verify(&proof)?)
    }
}
