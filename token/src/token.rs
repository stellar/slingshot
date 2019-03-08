use curve25519_dalek::scalar::Scalar;
use zkvm::{Commitment, Data, Output, Predicate, Program, Value};

/// Represents a ZkVM Token with unique flavor and embedded
/// metadata protected by a user-supplied Predicate.
#[derive(Clone, Debug)]
pub struct Token {
    issuance_predicate: Predicate,
    metadata: Vec<u8>,
}

impl Token {
    /// Constructs a new Token.
    pub fn new(pred: Predicate, metadata: Vec<u8>) -> Self {
        Token {
            issuance_predicate: pred,
            metadata: metadata,
        }
    }

    /// Returns the Token's flavor.
    pub fn flavor(&self) -> Scalar {
        Value::issue_flavor(
            &self.issuance_predicate,
            Data::Opaque(self.metadata.clone()),
        )
    }

    /// Adds instructions to a program to issues a given quantity
    /// of this Token.
    pub fn issue<'a>(&self, program: &'a mut Program, qty: u64) -> &'a mut Program {
        program
            .push(Commitment::blinded(qty)) // stack: qty
            .var() // stack: qty-var
            .push(Commitment::unblinded(self.flavor())) // stack: qty-var, flv
            .var() // stack: qty-var, flv-var
            .push(Data::Opaque(self.metadata.clone())) // stack: qty-var, flv-var, data
            .push(self.issuance_predicate.clone()) // stack: qty-var, flv-var, data, flv-pred
            .issue() // stack: issue-contract
            .sign_tx() // stack: issued-value
    }

    /// Adds instructions to a program to issue a given quantity
    /// of this token to a given destination predicate.
    pub fn issue_to<'a>(
        &self,
        program: &'a mut Program,
        qty: u64,
        dest: Predicate,
    ) -> &'a mut Program {
        self.issue(program, qty).push(dest).output(1)
    }

    /// Adds instructions to a program to retire a given UTXO.
    /// TBD: accept a qty/Token pairing to retire.
    pub fn retire<'a>(program: &'a mut Program, prev_output: Output) -> &'a mut Program {
        program.push(prev_output).input().sign_tx().retire()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bulletproofs::{BulletproofGens, PedersenGens};
    use zkvm::{
        Entry, Predicate, Program, Prover, Signature, Tx, TxHeader, TxID, TxLog, VMError,
        VerificationKey, Verifier,
    };

    fn add_nonce(p: &mut Program, nonce_key: &Scalar) {
        let dummy_block_id = Data::Opaque([0xffu8; 32].to_vec());
        p.push(Predicate::Key(VerificationKey::from_secret(nonce_key)))
            .push(dummy_block_id)
            .nonce()
            .sign_tx();
    }

    #[test]
    fn issue_to() {
        let (tx, _, _) = {
            let issue_key = Scalar::from(1u64);
            let dest_key = Scalar::from(2u64);
            let nonce_key = Scalar::from(3u64);
            let usd = Token::new(
                Predicate::Key(VerificationKey::from_secret(&issue_key)),
                b"USD".to_vec(),
            );
            let dest = Predicate::Key(VerificationKey::from_secret(&dest_key));

            let program = Program::build(|p| {
                add_nonce(p, &nonce_key);
                usd.issue_to(p, 10u64, dest.clone())
            });
            build(program, vec![issue_key, nonce_key]).unwrap()
        };

        // Verify tx
        let bp_gens = BulletproofGens::new(256, 1);
        assert!(Verifier::verify_tx(tx, &bp_gens).is_ok());
    }

    #[test]
    fn issue_and_retire() {
        // Issue tx
        let (tx, _, _) = {
            let issue_key = Scalar::from(1u64);
            let dest_key = Scalar::from(2u64);
            let nonce_key = Scalar::from(3u64);
            let usd = Token::new(
                Predicate::Key(VerificationKey::from_secret(&issue_key)),
                b"USD".to_vec(),
            );
            let dest = Predicate::Key(VerificationKey::from_secret(&dest_key));
            let issue_program = Program::build(|p| {
                add_nonce(p, &nonce_key);
                usd.issue_to(p, 10u64, dest.clone())
            });
            let (_, _, issue_txlog) = build(issue_program, vec![issue_key, nonce_key]).unwrap();

            let mut retire_program = Program::new();
            let issue_output = match &issue_txlog[3] {
                Entry::Output(x) => x.clone(),
                _ => return assert!(false, "TxLog entry doesn't match: expected Output"),
            };
            Token::retire(&mut retire_program, issue_output);
            build(retire_program, vec![dest_key]).unwrap()
        };

        // Verify tx
        let bp_gens = BulletproofGens::new(256, 1);
        assert!(Verifier::verify_tx(tx, &bp_gens).is_ok());
    }

    // Helper functions
    fn build(program: Program, keys: Vec<Scalar>) -> Result<(Tx, TxID, TxLog), VMError> {
        let bp_gens = BulletproofGens::new(256, 1);
        let header = TxHeader {
            version: 0u64,
            mintime: 0u64,
            maxtime: 0u64,
        };
        // TBD: figure out better + more robust signing mechanism
        let gens = PedersenGens::default();
        Prover::build_tx(program, header, &bp_gens, |t, verification_keys| {
            let signtx_keys: Vec<Scalar> = verification_keys
                .iter()
                .filter_map(|vk| {
                    for k in &keys {
                        if (k * gens.B).compress() == vk.0 {
                            return Some(*k);
                        }
                    }
                    None
                })
                .collect();
            Signature::sign_aggregated(t, &signtx_keys)
        })
    }
}
