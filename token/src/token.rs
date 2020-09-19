use curve25519_dalek::scalar::Scalar;
use zkvm::{Commitment, Contract, Predicate, Program, String, Value};

/// Represents a ZkVM Token with unique flavor and embedded
/// metadata protected by a user-supplied Predicate.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
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
            String::Opaque(self.metadata.clone()),
        )
    }

    /// Adds instructions to a program to issues a given quantity
    /// of this Token.
    pub fn issue<'a>(&self, program: &'a mut Program, qty: u64) -> &'a mut Program {
        program
            .push(Commitment::blinded(qty)) // stack: qty
            .commit() // stack: qty-var
            .push(Commitment::unblinded(self.flavor())) // stack: qty-var, flv
            .commit() // stack: qty-var, flv-var
            .push(String::Opaque(self.metadata.clone())) // stack: qty-var, flv-var, data
            .push(self.issuance_predicate.clone()) // stack: qty-var, flv-var, data, flv-pred
            .issue() // stack: issue-contract
            .signtx() // stack: issued-value
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
    ///
    /// DEPRECATED!
    ///
    pub fn retire<'a>(program: &'a mut Program, prev_output: Contract) -> &'a mut Program {
        program.push(prev_output).input().signtx().retire()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bulletproofs::{BulletproofGens, PedersenGens};
    use merlin::Transcript;
    use zkvm::{
        Anchor, Contract, Multisignature, Predicate, Program, Prover, Signature, Tx, TxEntry,
        TxHeader, TxID, TxLog, VMError, VerificationKey,
    };

    fn add_dummy_input(p: &mut Program, dummy_key: &Scalar) {
        let contract = Contract {
            predicate: Predicate::Key(VerificationKey::from_secret(dummy_key)),
            payload: vec![],
            anchor: Anchor::from_raw_bytes([0u8; 32]),
        };
        p.push(contract).input().signtx();
    }

    #[test]
    fn issue_to() {
        let (tx, _, _) = {
            let issue_key = Scalar::from(1u64);
            let dest_key = Scalar::from(2u64);
            let dummy_key = Scalar::from(3u64);
            let usd = Token::new(
                Predicate::Key(VerificationKey::from_secret(&issue_key)),
                b"USD".to_vec(),
            );
            let dest = Predicate::Key(VerificationKey::from_secret(&dest_key));

            let program = Program::build(|p| {
                add_dummy_input(p, &dummy_key);
                usd.issue_to(p, 10u64, dest.clone());
            });
            build(program, vec![issue_key, dummy_key]).unwrap()
        };

        // Verify tx
        let bp_gens = BulletproofGens::new(256, 1);
        assert!(tx.verify(&bp_gens).is_ok());
    }

    #[test]
    fn issue_and_retire() {
        // Issue tx
        let (tx, _, _) = {
            let issue_key = Scalar::from(1u64);
            let dest_key = Scalar::from(2u64);
            let dummy_key = Scalar::from(3u64);
            let usd = Token::new(
                Predicate::Key(VerificationKey::from_secret(&issue_key)),
                b"USD".to_vec(),
            );
            let dest = Predicate::Key(VerificationKey::from_secret(&dest_key));
            let issue_program = Program::build(|p| {
                add_dummy_input(p, &dummy_key);
                usd.issue_to(p, 10u64, dest.clone());
            });
            let (_, _, issue_txlog) = build(issue_program, vec![issue_key, dummy_key]).unwrap();

            let mut retire_program = Program::new();
            let issue_output = match &issue_txlog[3] {
                TxEntry::Output(x) => x.clone(),
                _ => return assert!(false, "TxLog entry doesn't match: expected Output"),
            };
            Token::retire(&mut retire_program, issue_output);
            build(retire_program, vec![dest_key]).unwrap()
        };

        // Verify tx
        let bp_gens = BulletproofGens::new(256, 1);
        assert!(tx.verify(&bp_gens).is_ok());
    }

    // Helper functions
    fn build(program: Program, keys: Vec<Scalar>) -> Result<(Tx, TxID, TxLog), VMError> {
        let bp_gens = BulletproofGens::new(256, 1);
        let header = TxHeader {
            version: 0u64,
            mintime_ms: 0u64,
            maxtime_ms: 0u64,
        };
        // TBD: figure out better + more robust signing mechanism
        let gens = PedersenGens::default();
        let utx = Prover::build_tx(program, header, &bp_gens)?;

        // find all the secret scalars for the pubkeys used in the VM
        let privkeys: Vec<Scalar> = utx
            .signing_instructions
            .iter()
            .filter_map(|(pubkey, _msg)| {
                for k in keys.iter() {
                    if (k * gens.B).compress() == *pubkey.as_point() {
                        return Some(*k);
                    }
                }
                None
            })
            .collect();

        let mut signtx_transcript = Transcript::new(b"ZkVM.signtx");
        signtx_transcript.append_message(b"txid", &utx.txid.0);
        let sig = Signature::sign_multi(
            privkeys,
            utx.signing_instructions.clone(),
            &mut signtx_transcript,
        )
        .unwrap();

        let txid = utx.txid;
        let txlog = utx.txlog.clone();
        let tx = utx.sign(sig);
        Ok((tx, txid, txlog))
    }
}
