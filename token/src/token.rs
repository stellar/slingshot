use bulletproofs::{BulletproofGens, PedersenGens};
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use zkvm::{
    Commitment, Data, Entry, Input, Instruction, Predicate, Program, Prover, Signature, Tx,
    TxHeader, TxID, TxLog, VMError, Value, VerificationKey, Verifier,
};

/// Represents a ZkVM Token with unique flavor and embedded
/// metadata protected by a user-supplied Predicate.
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
        Value::issue_flavor(&self.issuance_predicate, Data::Opaque(self.metadata.clone()))
    }

    /// Returns program that issues specified quantity of Token.
    pub fn issue<'a>(program: &'a mut Program, token: &Token, qty: u64) -> &'a mut Program {
        program
            .push(Commitment::blinded(qty)) // stack: qty
            .var() // stack: qty-var
            .push(Commitment::unblinded(token.flavor())) // stack: qty-var, flv
            .var() // stack: qty-var, flv-var
            .push(Data::Opaque(token.metadata.clone())) // stack: qty-var, flv-var, data
            .push(token.issuance_predicate.clone()) // stack: qty-var, flv-var, data, flv-pred
            .issue() // stack: issue-contract
            .sign_tx() // stack: issued-value
    }

    /// Returns program that issues specified quantity of Token,
    /// outputting it to the destination Predicate.
    pub fn issue_to<'a>(
        program: &'a mut Program,
        token: &Token,
        qty: u64,
        dest: &Predicate,
    ) -> &'a mut Program {
        Token::issue(program, token, qty)
            .push(dest.clone())
            .output(1)
    }

    /// Returns program that retires a Token.
    /// TBD: better symmetry here to accept a Token object
    pub fn retire<'a>(
        program: &'a mut Program,
        qty: CompressedRistretto,
        flv: CompressedRistretto,
        pred: &Predicate,
        txid: TxID,
    ) -> &'a mut Program {
        let output = (Commitment::Closed(qty), Commitment::Closed(flv));
        program
            .push(Data::Input(Box::new(Input::new(
                vec![output],
                pred.clone(),
                txid,
            ))))
            .input()
            .sign_tx()
            .retire()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issue_to() {
        let (tx, _, txlog) = {
            let issue_key = Scalar::from(1u64);
            let dest_key = Scalar::from(2u64);
            let nonce_key = Scalar::from(3u64);
            let usd = Token::new(
                Predicate::Key(VerificationKey::from_secret(&issue_key)),
                b"USD".to_vec(),
            );
            let dest = Predicate::Key(VerificationKey::from_secret(&dest_key));
            let program = Program::build(|p| {
                Token::issue_to(p, &usd, 10u64, &dest)
                    .push(Predicate::Key(VerificationKey::from_secret(&nonce_key)))
                    .nonce()
                    .sign_tx()
            })
            .to_vec();
            build(program, vec![issue_key, nonce_key]).unwrap()
        };

        // Verify tx
        let bp_gens = BulletproofGens::new(256, 1);
        let vtx = Verifier::verify_tx(tx, &bp_gens).unwrap();
        assert_eq!(vtx.log, txlog);
    }

    #[test]
    fn issue_and_retire() {
        // Issue tx
        let (tx, _, txlog) = {
            let issue_key = Scalar::from(1u64);
            let dest_key = Scalar::from(2u64);
            let nonce_key = Scalar::from(3u64);
            let usd = Token::new(
                Predicate::Key(VerificationKey::from_secret(&issue_key)),
                b"USD".to_vec(),
            );
            let dest = Predicate::Key(VerificationKey::from_secret(&dest_key));
            let issue_program = Program::build(|p| {
                Token::issue_to(p, &usd, 10u64, &dest)
                    .push(Predicate::Key(VerificationKey::from_secret(&nonce_key)))
                    .nonce()
                    .sign_tx()
            })
            .to_vec();
            let (_, issue_txid, issue_txlog) = build(issue_program, vec![issue_key, nonce_key]).unwrap();

            let mut retire_program = Program::new();
            let (qty, flv) = match issue_txlog[1] {
                Entry::Issue(q, f) => (q, f),
                _ => return assert!(false, "TxLog entry doesn't match: expected Issue"),
            };
            Token::retire(&mut retire_program, qty, flv, &dest, issue_txid);
            build(retire_program.to_vec(), vec![dest_key]).unwrap()
        };

        // Verify tx
        let bp_gens = BulletproofGens::new(256, 1);
        let vtx = Verifier::verify_tx(tx, &bp_gens).unwrap();
        assert_eq!(vtx.log, txlog);
    }

    // Helper functions
    fn build(
        program: Vec<Instruction>,
        keys: Vec<Scalar>,
    ) -> Result<(Tx, TxID, TxLog), VMError> {
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
