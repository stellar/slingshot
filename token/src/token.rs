use bulletproofs::{BulletproofGens, PedersenGens};
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use zkvm::*;

pub struct Token {
    flavor: Predicate,
    metadata: Vec<u8>,
    nonce: Scalar,
}

impl Token {
    pub fn new(pred: Predicate, metadata: &[u8]) -> Self {
        Token {
            flavor: pred,
            metadata: metadata.to_vec(),
            nonce: Scalar::random(&mut rand::thread_rng()),
        }
    }

    pub fn issue<'a>(program: &'a mut Program, token: &Token, qty: u64) -> &'a mut Program {
        let nonce = Predicate::Key(VerificationKey::from_secret(&token.nonce));
        program
            .push(Commitment::blinded(qty)) // stack: qty
            .var() // stack: qty-var
            .push(Commitment::unblinded(Value::issue_flavor(
                &token.flavor,
                Data::Opaque(token.metadata.to_vec()),
            ))) // stack: qty-var, flv
            .var() // stack: qty-var, flv-var
            .push(Data::Opaque(token.metadata.to_vec())) // stack: qty-var, flv-var, data
            .push(token.flavor.clone()) // stack: qty-var, flv-var, data, flv-pred
            .issue() // stack: issue-contract
            .push(nonce) // stack: issue-contract, nonce-pred
            .nonce() // stack: issue-contract, nonce-contract
            .sign_tx() // stack: issue-contract
            .sign_tx() // stack: issued-value
    }

    pub fn issue_and_spend<'a>(
        program: &'a mut Program,
        token: &Token,
        qty: u64,
        dest: &Predicate,
    ) -> &'a mut Program {
        Token::issue(program, token, qty)
            .push(dest.clone())
            .output(1)
    }

    pub fn build(
        program: Vec<Instruction>,
        token: &Token,
        mut keys: Vec<Scalar>,
    ) -> Result<(Tx, TxID, TxLog), VMError> {
        let bp_gens = BulletproofGens::new(256, 1);
        let header = TxHeader {
            version: 0u64,
            mintime: 0u64,
            maxtime: 0u64,
        };
        // TBD: figure out better + more robust signing mechanism
        let gens = PedersenGens::default();
        keys.push(token.nonce);
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

    /// Builds a transaction to issue and spend a transaction, returning
    /// the TxLog Entry containing the Output entry to input later.
    pub fn build_issue_and_spend(
        token: &Token,
        qty: u64,
        dest: Predicate,
        issue_key: Scalar,
    ) -> Result<(Tx, TxID, TxLog, Entry), VMError> {
        let mut program = Program::new();
        Token::issue_and_spend(&mut program, &token, qty, &dest);
        let (tx, txid, txlog) =
            Token::build(program.to_vec(), token, vec![issue_key, token.nonce])?;
        let output = txlog[0].clone();
        Ok((tx, txid, txlog, output))
    }

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
    fn issue_and_spend() {
        let (tx, _, txlog) = {
            let pred = Predicate::Key(VerificationKey::from_secret(&Scalar::from(1u64)));
            let usd = Token::new(pred, b"USD");
            let dest = Predicate::Key(VerificationKey::from_secret(&Scalar::from(2u64)));
            let mut program = Program::new();
            Token::issue_and_spend(&mut program, &usd, 10u64, &dest);
            match Token::build(program.to_vec(), &usd, vec![Scalar::from(1u64)]) {
                Ok(x) => x,
                Err(err) => return assert!(false, err.to_string()),
            }
        };

        // Verify tx
        let bp_gens = BulletproofGens::new(256, 1);
        match Verifier::verify_tx(tx, &bp_gens) {
            Err(err) => return assert!(false, err.to_string()),
            Ok(v) => {
                assert_eq!(v.log, txlog);
            }
        };
    }

    #[test]
    fn issue_and_retire() {
        // Issue tx
        let (tx, _, txlog) = {
            let issue_key = Scalar::from(1u64);
            let dest_key = Scalar::from(2u64);
            let usd = Token::new(
                Predicate::Key(VerificationKey::from_secret(&issue_key)),
                b"USD",
            );
            let dest = Predicate::Key(VerificationKey::from_secret(&dest_key));
            let mut issue_program = Program::new();
            Token::issue_and_spend(&mut issue_program, &usd, 10u64, &dest);
            let (_, issue_txid, issue_txlog) =
                match Token::build(issue_program.to_vec(), &usd, vec![issue_key]) {
                    Ok(x) => x,
                    Err(err) => return assert!(false, err.to_string()),
                };

            let mut retire_program = Program::new();
            let (qty, flv) = match issue_txlog[1] {
                Entry::Issue(q, f) => (q, f),
                _ => return assert!(false, "TxLog entry doesn't match: expected Issue"),
            };
            Token::retire(&mut retire_program, qty, flv, &dest, issue_txid);
            match Token::build(retire_program.to_vec(), &usd, vec![dest_key]) {
                Ok(x) => x,
                Err(err) => return assert!(false, err.to_string()),
            }
        };

        // Verify tx
        let bp_gens = BulletproofGens::new(256, 1);
        match Verifier::verify_tx(tx, &bp_gens) {
            Err(err) => return assert!(false, err.to_string()),
            Ok(v) => {
                assert_eq!(v.log, txlog);
            }
        };
    }
}
