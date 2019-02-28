use bulletproofs::{BulletproofGens, PedersenGens};
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

    pub fn issue<'a>(&self, program: &'a mut Program, qty: u64) -> &'a mut Program {
        let nonce = Predicate::Key(VerificationKey::from_secret(&self.nonce));
        program
            .push(Commitment::blinded(qty)) // stack: qty
            .var() // stack: qty-var
            .push(Commitment::unblinded(Value::issue_flavor(
                &self.flavor,
                Data::Opaque(self.metadata.to_vec()),
            ))) // stack: qty-var, flv
            .var() // stack: qty-var, flv-var
            .push(Data::Opaque(self.metadata.to_vec())) // stack: qty-var, flv-var, data
            .push(self.flavor.clone()) // stack: qty-var, flv-var, data, flv-pred
            .issue() // stack: issue-contract
            .push(nonce) // stack: issue-contract, nonce-pred
            .nonce() // stack: issue-contract, nonce-contract
            .sign_tx() // stack: issue-contract
            .sign_tx() // stack: issued-value
    }

    pub fn issue_and_spend<'a>(
        &self,
        program: &'a mut Program,
        qty: u64,
        dest: Predicate,
    ) -> &'a mut Program {
        self.issue(program, qty).push(dest).output(1)
    }

    pub fn build(
        program: Program,
        token: Token,
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
        Prover::build_tx(
            program.to_vec(),
            header,
            &bp_gens,
            |t, verification_keys| {
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
            },
        )
    }

    // TBD: do we want retire to input some value to the stack for it to
    // then retire? or to assume that there's already the appropriate
    // value on the stack and just add the retire instruction.
    pub fn retire(&self, program: Program) {
        unimplemented!()
    }
}
