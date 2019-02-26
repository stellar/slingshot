use bulletproofs::BulletproofGens;
use curve25519_dalek::scalar::Scalar;
use postgres::{Connection, TlsMode};
use zkvm::*;

pub struct Treasury {
    conn: Connection,
}

// TBD: define annotated struct for embedding metadata
// and other info with token flavors

impl Treasury {
    /// Creates a new token for the given Predicate.
    pub fn create_token(pred: Predicate) {
        unimplemented!()
    }

    /// Issues a token of the specified flavor and quantity to a destination
    /// specified by the Scalar private key.
    pub fn issue_token(
        flavor: Predicate,
        qty: u64,
        dest: Scalar,
    ) -> Result<(Tx, TxID, TxLog), VMError> {
        let issue_prog = Program::build(|p| issue_token(p, qty, flavor, dest)).to_vec();
        // Build tx
        let bp_gens = BulletproofGens::new(256, 1);
        let header = TxHeader {
            version: 0u64,
            mintime: 0u64,
            maxtime: 0u64,
        };
        Prover::build_tx(issue_prog, header, &bp_gens)
    }

    /// Returns the number of tokens of the given flavor in circulation.
    pub fn get_circulation(flavor: Scalar) -> Result<u64, VMError> {
        unimplemented!()
    }

    pub fn retire_token(flavor: Predicate, qty: u64) -> Result<(Tx, TxID, TxLog), VMError> {
        unimplemented!()
    }
}

// Helper functions to build programs

pub fn issue_token(
    program: &mut Program,
    qty: u64,
    flavor: Predicate,
    dest: Scalar,
) -> &mut Program {
    let nonce = Predicate::from_signing_key(Scalar::random(&mut rand::thread_rng()));
    program
        .push(Commitment::blinded(qty))
        .var()
        .push(Commitment::unblinded(Value::issue_flavor(&flavor)))
        .var()
        .push(flavor)
        .issue()
        .push(nonce)
        .nonce()
        .sign_tx()
        .sign_tx()
        .push(Predicate::from_signing_key(dest))
        .output(1)
}
