use bulletproofs::BulletproofGens;
use curve25519_dalek::scalar::Scalar;
use zkvm::*;

pub struct Treasury {
    // TBD: add store to track tokens in circulation
}

// TBD: define annotated struct for embedding metadata
// and other info with token flavors

impl Treasury {
    /// Creates a new token flavor, returning the flavor Predicate
    /// and its Scalar representation
    pub fn create_token() -> (Predicate, Scalar) {
        let flavor_pred = Predicate::from_signing_key(Scalar::random(&mut rand::thread_rng()));
        let flavor_scalar = Value::issue_flavor(&flavor_pred);
        (flavor_pred, flavor_scalar)
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
        .push(Commitment::blinded_with_factor(
            qty,
            Scalar::random(&mut rand::thread_rng()),
        ))
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
