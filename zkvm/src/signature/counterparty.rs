use crate::signature::VerificationKey;

pub struct Counterparty {
    pubkey: VerificationKey,
}

pub struct CounterpartyPrecommitted {
    precommitment: NoncePrecommitment,
    pubkey: VerificationKey,
}

pub struct CounterpartyCommitted {
    commitment: NonceCommitment,
    pubkey: VerificationKey,
}
