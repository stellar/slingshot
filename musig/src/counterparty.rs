use super::context::MusigContext;
use super::errors::MusigError;
use super::key::VerificationKey;
use crate::transcript::TranscriptProtocol;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use subtle::ConstantTimeEq;

#[derive(Copy, Clone)]
pub struct NoncePrecommitment([u8; 32]);

#[derive(Copy, Clone, Debug)]
pub struct NonceCommitment(RistrettoPoint);

impl NonceCommitment {
    pub(super) fn new(commitment: RistrettoPoint) -> Self {
        NonceCommitment(commitment)
    }

    pub(super) fn precommit(&self) -> NoncePrecommitment {
        let mut h = Transcript::new(b"Musig.nonce-precommit");
        h.commit_point(b"R", &self.0.compress());
        let mut precommitment = [0u8; 32];
        h.challenge_bytes(b"precommitment", &mut precommitment);
        NoncePrecommitment(precommitment)
    }

    pub(super) fn sum(commitments: &Vec<Self>) -> RistrettoPoint {
        commitments.iter().map(|R_i| R_i.0).sum()
    }
}

pub struct Counterparty {
    position: usize,
    pubkey: VerificationKey,
}

pub struct CounterpartyPrecommitted {
    precommitment: NoncePrecommitment,
    position: usize,
    pubkey: VerificationKey,
}

pub struct CounterpartyCommitted {
    commitment: NonceCommitment,
    position: usize,
    pubkey: VerificationKey,
}

impl Counterparty {
    pub(super) fn new(position: usize, pubkey: VerificationKey) -> Self {
        Counterparty { position, pubkey }
    }

    pub(super) fn precommit_nonce(
        self,
        precommitment: NoncePrecommitment,
    ) -> CounterpartyPrecommitted {
        CounterpartyPrecommitted {
            precommitment,
            position: self.position,
            pubkey: self.pubkey,
        }
    }
}

impl CounterpartyPrecommitted {
    pub(super) fn commit_nonce(
        self,
        commitment: NonceCommitment,
    ) -> Result<CounterpartyCommitted, MusigError> {
        // Check H(commitment) =? precommitment
        let received_precommitment = commitment.precommit();
        let equal = self.precommitment.0.ct_eq(&received_precommitment.0);
        if equal.unwrap_u8() == 0 {
            return Err(MusigError::ShareError {
                pubkey: self.pubkey.into_compressed().to_bytes(),
            });
        }

        Ok(CounterpartyCommitted {
            commitment: commitment,
            position: self.position,
            pubkey: self.pubkey,
        })
    }
}

impl CounterpartyCommitted {
    pub(super) fn check_share<C: MusigContext>(
        self,
        share: Scalar,
        context: &C,
        transcript: &Transcript,
    ) -> Result<Scalar, MusigError> {
        // Check if s_i * G == R_i + c * a_i * X_i.
        //   s_i = share
        //   G = RISTRETTO_BASEPOINT_POINT
        //   R_i = self.commitment
        //   c = challenge
        //   a_i = multikey.factor_for_key(self.pubkey)
        //   X_i = self.pubkey
        let S_i = share * RISTRETTO_BASEPOINT_POINT;
        let c_i = context.challenge(self.position, &mut transcript.clone());
        let X_i = self.pubkey.into_point();

        if S_i != self.commitment.0 + c_i * X_i {
            return Err(MusigError::ShareError {
                pubkey: X_i.compress().to_bytes(),
            });
        }

        Ok(share)
    }
}
