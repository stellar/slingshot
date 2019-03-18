#![allow(non_snake_case)]

use crate::errors::VMError;
use crate::signature::multikey::Multikey;
use crate::signature::musig::*;
use crate::signature::VerificationKey;
use crate::transcript::TranscriptProtocol;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use rand;
use subtle::ConstantTimeEq;

#[derive(Copy, Clone)]
pub struct NoncePrecommitment([u8; 32]);

#[derive(Copy, Clone, Debug)]
pub struct NonceCommitment(RistrettoPoint);

pub struct Party {}

pub struct PartyAwaitingPrecommitments {
    transcript: Transcript,
    multikey: Multikey,
    x_i: Scalar,
    r_i: Scalar,
    R_i: NonceCommitment,
}

pub struct PartyAwaitingCommitments {
    transcript: Transcript,
    multikey: Multikey,
    x_i: Scalar,
    r_i: Scalar,
    nonce_precommitments: Vec<NoncePrecommitment>,
}

pub struct PartyAwaitingShares {
    multikey: Multikey,
    c: Scalar,
    R: RistrettoPoint,
    nonce_commitments: Vec<NonceCommitment>,
}

impl NonceCommitment {
    fn precommit(&self) -> NoncePrecommitment {
        let mut h = Transcript::new(b"MuSig.nonce-precommit");
        h.commit_point(b"R", &self.0.compress());
        let mut precommitment = [0u8; 32];
        h.challenge_bytes(b"precommitment", &mut precommitment);
        NoncePrecommitment(precommitment)
    }
}

impl Party {
    pub fn new(
        // The message `m` should already have been fed into the transcript
        transcript: &Transcript,
        x_i: Scalar,
        multikey: Multikey,
    ) -> (PartyAwaitingPrecommitments, NoncePrecommitment) {
        let mut rng = transcript
            .build_rng()
            .commit_witness_bytes(b"x_i", &x_i.to_bytes())
            .finalize(&mut rand::thread_rng());

        // Generate ephemeral keypair (r_i, R_i). r_i is a random nonce.
        let r_i = Scalar::random(&mut rng);
        // R_i = generator * r_i
        let R_i = NonceCommitment(RISTRETTO_BASEPOINT_POINT * r_i);
        // Make H(R_i)
        let precommitment = R_i.precommit();

        (
            PartyAwaitingPrecommitments {
                transcript: transcript.clone(),
                multikey,
                x_i,
                r_i,
                R_i,
            },
            precommitment,
        )
    }
}

impl PartyAwaitingPrecommitments {
    pub fn receive_precommitments(
        self,
        nonce_precommitments: Vec<NoncePrecommitment>,
    ) -> (PartyAwaitingCommitments, NonceCommitment) {
        // Store received nonce precommitments in next state
        (
            PartyAwaitingCommitments {
                nonce_precommitments,
                transcript: self.transcript,
                multikey: self.multikey,
                x_i: self.x_i,
                r_i: self.r_i,
            },
            self.R_i,
        )
    }
}

impl PartyAwaitingCommitments {
    pub fn receive_commitments(
        mut self,
        nonce_commitments: Vec<NonceCommitment>,
    ) -> Result<(PartyAwaitingShares, Scalar), VMError> {
        // Check stored precommitments against received commitments
        for (index, (pre_comm, comm)) in self
            .nonce_precommitments
            .iter()
            .zip(nonce_commitments.iter())
            .enumerate()
        {
            // Make H(comm) = H(R_i)
            let actual_precomm = comm.precommit();

            // Compare H(comm) with pre_comm, they should be equal
            let equal = pre_comm.0.ct_eq(&actual_precomm.0);
            if equal.unwrap_u8() == 0 {
                return Err(VMError::ShareError { index });
            }
        }

        // Make R = sum_i(R_i). nonce_commitments = R_i from all the parties.
        let R: RistrettoPoint = nonce_commitments.iter().map(|R_i| R_i.0).sum();

        // Make c = H(X, R, m)
        // The message `m` should already have been fed into the transcript.
        let c = {
            self.transcript
                .commit_point(b"P", &self.multikey.aggregated_key().0);
            self.transcript.commit_point(b"R", &R.compress());
            self.transcript.challenge_scalar(b"c")
        };

        // Make a_i = H(L, X_i)
        let X_i = VerificationKey((self.x_i * RISTRETTO_BASEPOINT_POINT).compress());
        let a_i = self.multikey.factor_for_key(&X_i);

        // Generate share: s_i = r_i + c * a_i * x_i
        let s_i = self.r_i + c * a_i * self.x_i;

        // Store received nonce commitments in next state
        Ok((
            PartyAwaitingShares {
                multikey: self.multikey,
                nonce_commitments,
                c,
                R,
            },
            s_i,
        ))
    }
}

impl PartyAwaitingShares {
    pub fn receive_trusted_shares(self, shares: Vec<Scalar>) -> Signature {
        // s = sum(s_i), s_i = shares[i]
        let s: Scalar = shares.into_iter().map(|share| share).sum();
        Signature { s, R: self.R }
    }

    pub fn receive_shares(
        self,
        shares: Vec<Scalar>,
        pubkeys: Vec<VerificationKey>,
    ) -> Result<Signature, VMError> {
        // Check that all shares are valid
        for (i, s_i) in shares.iter().enumerate() {
            let S_i = s_i * RISTRETTO_BASEPOINT_POINT;
            let X_i = pubkeys[i];
            let R_i = self.nonce_commitments[i].0;

            // Make a_i = H(L, X_i)
            let a_i = self.multikey.factor_for_key(&VerificationKey(X_i.0));

            let X_i = X_i.0.decompress().ok_or(VMError::InvalidPoint)?;

            // Check that S_i = R_i + c * a_i * X_i
            if S_i != R_i + self.c * a_i * X_i {
                return Err(VMError::ShareError { index: i });
            }
        }

        Ok(self.receive_trusted_shares(shares))
    }
}
