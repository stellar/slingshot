#![allow(non_snake_case)]

use crate::signer::*;
use crate::transcript::TranscriptProtocol;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use rand;

#[derive(Copy, Clone)]
pub struct Nonce(Scalar);
pub struct NoncePrecommitment(Scalar);
pub struct NonceCommitment(RistrettoPoint);
pub struct Siglet(Scalar);

// TODO: come up with a better name for this!
pub struct Shared<'a> {
    generator: RistrettoPoint,
    transcript: &'a mut Transcript,
    // X = sum_i ( H(L, X_i) * X_i )
    agg_pubkey: PubKey,
    // L = H(X_1 || X_2 || ... || X_n)
    agg_pubkey_hash: PubKeyHash,
    // TODO: what should the message representation format be?
    message: Vec<u8>,
}

pub struct PartyAwaitingPrecommitments<'a> {
    shared: Shared<'a>,
    x_i: PrivKey,
    r_i: Nonce,
    R_i: NonceCommitment,
}

pub struct PartyAwaitingCommitments<'a> {
    shared: Shared<'a>,
    x_i: PrivKey,
    r_i: Nonce,
    nonce_precommitments: Vec<NoncePrecommitment>,
}

pub struct PartyAwaitingSiglets<'a> {
    shared: Shared<'a>,
    x_i: PrivKey,
    r_i: Nonce,
    nonce_commitments: Vec<NonceCommitment>,
}

impl<'a> PartyAwaitingPrecommitments<'a> {
    pub fn new(x_i: PrivKey, shared: Shared<'a>) -> (Self, NoncePrecommitment) {
        let mut rng = shared
            .transcript
            .build_rng()
            .finalize(&mut rand::thread_rng());

        // Generate ephemeral keypair (r_i, R_i). r_i is a random nonce.
        let r_i = Nonce(Scalar::random(&mut rng));
        // R_i = generator * r_i
        let R_i = NonceCommitment(shared.generator * r_i.0);

        // Make H(R_i)
        let mut hash_transcript = shared.transcript.clone();
        hash_transcript.commit_point(b"R_i", &R_i.0.compress());
        let precommitment =
            NoncePrecommitment(hash_transcript.challenge_scalar(b"nonce.precommit"));

        (
            PartyAwaitingPrecommitments {
                shared,
                x_i,
                r_i,
                R_i,
            },
            precommitment,
        )
    }

    pub fn receive_hashes(
        self,
        nonce_precommitments: Vec<NoncePrecommitment>,
    ) -> (PartyAwaitingCommitments<'a>, NonceCommitment) {
        // Store received nonce precommitments in next state
        (
            PartyAwaitingCommitments {
                shared: self.shared,
                x_i: self.x_i,
                r_i: self.r_i,
                nonce_precommitments,
            },
            self.R_i,
        )
    }
}

impl<'a> PartyAwaitingCommitments<'a> {
    pub fn receive_nonces(
        self,
        nonce_commitments: Vec<NonceCommitment>,
    ) -> (PartyAwaitingSiglets<'a>, Siglet) {
        // Check stored precommitments against received commitments
        for (pre_comm, comm) in self
            .nonce_precommitments
            .iter()
            .zip(nonce_commitments.iter())
        {
            // Make H(comm) = H(R_i)
            let mut hash_transcript = self.shared.transcript.clone();
            hash_transcript.commit_point(b"R_i", &comm.0.compress());
            let correct_precomm = hash_transcript.challenge_scalar(b"nonce.precommit");

            // Compare H(comm) with pre_comm, they should be equal
            assert_eq!(pre_comm.0, correct_precomm);
        }

        // Make R = sum_i(R_i). nonce_commitments = R_i from all the parties.
        let R: RistrettoPoint = nonce_commitments.iter().map(|R_i| R_i.0).sum();

        // Make H(X,R,m). shared.agg_pubkey = X, shared.message = m.
        let hash_x_R_m = {
            let mut hash_transcript = self.shared.transcript.clone();
            hash_transcript.commit_point(b"X", &self.shared.agg_pubkey.0.compress());
            hash_transcript.commit_point(b"R", &R.compress());
            hash_transcript.commit_bytes(b"m", &self.shared.message);
            hash_transcript.challenge_scalar(b"hash_x_R_m")
        };

        // Make H(L,X_i). shared.agg_pubkey_hash = L,
        let hash_L_X_i = {
            let mut hash_transcript = self.shared.transcript.clone();
            hash_transcript.commit_scalar(b"L", &self.shared.agg_pubkey_hash.0);
            let X_i = self.x_i.0 * self.shared.generator;
            hash_transcript.commit_point(b"X_i", &X_i.compress());
            hash_transcript.challenge_scalar(b"hash_L_X_i")
        };

        // Generate siglet: s_i = r_i + H(X,R,m)*H(L,X_i)*x_i
        let s_i = self.r_i.0 + hash_x_R_m * hash_L_X_i * self.x_i.0;

        // Store received nonce commitments in next state
        (
            PartyAwaitingSiglets {
                shared: self.shared,
                x_i: self.x_i,
                r_i: self.r_i,
                nonce_commitments,
            },
            Siglet(s_i),
        )
    }
}

impl<'a> PartyAwaitingSiglets<'a> {
    pub fn receive_siglets(self, _siglets: Vec<Siglet>) -> Signature {
        // verify received siglets
        // s = sum(siglets)
        // R = sum(R_vec)
        unimplemented!();
    }
}
