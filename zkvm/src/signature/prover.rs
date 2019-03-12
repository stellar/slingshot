#![allow(non_snake_case)]

use crate::signature::multikey::Multikey;
use crate::signature::musig::*;
use crate::signature::VerificationKey;
use crate::transcript::TranscriptProtocol;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use rand;

#[derive(Clone)]
pub struct Nonce(Scalar);

#[derive(Clone)]
pub struct NoncePrecommitment(Scalar);

// TODO: compress & decompress RistrettoPoint into CompressedRistretto when sending as message
#[derive(Clone)]
pub struct NonceCommitment(RistrettoPoint);

#[derive(Clone)]
pub struct Siglet(Scalar);

pub struct PartyAwaitingPrecommitments<'a> {
    transcript: &'a mut Transcript,
    multikey: Multikey,
    x_i: PrivKey,
    r_i: Nonce,
    R_i: NonceCommitment,
}

pub struct PartyAwaitingCommitments<'a> {
    transcript: &'a mut Transcript,
    multikey: Multikey,
    x_i: PrivKey,
    r_i: Nonce,
    nonce_precommitments: Vec<NoncePrecommitment>,
}

pub struct PartyAwaitingSiglets<'a> {
    transcript: &'a mut Transcript,
    multikey: Multikey,
    nonce_commitments: Vec<NonceCommitment>,
    m: Message,
}

impl<'a> PartyAwaitingPrecommitments<'a> {
    pub fn new(
        transcript: &'a mut Transcript,
        x_i: PrivKey,
        multikey: Multikey,
    ) -> (Self, NoncePrecommitment) {
        let mut rng = transcript.build_rng().finalize(&mut rand::thread_rng());

        // Generate ephemeral keypair (r_i, R_i). r_i is a random nonce.
        let r_i = Nonce(Scalar::random(&mut rng));
        // R_i = generator * r_i
        let R_i = NonceCommitment(RISTRETTO_BASEPOINT_POINT * r_i.0);

        // Make H(R_i)
        transcript.commit_point(b"R_i", &R_i.0.compress());
        let precommitment = NoncePrecommitment(transcript.challenge_scalar(b"nonce.precommit"));

        (
            PartyAwaitingPrecommitments {
                transcript,
                multikey,
                x_i,
                r_i,
                R_i,
            },
            precommitment,
        )
    }

    pub fn receive_precommitments(
        self,
        nonce_precommitments: Vec<NoncePrecommitment>,
    ) -> (PartyAwaitingCommitments<'a>, NonceCommitment) {
        // Store received nonce precommitments in next state
        (
            PartyAwaitingCommitments {
                transcript: self.transcript,
                multikey: self.multikey,
                x_i: self.x_i,
                r_i: self.r_i,
                nonce_precommitments,
            },
            self.R_i,
        )
    }
}

impl<'a> PartyAwaitingCommitments<'a> {
    pub fn receive_commitments(
        self,
        m: Message,
        nonce_commitments: Vec<NonceCommitment>,
    ) -> (PartyAwaitingSiglets<'a>, Siglet) {
        // Check stored precommitments against received commitments
        for (pre_comm, comm) in self
            .nonce_precommitments
            .iter()
            .zip(nonce_commitments.iter())
        {
            // Make H(comm) = H(R_i)
            let mut precomm_transcript = self.transcript.clone();
            precomm_transcript.commit_point(b"R_i", &comm.0.compress());
            let correct_precomm = precomm_transcript.challenge_scalar(b"nonce.precommit");

            // Compare H(comm) with pre_comm, they should be equal
            assert_eq!(pre_comm.0, correct_precomm);
        }

        // Make R = sum_i(R_i). nonce_commitments = R_i from all the parties.
        let R: RistrettoPoint = nonce_commitments.iter().map(|R_i| R_i.0).sum();

        // Make c = H(X_agg, R, m)
        let c = {
            self.transcript
                .commit_point(b"X_agg", &self.multikey.aggregated_key().0);
            self.transcript.commit_point(b"R", &R.compress());
            self.transcript.commit_bytes(b"m", &m.0);
            self.transcript.challenge_scalar(b"c")
        };

        // Make a_i = H(L, X_i)
        let X_i = VerificationKey((self.x_i.0 * RISTRETTO_BASEPOINT_POINT).compress());
        let a_i = self.multikey.a_i(&X_i);

        // Generate siglet: s_i = r_i + c * a_i * x_i
        let s_i = self.r_i.0 + c * a_i * self.x_i.0;

        // Store received nonce commitments in next state
        (
            PartyAwaitingSiglets {
                transcript: self.transcript,
                multikey: self.multikey,
                nonce_commitments,
                m,
            },
            Siglet(s_i),
        )
    }
}

impl<'a> PartyAwaitingSiglets<'a> {
    pub fn receive_siglets(self, siglets: Vec<Siglet>) -> Signature {
        // s = sum(siglets)
        let s: Scalar = siglets.iter().map(|siglet| siglet.0).sum();
        // R = sum(R_i). nonce_commitments = R_i
        let R: RistrettoPoint = self.nonce_commitments.iter().map(|R_i| R_i.0).sum();

        Signature { s, R }
    }

    pub fn receive_and_verify_siglets(
        self,
        siglets: Vec<Siglet>,
        pubkeys: Vec<PubKey>,
    ) -> Signature {
        // Check that all siglets are valid
        for (i, s_i) in siglets.iter().enumerate() {
            let S_i = s_i.0 * RISTRETTO_BASEPOINT_POINT;
            let X_i = pubkeys[i].0;
            let R_i = self.nonce_commitments[i].0;
            let R: RistrettoPoint = self.nonce_commitments.iter().map(|R_i| R_i.0).sum();

            // Make c = H(X_agg, R, m)
            let c = {
                let mut c_transcript = self.transcript.clone();
                c_transcript.commit_point(b"X_agg", &self.multikey.aggregated_key().0);
                c_transcript.commit_point(b"R", &R.compress());
                c_transcript.commit_bytes(b"m", &self.m.0);
                c_transcript.challenge_scalar(b"c")
            };
            // Make a_i = H(L, X_i)
            let a_i = self.multikey.a_i(&VerificationKey(X_i.compress()));

            // Check that S_i = R_i + c * a_i * X_i
            assert_eq!(S_i, R_i + c * a_i * X_i);
        }

        self.receive_siglets(siglets)
    }
}
