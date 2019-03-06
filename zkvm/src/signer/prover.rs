#![allow(non_snake_case)]

use crate::signer::*;
use crate::transcript::TranscriptProtocol;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use rand;

#[derive(Copy, Clone)]
pub struct Nonce(RistrettoPoint);
pub struct NoncePrecommitment(Scalar);
pub struct Siglet(RistrettoPoint);

pub struct PartyAwaitingHashes<'a> {
    generator: RistrettoPoint,
    transcript: &'a mut Transcript,
    r_i: Scalar,
    R_i: Nonce,
}

pub struct PartyAwaitingNonces<'a> {
    generator: RistrettoPoint,
    transcript: &'a mut Transcript,
    r_i: Scalar,
    R_i: Nonce,
    R_hashes: Vec<NoncePrecommitment>,
}

pub struct PartyAwaitingSiglets<'a> {
    generator: RistrettoPoint,
    transcript: &'a mut Transcript,
    r_i: Scalar,
    R_i: Nonce,
    R_vec: Vec<Nonce>,
}

impl<'a> PartyAwaitingHashes<'a> {
    pub fn new(
        generator: RistrettoPoint,
        transcript: &'a mut Transcript,
        privkey: PrivKey,
        pubkeys: MultikeyWitness,
    ) -> (Self, NoncePrecommitment) {
        let mut rng = transcript.build_rng().finalize(&mut rand::thread_rng());

        // generate ephemeral keypair (k_i, R_i). R_i = generator * k_i
        let r_i = Scalar::random(&mut rng);
        let R_i = Nonce(generator * r_i);

        // make H(R_i)
        let mut hash_transcript = transcript.clone();
        hash_transcript.commit_point(b"R_i", &R_i.0.compress());
        let precommitment = NoncePrecommitment(transcript.challenge_scalar(b"R_i.precommit"));

        (
            PartyAwaitingHashes {
                generator,
                transcript,
                r_i,
                R_i,
            },
            precommitment,
        )
    }

    pub fn receive_hashes(
        self,
        hashes: Vec<NoncePrecommitment>,
    ) -> (PartyAwaitingNonces<'a>, Nonce) {
        // store received hashes
        (
            PartyAwaitingNonces {
                generator: self.generator,
                transcript: self.transcript,
                r_i: self.r_i,
                R_i: self.R_i,
                R_hashes: hashes,
            },
            self.R_i,
        )
    }
}

impl<'a> PartyAwaitingNonces<'a> {
    pub fn receive_nonces(self, nonces: Vec<Nonce>) -> (PartyAwaitingSiglets<'a>, Siglet) {
        // TODO: check stored hashes against received nonces
        // TODO: generate siglet
        // store received nonces
        let _ = PartyAwaitingSiglets {
            generator: self.generator,
            transcript: self.transcript,
            r_i: self.r_i,
            R_i: self.R_i,
            R_vec: nonces,
        };
        unimplemented!()
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
