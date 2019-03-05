#![allow(non_snake_case)]

use crate::transcript::TranscriptProtocol;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use rand;

pub struct PartyAwaitingHashes<'a> {
    generator: RistrettoPoint,
    transcript: &'a mut Transcript,
    k_i: Scalar,
    R_i: RistrettoPoint,
}
pub struct Hash(Scalar);

pub struct PartyAwaitingNonces<'a> {
    generator: RistrettoPoint,
    transcript: &'a mut Transcript,
    k_i: Scalar,
    R_i: RistrettoPoint,
    R_hashes: Vec<Hash>,
}
pub struct Nonce(RistrettoPoint);

pub struct PartyAwaitingSiglets<'a> {
    generator: RistrettoPoint,
    transcript: &'a mut Transcript,
    k_i: Scalar,
    R_i: RistrettoPoint,
    R_vec: Vec<Nonce>,
}
pub struct Siglet(RistrettoPoint);

pub struct Signature {
    s: Scalar,
    r: RistrettoPoint,
}

// TODO: compress & decompress RistrettoPoint into CompressedRistretto when sending as messages

impl<'a> PartyAwaitingHashes<'a> {
    pub fn new(generator: RistrettoPoint, transcript: &'a mut Transcript) -> (Self, Hash) {
        let mut rng = transcript.build_rng().finalize(&mut rand::thread_rng());

        // generate ephemeral keypair (k_i, R_i). R_i = generator * k_i
        let k_i = Scalar::random(&mut rng);
        let R_i = generator * k_i;

        // make H(R_i)
        let mut hash_transcript = transcript.clone();
        hash_transcript.commit_point(b"R_i", &R_i.compress());
        let hash = Hash(transcript.challenge_scalar(b"R_i.hash"));

        (
            PartyAwaitingHashes {
                generator,
                transcript,
                k_i,
                R_i,
            },
            hash,
        )
    }

    pub fn receive_hashes(self, hashes: Vec<Hash>) -> PartyAwaitingNonces<'a> {
        // store received hashes
        PartyAwaitingNonces {
            generator: self.generator,
            transcript: self.transcript,
            k_i: self.k_i,
            R_i: self.R_i,
            R_hashes: hashes,
        }
    }
}

impl<'a> PartyAwaitingNonces<'a> {
    pub fn receive_nonces(self, nonces: Vec<Nonce>) -> PartyAwaitingSiglets<'a> {
        // TODO: check stored hashes against received nonces

        // store received nonces
        PartyAwaitingSiglets {
            generator: self.generator,
            transcript: self.transcript,
            k_i: self.k_i,
            R_i: self.R_i,
            R_vec: nonces,
        }
    }
}

impl<'a> PartyAwaitingSiglets<'a> {
    pub fn receive_siglets(self, _siglets: Vec<Siglet>) -> Signature {
        // verify received siglets
        // s = sum(siglets
        // R = sum(R_vec)
        unimplemented!();
    }
}
