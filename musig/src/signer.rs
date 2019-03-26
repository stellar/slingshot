use super::counterparty::*;
use super::errors::MusigError;
use super::key::{Multikey, VerificationKey};
use super::signature::Signature;
use super::transcript::TranscriptProtocol;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use rand;

/// Entry point to multi-party signing protocol.
pub struct Party {}

/// State of the party when awaiting nonce precommitments from other parties.
pub struct PartyAwaitingPrecommitments<'t> {
    transcript: &'t mut Transcript,
    multikey: Multikey,
    x_i: Scalar,
    r_i: Scalar,
    R_i: NonceCommitment,
    counterparties: Vec<Counterparty>,
}

/// State of the party when awaiting nonce commitments from other parties.
pub struct PartyAwaitingCommitments<'t> {
    transcript: &'t mut Transcript,
    multikey: Multikey,
    x_i: Scalar,
    r_i: Scalar,
    counterparties: Vec<CounterpartyPrecommitted>,
}

/// State of the party when awaiting signature shares from other parties.
pub struct PartyAwaitingShares {
    multikey: Multikey,
    c: Scalar,
    R: RistrettoPoint,
    counterparties: Vec<CounterpartyCommitted>,
}

impl Party {
    /// Create new signing party for a given transcript.
    pub fn new<'t>(
        // The message `m` has already been fed into the transcript
        transcript: &'t mut Transcript,
        x_i: Scalar,
        multikey: Multikey,
        // TBD: move this inside Multikey API to avoid such redundancy.
        pubkeys: Vec<VerificationKey>,
    ) -> (PartyAwaitingPrecommitments<'t>, NoncePrecommitment) {
        let mut rng = transcript
            .build_rng()
            .commit_witness_bytes(b"x_i", &x_i.to_bytes())
            .finalize(&mut rand::thread_rng());

        // Generate ephemeral keypair (r_i, R_i). r_i is a random nonce.
        let r_i = Scalar::random(&mut rng);
        // R_i = generator * r_i
        let R_i = NonceCommitment::new(RISTRETTO_BASEPOINT_POINT * r_i);
        // Make H(R_i)
        let precommitment = R_i.precommit();

        let counterparties = pubkeys
            .iter()
            .map(|pubkey| Counterparty::new(*pubkey))
            .collect();

        (
            PartyAwaitingPrecommitments {
                transcript,
                multikey,
                x_i,
                r_i,
                R_i,
                counterparties,
            },
            precommitment,
        )
    }
}

impl<'t> PartyAwaitingPrecommitments<'t> {
    /// Provide nonce precommitments to the party and transition to the next round.
    pub fn receive_precommitments(
        self,
        nonce_precommitments: Vec<NoncePrecommitment>,
    ) -> (PartyAwaitingCommitments<'t>, NonceCommitment) {
        let counterparties = self
            .counterparties
            .into_iter()
            .zip(nonce_precommitments)
            .map(|(counterparty, precommitment)| counterparty.precommit_nonce(precommitment))
            .collect();
        // Store received nonce precommitments in next state
        (
            PartyAwaitingCommitments {
                transcript: self.transcript,
                multikey: self.multikey,
                x_i: self.x_i,
                r_i: self.r_i,
                counterparties,
            },
            self.R_i,
        )
    }
}

impl<'t> PartyAwaitingCommitments<'t> {
    /// Provide nonce commitments to the party and transition to the next round
    /// if they match the precommitments.
    pub fn receive_commitments(
        self,
        nonce_commitments: Vec<NonceCommitment>,
    ) -> Result<(PartyAwaitingShares, Scalar), MusigError> {
        // Make R = sum_i(R_i). nonce_commitments = R_i from all the parties.
        let R = NonceCommitment::sum(&nonce_commitments);

        // Check stored precommitments against received commitments
        let counterparties = self
            .counterparties
            .into_iter()
            .zip(nonce_commitments)
            .map(|(counterparty, commitment)| counterparty.commit_nonce(commitment))
            .collect::<Result<_, _>>()?;

        // Make c = H(X, R, m)
        // The message `m` has already been fed into the transcript.
        let c = {
            self.transcript
                .commit_point(b"X", &self.multikey.aggregated_key().0);
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
                c,
                R,
                counterparties,
            },
            s_i,
        ))
    }
}

impl PartyAwaitingShares {
    /// Assemble trusted signature shares (e.g. when all keys owned by one signer)
    pub fn receive_trusted_shares(self, shares: Vec<Scalar>) -> Signature {
        // s = sum(s_i), s_i = shares[i]
        let s: Scalar = shares.into_iter().map(|share| share).sum();
        Signature {
            s,
            R: self.R.compress(),
        }
    }

    /// Verify and assemble signature shares.
    pub fn receive_shares(self, shares: Vec<Scalar>) -> Result<Signature, MusigError> {
        // Move out self's fields because `self.c` inside `map`'s closure would
        // lead to capturing `self` by reference, while we want
        // to move `self.counterparties` out of it.
        // See also RFC2229: https://github.com/rust-lang/rfcs/pull/2229
        let challenge = self.c;
        let multikey = &self.multikey;

        // Check that all shares are valid. If so, create s from them.
        // s = sum(s_i), s_i = shares[i]
        let s = self
            .counterparties
            .into_iter()
            .zip(shares)
            .map(|(counterparty, share)| counterparty.sign(share, challenge, multikey))
            .sum::<Result<_, _>>()?;

        Ok(Signature {
            s,
            R: self.R.compress(),
        })
    }
}
