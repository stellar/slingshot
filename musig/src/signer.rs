use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use rand;

use starsig::{Signature, TranscriptProtocol};

use super::counterparty::*;
use super::{MusigContext, MusigError};

/// Entry point to multi-party signing protocol.
pub struct Signer {}

/// State of the party when awaiting nonce precommitments from other parties.
pub struct SignerAwaitingPrecommitments<'t, C: MusigContext> {
    transcript: &'t mut Transcript,
    context: C,
    position: usize,
    x_i: Scalar,
    r_i: Scalar,
    R_i: NonceCommitment,
    counterparties: Vec<Counterparty>,
}

/// State of the party when awaiting nonce commitments from other parties.
pub struct SignerAwaitingCommitments<'t, C: MusigContext> {
    transcript: &'t mut Transcript,
    context: C,
    position: usize,
    x_i: Scalar,
    r_i: Scalar,
    counterparties: Vec<CounterpartyPrecommitted>,
}

/// State of the party when awaiting signature shares from other parties.
pub struct SignerAwaitingShares<C: MusigContext> {
    transcript: Transcript,
    context: C,
    R: RistrettoPoint,
    counterparties: Vec<CounterpartyCommitted>,
}

impl Signer {
    /// Create new signing party for a given transcript.
    pub fn new<'t, C: MusigContext>(
        // The message `m` has already been fed into the transcript
        transcript: &'t mut Transcript,
        position: usize,
        x_i: Scalar,
        context: C,
    ) -> (SignerAwaitingPrecommitments<'t, C>, NoncePrecommitment) {
        let mut rng = transcript
            .build_rng()
            .rekey_with_witness_bytes(b"x_i", &x_i.to_bytes())
            .finalize(&mut rand::thread_rng());

        // Generate ephemeral keypair (r_i, R_i). r_i is a random nonce.
        let r_i = Scalar::random(&mut rng);
        // R_i = generator * r_i
        let R_i = NonceCommitment::new(RISTRETTO_BASEPOINT_POINT * r_i);
        // Make H(R_i)
        let precommitment = R_i.precommit();

        let counterparties = (0..context.len())
            .map(|i| Counterparty::new(i, context.key(i)))
            .collect();

        (
            SignerAwaitingPrecommitments {
                transcript,
                context,
                position,
                x_i,
                r_i,
                R_i,
                counterparties,
            },
            precommitment,
        )
    }
}

impl<'t, C: MusigContext> SignerAwaitingPrecommitments<'t, C> {
    /// Provide nonce precommitments to the party and transition to the next round.
    pub fn receive_precommitments(
        self,
        nonce_precommitments: Vec<NoncePrecommitment>,
    ) -> (SignerAwaitingCommitments<'t, C>, NonceCommitment) {
        let counterparties = self
            .counterparties
            .into_iter()
            .zip(nonce_precommitments)
            .map(|(counterparty, precommitment)| counterparty.precommit_nonce(precommitment))
            .collect();
        // Store received nonce precommitments in next state
        (
            SignerAwaitingCommitments {
                transcript: self.transcript,
                context: self.context,
                position: self.position,
                x_i: self.x_i,
                r_i: self.r_i,
                counterparties,
            },
            self.R_i,
        )
    }
}

impl<'t, C: MusigContext> SignerAwaitingCommitments<'t, C> {
    /// Provide nonce commitments to the party and transition to the next round
    /// if they match the precommitments.
    pub fn receive_commitments(
        mut self,
        nonce_commitments: Vec<NonceCommitment>,
    ) -> Result<(SignerAwaitingShares<C>, Scalar), MusigError> {
        // Make R = sum_i(R_i). nonce_commitments = R_i from all the parties.
        let R = NonceCommitment::sum(&nonce_commitments);

        // Check stored precommitments against received commitments
        let counterparties = self
            .counterparties
            .into_iter()
            .zip(nonce_commitments)
            .map(|(counterparty, commitment)| counterparty.verify_nonce(commitment))
            .collect::<Result<_, _>>()?;

        // Commit the context with label "X", and commit the nonce sum with label "R"
        self.context.commit(&mut self.transcript);
        self.transcript.append_point(b"R", &R.compress());

        // Make a copy of the transcript for extracting the challenge c_i.
        // This way, we can pass self.transcript to the next state so the next state
        // can also extract the same challenge (for checking signature share validity).
        let transcript = self.transcript.clone();

        // Get per-party challenge c_i
        let c_i = self.context.challenge(self.position, &mut self.transcript);

        // Generate share: s_i = r_i + c * a_i * x_i
        let s_i = self.r_i + c_i * self.x_i;

        // Store received nonce commitments in next state
        Ok((
            SignerAwaitingShares {
                transcript,
                context: self.context,
                R,
                counterparties,
            },
            s_i,
        ))
    }
}

impl<'t, C: MusigContext> SignerAwaitingShares<C> {
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
        let context = &self.context;
        let transcript = self.transcript;

        // Check that all shares are valid and sum them up.
        let s = self
            .counterparties
            .into_iter()
            .zip(shares)
            .map(|(counterparty, share)| counterparty.verify_share(share, context, &transcript))
            .sum::<Result<_, _>>()?;

        Ok(Signature {
            s,
            R: self.R.compress(),
        })
    }
}
