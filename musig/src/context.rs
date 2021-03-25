use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use starsig::{SigningKey, TranscriptProtocol as StarsigTranscriptProtocol, VerificationKey};

use super::{MusigError, TranscriptProtocol};

/// The context for signing - can either be a Multikey or Multimessage context.
pub trait MusigContext {
    /// Takes a mutable transcript, and commits the internal context to the transcript.
    fn commit(&self, transcript: &mut Transcript);

    /// Takes an index of a public key and mutable transcript,
    /// and returns the suitable challenge for that public key.
    fn challenge(&self, index: usize, transcript: &mut Transcript) -> Scalar;

    /// Length of the number of pubkeys in the context
    fn len(&self) -> usize;

    /// Returns the pubkey for the index i
    fn key(&self, index: usize) -> VerificationKey;
}

/// MuSig aggregated key context
#[derive(Clone)]
pub struct Multikey {
    prf: Option<Transcript>,
    aggregated_key: VerificationKey,
    public_keys: Vec<VerificationKey>,
}

/// MuSig multimessage context
#[derive(Clone)]
pub struct Multimessage<M: AsRef<[u8]>> {
    pairs: Vec<(VerificationKey, M)>,
}

impl Multikey {
    /// Constructs a new MuSig multikey aggregating the pubkeys.
    pub fn new(pubkeys: Vec<VerificationKey>) -> Result<Self, MusigError> {
        match pubkeys.len() {
            0 => {
                return Err(MusigError::BadArguments);
            }
            1 => {
                // Special case: single key can be wrapped in a Multikey type
                // without a delinearization factor applied.
                return Ok(Multikey {
                    prf: None,
                    aggregated_key: pubkeys[0],
                    public_keys: pubkeys,
                });
            }
            _ => {}
        }

        // Create transcript for Multikey
        let mut prf = Transcript::new(b"Musig.aggregated-key");
        prf.append_u64(b"n", pubkeys.len() as u64);

        // Commit pubkeys into the transcript
        // <L> = H(X_1 || X_2 || ... || X_n)
        for X in &pubkeys {
            prf.append_point(b"X", X.as_point());
        }

        // aggregated_key = sum_i ( a_i * X_i )
        let mut aggregated_key = RistrettoPoint::default();
        for (i, X) in pubkeys.iter().enumerate() {
            let a = Multikey::compute_factor(&prf, i);
            let X = X.as_point().decompress().ok_or(MusigError::InvalidPoint)?;
            aggregated_key = aggregated_key + a * X;
        }

        Ok(Multikey {
            prf: Some(prf),
            aggregated_key: VerificationKey::from(aggregated_key),
            public_keys: pubkeys,
        })
    }

    /// Returns `a_i` factor for component key in aggregated key.
    /// a_i = H(<L>, X_i). The list of pubkeys, <L>, has already been committed to the transcript.
    fn compute_factor(prf: &Transcript, i: usize) -> Scalar {
        let mut a_i_prf = prf.clone();
        a_i_prf.append_u64(b"i", i as u64);
        a_i_prf.challenge_scalar(b"a_i")
    }

    /// Returns VerificationKey representation of aggregated key.
    pub fn aggregated_key(&self) -> VerificationKey {
        self.aggregated_key
    }

    /// Constructs a signing multikey aggregating the individual signing keys.
    /// This function is not used in real applications because parties do not share keys,
    /// but comes handy in unit tests.
    pub fn aggregated_signing_key(privkeys: &[SigningKey]) -> SigningKey {
        match privkeys.len() {
            0 => {
                return Scalar::zero();
            }
            1 => {
                // Special case: single key is passed as-is
                return privkeys[0];
            }
            _ => {}
        }

        // Create transcript for Multikey
        let mut prf = Transcript::new(b"Musig.aggregated-key");
        prf.append_u64(b"n", privkeys.len() as u64);

        // Commit pubkeys into the transcript
        // <L> = H(X_1 || X_2 || ... || X_n)
        for x in privkeys.iter() {
            let X = VerificationKey::from_secret(x);
            prf.append_point(b"X", X.as_point());
        }

        // aggregated_key = sum_i ( a_i * X_i )
        let mut aggregated_key = Scalar::zero();
        for (i, x) in privkeys.iter().enumerate() {
            let a = Multikey::compute_factor(&prf, i);
            aggregated_key = aggregated_key + a * x;
        }

        aggregated_key
    }
}

impl MusigContext for Multikey {
    fn commit(&self, transcript: &mut Transcript) {
        transcript.starsig_domain_sep();
        transcript.append_point(b"X", self.aggregated_key.as_point());
    }

    fn challenge(&self, i: usize, transcript: &mut Transcript) -> Scalar {
        // Make c = H(X, R, m)
        // The message `m`, nonce commitment `R`, and aggregated key `X`
        // have already been fed into the transcript.
        let c = transcript.challenge_scalar(b"c");

        // Make a_i, the per-party factor. a_i = H(<L>, X_i).
        // The list of pubkeys, <L>, has already been committed to self.transcript.
        let a_i = match &self.prf {
            Some(t) => Multikey::compute_factor(&t, i),
            None => Scalar::one(),
        };

        c * a_i
    }

    fn len(&self) -> usize {
        self.public_keys.len()
    }

    fn key(&self, index: usize) -> VerificationKey {
        self.public_keys[index]
    }
}

impl<M: AsRef<[u8]>> Multimessage<M> {
    /// Constructs a new multimessage context
    pub fn new(pairs: Vec<(VerificationKey, M)>) -> Self {
        Self { pairs }
    }
}

impl<M: AsRef<[u8]>> MusigContext for Multimessage<M> {
    fn commit(&self, transcript: &mut Transcript) {
        transcript.musig_multimessage_domain_sep(self.pairs.len());
        for (key, msg) in &self.pairs {
            transcript.append_point(b"X", key.as_point());
            transcript.append_message(b"m", msg.as_ref());
        }
    }

    fn challenge(&self, i: usize, transcript: &mut Transcript) -> Scalar {
        let mut transcript_i = transcript.clone();
        transcript_i.append_u64(b"i", i as u64);
        transcript_i.challenge_scalar(b"c")

        // TBD: Do we want to add a domain separator to the transcript?
    }

    fn len(&self) -> usize {
        self.pairs.len()
    }

    fn key(&self, index: usize) -> VerificationKey {
        self.pairs[index].0
    }
}
