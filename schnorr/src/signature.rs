use core::borrow::Borrow;
use core::iter;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::{IsIdentity, VartimeMultiscalarMul};
use merlin::Transcript;
use serde::{de::Deserializer, de::Visitor, ser::Serializer, Deserialize, Serialize};

use super::errors::SchnorrError;
use super::key::VerificationKey;
use super::transcript::TranscriptProtocol;

/// A Schnorr signature.
#[derive(Debug, Clone)]
pub struct Signature {
    /// Signature using nonce, message, and private key
    pub s: Scalar,
    /// Nonce commitment
    pub R: CompressedRistretto,
}

/// Trait for a batch verification of signatures.
pub trait BatchVerification {
    /// Adds scalar for multiplying by a base point and pairs of dynamic scalars/points.
    /// The API admits variable-length iterators of scalars/points
    /// for compatibility with multi-key signatures (see Musig).
    fn append<I, J>(&mut self, basepoint_scalar: I::Item, dynamic_factors: I, dynamic_points: J)
    where
        I: IntoIterator<Item = Scalar>,
        I::Item: Borrow<Scalar>,
        J: IntoIterator<Item = Option<RistrettoPoint>>;
}

impl Signature {
    /// Creates a signature for a single private key and single message
    pub fn sign(transcript: &mut Transcript, privkey: Scalar) -> Signature {
        let X = VerificationKey::from_secret(&privkey); // pubkey

        let mut rng = transcript
            .build_rng()
            .rekey_with_witness_bytes(b"x", &privkey.to_bytes())
            .finalize(&mut rand::thread_rng());

        // Generate ephemeral keypair (r, R). r is a random nonce.
        let r = Scalar::random(&mut rng);
        // R = generator * r
        let R = (RISTRETTO_BASEPOINT_POINT * r).compress();

        let c = {
            transcript.schnorr_sig_domain_sep();
            transcript.commit_point(b"X", X.as_compressed());
            transcript.commit_point(b"R", &R);
            transcript.challenge_scalar(b"c")
        };

        let s = r + c * privkey;

        Signature { s, R }
    }

    /// Verifies the signature against a given verification key.
    /// Transcript should be in the same state as it was during the `sign` call
    /// that created the signature.
    pub fn verify(
        &self,
        transcript: &mut Transcript,
        X: VerificationKey,
    ) -> Result<(), SchnorrError> {
        struct VerifyOne {
            result: Result<(), SchnorrError>,
        }

        impl BatchVerification for VerifyOne {
            fn append<I, J>(
                &mut self,
                basepoint_scalar: I::Item,
                dynamic_factors: I,
                dynamic_points: J,
            ) where
                I: IntoIterator,
                I::Item: Borrow<Scalar>,
                J: IntoIterator<Item = Option<RistrettoPoint>>,
            {
                self.result = RistrettoPoint::optional_multiscalar_mul(
                    iter::once(basepoint_scalar).chain(dynamic_factors),
                    iter::once(Some(RISTRETTO_BASEPOINT_POINT)).chain(dynamic_points),
                )
                .ok_or(SchnorrError::InvalidSignature)
                .and_then(|result| {
                    if result.is_identity() {
                        Ok(())
                    } else {
                        Err(SchnorrError::InvalidSignature)
                    }
                })
            }
        }

        let mut verifier = VerifyOne {
            result: Err(SchnorrError::InvalidSignature),
        };
        self.verify_batched(transcript, X, &mut verifier);
        return verifier.result;
    }

    /// Verifies the signature against a given verification key in a batch.
    /// Transcript should be in the same state as it was during the `sign` call
    /// that created the signature.
    pub fn verify_batched(
        &self,
        transcript: &mut Transcript,
        X: VerificationKey,
        batch: &mut impl BatchVerification,
    ) {
        // Make c = H(X, R, m)
        // The message has already been fed into the transcript
        let c = {
            transcript.schnorr_sig_domain_sep();
            transcript.commit_point(b"X", X.as_compressed());
            transcript.commit_point(b"R", &self.R);
            transcript.challenge_scalar(b"c")
        };

        // Form the final linear combination:
        // `s * G = R + c * X`
        //      ->
        // `0 == (-s * G) + (1 * R) + (c * X)`
        batch.append(
            -self.s,
            iter::once(Scalar::one()).chain(iter::once(c)),
            iter::once(self.R.decompress()).chain(iter::once(Some(X.into_point()))),
        );
    }

    /// Decodes a signature from a 64-byte slice.
    pub fn from_bytes(sig: &[u8]) -> Result<Self, SchnorrError> {
        if sig.len() != 64 {
            return Err(SchnorrError::InvalidSignature);
        }
        let mut Rbuf = [0u8; 32];
        let mut sbuf = [0u8; 32];
        Rbuf[..].copy_from_slice(&sig[..32]);
        sbuf[..].copy_from_slice(&sig[32..]);
        Ok(Signature {
            R: CompressedRistretto(Rbuf),
            s: Scalar::from_canonical_bytes(sbuf).ok_or(SchnorrError::InvalidSignature)?,
        })
    }

    /// Encodes the signature as a 64-byte array.
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut buf = [0u8; 64];
        buf[..32].copy_from_slice(self.R.as_bytes());
        buf[32..].copy_from_slice(self.s.as_bytes());
        buf
    }
}

// TBD: serialize in hex in case of a human-readable serializer
impl Serialize for Signature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&self.to_bytes()[..])
    }
}
impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct SigVisitor;

        impl<'de> Visitor<'de> for SigVisitor {
            type Value = Signature;

            fn expecting(&self, formatter: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                formatter.write_str("a valid schnorr signature")
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Signature, E>
            where
                E: serde::de::Error,
            {
                Signature::from_bytes(v).map_err(serde::de::Error::custom)
            }
        }

        deserializer.deserialize_bytes(SigVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify() {
        let privkey = Scalar::from(1u64);
        let sig = Signature::sign(&mut Transcript::new(b"example transcript"), privkey);

        let X = VerificationKey::from_secret(&privkey);

        assert!(sig
            .verify(&mut Transcript::new(b"example transcript"), X)
            .is_ok());

        let priv_bad = Scalar::from(2u64);
        let X_bad = VerificationKey::from_secret(&priv_bad);
        assert!(sig
            .verify(&mut Transcript::new(b"example transcript"), X_bad)
            .is_err());
        assert!(sig
            .verify(&mut Transcript::new(b"invalid transcript"), X)
            .is_err());
    }
}
