//! ```ascii
//! ┌──────────────────────────────────────────────────────────────────────────────────────┐
//! │    _______ __   __ ______  _______  ______ _______ _     _ _______ _     _ _______   │
//! │    |         \_/   |_____] |______ |_____/ |______ |_____| |_____| |____/  |______   │
//! │    |_____     |    |_____] |______ |    \_ ______| |     | |     | |    \_ |______   │
//! │                                                                                      │
//! └──────────────────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # C Y B E R S H A K E
//!
//! Yet Another Handshake Protocol for p2p sessions.
//!
//! You start with a local private key, remote public key (optional),
//! and a pair of `AsyncRead` and `AsyncWrite` interfaces.
//!
//! The protocol performs mutual authentication and, if it succeeded,
//! returns a pair of wrappers around these interfaces,
//! that keep track of the encryption keys.
//!
//! ## Features
//!
//! * **Symmetric and low-latency.** Handshake is performed by both ends simultaneously.
//! * **Mutual-authentication.** Each party receives other's long-term public key by the end of handshake.
//! * **Key blinding.** Long-term identity keys are never transmitted in the clear.
//! * **Foward secrecy.** Keys are rotated on each sent message.
//! * **Robust encryption.** cipher AES-SIV-PMAC-128 provides high speed and resistance to nonce-misuse.
//!
//! ## TODO
//!
//! * Streaming API to send larger portions of data wrapped in async streams.
//! * Add custom header to be sent in the first encrypted frame:
//!   users can put the protocol version there, certificate info etc.

use byteorder::{ByteOrder, LittleEndian};
use core::marker::Unpin;
use miscreant::{generic_array::GenericArray, Aes128PmacSiv};
use rand_core::{CryptoRng, RngCore};

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::VartimeMultiscalarMul;
use merlin::Transcript; // TODO: change for raw Strobe.

use tokio::io;
use tokio::prelude::*;

use serde::{Deserialize, Serialize};

/// The current version of the protocol is 0.
/// In the future we may add more versions, version bits or whatever.
const ONLY_SUPPORTED_VERSION: u64 = 0;

/// Private key for encrypting and authenticating connection.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct PrivateKey {
    secret: Scalar,
    pubkey: PublicKey,
}

/// Public key for authenticating connection.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct PublicKey {
    point: CompressedRistretto,
}

/// An endpoint for sending messages to remote party.
/// All messages are ordered and encryption key is ratcheted after each sent message.
pub struct Outgoing<W: io::AsyncWrite + Unpin> {
    writer: W,
    seq: u64,
    kdf: Transcript,
}

/// An endpoint for receiving messages from a remote party.
/// All messages are ordered and encryption key is ratcheted after each received message.
/// Recipient's incoming.seq corresponds to the sender's outgoing.seq.
pub struct Incoming<R: io::AsyncRead + Unpin> {
    reader: R,
    seq: u64,
    kdf: Transcript,
    message_maxlen: usize,
}

/// Kinds of failures that may happen during the handshake.
#[derive(Debug)]
pub enum Error {
    /// I/O error (connection closed, not enough data, etc).
    IoError(io::Error),

    /// Point failed to decode correctly.
    ProtocolError,

    /// Received message is declared too large - not reading.
    MessageTooLong(usize),

    /// Version used by remote peer is not supported.
    UnsupportedVersion,
}

/// Performs the key exchange with a remote end using byte-oriented read- and write- interfaces
/// (e.g. TcpSocket halves).
/// Returns the identity key of the remote peer, along with read- and write- interfaces
/// that perform encryption and authentication behind the scenes.
/// If you need to verify the identity per local policy or certificates, use the returned public key.
pub async fn cybershake<R, W, RNG>(
    local_identity: &PrivateKey,
    mut reader: R,
    mut writer: W,
    message_maxlen: usize,
    rng: &mut RNG,
) -> Result<(PublicKey, Outgoing<W>, Incoming<R>), Error>
where
    R: io::AsyncRead + Unpin,
    W: io::AsyncWrite + Unpin,
    RNG: RngCore + CryptoRng,
{
    // We are going to need an additional ephemeral D-H key,
    // and a salt for blinding the reusable identity key.

    let mut keygen_rng = Transcript::new(b"Cybershake.randomness")
        .build_rng()
        .rekey_with_witness_bytes(b"local_privkey", local_identity.as_secret_bytes())
        .finalize(rng);

    let local_ephemeral = PrivateKey::from(Scalar::random(&mut keygen_rng));

    const SALT_LEN: usize = 16;
    let mut local_salt = [0u8; SALT_LEN];
    keygen_rng.fill_bytes(&mut local_salt[..]);
    let local_blinded_identity = local_identity.blind(&local_salt);

    // Now we send our first, unencrypted, message:
    //
    // [version] [blinded local identity pubkey] [local ephemeral pubkey]
    // u64-le     32 bytes                        32 bytes
    writer
        .write(&encode_u64le(ONLY_SUPPORTED_VERSION)[..])
        .await?;
    writer
        .write(local_blinded_identity.pubkey.as_bytes())
        .await?;
    writer.write(local_ephemeral.pubkey.as_bytes()).await?;
    writer.flush().await?;

    // Receive the similar message from the other end (that was sent simultaneously).
    let mut remote_version_buf = [0u8; 8];
    reader.read_exact(&mut remote_version_buf[..]).await?;
    let remote_version = LittleEndian::read_u64(&remote_version_buf);
    if remote_version != ONLY_SUPPORTED_VERSION {
        return Err(Error::UnsupportedVersion);
    }
    let remote_blinded_identity = PublicKey::read_from(&mut reader).await?;
    let remote_ephemeral = PublicKey::read_from(&mut reader).await?;

    // Now, perform a triple Diffie-Hellman shared key generation.
    let t = cybershake_x3dh(
        &local_blinded_identity,
        &local_ephemeral,
        &remote_blinded_identity,
        &remote_ephemeral,
    )?;

    // We will have two independent derivations of the shared key:
    // one for the outgoing messages, and another one for incoming messages.
    let mut kdf_outgoing = t.clone();
    let mut kdf_incoming = t;
    kdf_outgoing.append_message(b"src", local_blinded_identity.pubkey.as_bytes());
    kdf_incoming.append_message(b"src", remote_blinded_identity.as_bytes());

    // Now we prepare endpoints for reading and writing messages,
    // but don't give them to the user until we authenticate the connection.
    let mut outgoing = Outgoing {
        writer,
        seq: 0,
        kdf: kdf_outgoing,
    };
    let mut incoming = Incoming {
        reader,
        seq: 0,
        kdf: kdf_incoming,
        message_maxlen,
    };

    // In order to authenticate the session, we send our first encrypted message
    // in which we show the salt and the root key.
    // If the transmission was successful (authenticated decryption succeeded),
    // we check the blinded key and then let user continue using the session.

    // Prepare and send the message: salt and local identity pubkey.
    let msg_len = SALT_LEN + 32;
    let mut local_salt_and_id = Vec::<u8>::with_capacity(msg_len);
    local_salt_and_id.extend_from_slice(&local_salt[..]);
    local_salt_and_id.extend_from_slice(local_identity.pubkey.as_bytes());
    outgoing.send_message(&local_salt_and_id).await?;

    // Receive the message from another end: their salt and their identity pubkey.
    let remote_salt_and_id = incoming.receive_message().await?;
    if remote_salt_and_id.len() != msg_len {
        return Err(Error::ProtocolError);
    }
    let mut remote_salt = [0u8; SALT_LEN];
    remote_salt[..].copy_from_slice(&remote_salt_and_id[0..SALT_LEN]);
    let received_remote_identity =
        PublicKey::read_from(&mut &remote_salt_and_id[SALT_LEN..]).await?;

    // Blinded key is also a secure commitment to the underlying key.
    // Here we check that the remote party has sent us the correct identity key
    // matching the blinded key they used for X3DH.
    let received_remote_id_blinded = received_remote_identity
        .blind(&remote_salt)
        .ok_or(Error::ProtocolError)?;
    if received_remote_id_blinded != remote_blinded_identity {
        return Err(Error::ProtocolError);
    }

    Ok((received_remote_identity, outgoing, incoming))
}

// TODO: implement AsyncWrite for this, buffering the data and encrypting on flush or on each N-byte chunk.
impl<W: AsyncWrite + Unpin> Outgoing<W> {
    pub async fn send_message(&mut self, msg: &[u8]) -> Result<(), Error> {
        self.kdf.append_u64(b"seq", self.seq);
        let mut key = [0u8; 32];
        self.kdf.challenge_bytes(b"key", &mut key);

        let ad = encode_u64le(self.seq);

        let ciphertext = Aes128PmacSiv::new(GenericArray::clone_from_slice(&key))
            .encrypt(&[&ad], msg)
            .map_err(|_| Error::ProtocolError)?;

        self.seq += 1;

        // Write the length prefix and the ciphertext.
        self.writer
            .write(&encode_u64le(ciphertext.len() as u64)[..])
            .await?;
        self.writer.write(&ciphertext[..]).await?;
        self.writer.flush().await?;
        Ok(())
    }
}

impl<W: AsyncRead + Unpin> Incoming<W> {
    pub async fn receive_message(&mut self) -> Result<Vec<u8>, Error> {
        let mut lenbuf = [0u8; 8];
        let seq = self.seq;
        self.seq += 1;
        self.reader.read_exact(&mut lenbuf[..]).await?;
        let len = LittleEndian::read_u64(&lenbuf) as usize;

        // length must include IV prefix (16 bytes)
        if len < 16 {
            return Err(Error::ProtocolError);
        }
        // Check the message length and fail before changing any of the remaining state.
        if (len - 16) > self.message_maxlen {
            return Err(Error::MessageTooLong(len - 16));
        }

        let mut ciphertext = Vec::with_capacity(len);
        ciphertext.resize(len, 0u8);
        self.reader.read_exact(&mut ciphertext[..]).await?;

        self.kdf.append_u64(b"seq", seq);
        let mut key = [0u8; 32];
        self.kdf.challenge_bytes(b"key", &mut key);

        let ad = encode_u64le(seq);

        let plaintext = Aes128PmacSiv::new(GenericArray::clone_from_slice(&key))
            .decrypt(&[&ad], &ciphertext)
            .map_err(|_| Error::ProtocolError)?;

        Ok(plaintext)
    }

    /// Converts to the Stream
    pub fn into_stream(self) -> impl futures::stream::Stream<Item = Result<Vec<u8>, Error>> {
        futures::stream::unfold(self, |mut src| {
            async move {
                let res = src.receive_message().await;
                Some((res, src))
            }
        })
    }
}

/// This is a YOLO variant of Signal's X3DH that's aimed at improved performance:
/// instead of doing independent computation of three DH instances,
/// compressing them, and feeding independently into a hash,
/// we add them all together, separated by a Fiat-Shamir challenges (x, y):
///
/// X3DH = Hash(DH(eph1, eph2) + x * DH(id1, eph2) + y * DH(id2, eph1))
///
/// This allows reusing doublings across all three instances,
/// and do a single point compression in the end instead of three.
///
/// To get consistent results on both ends, we reorder keys so the "first" party
/// is the one with the lower compressed identity public key.
fn cybershake_x3dh(
    id1: &PrivateKey,
    eph1: &PrivateKey,
    id2: &PublicKey,
    eph2: &PublicKey,
) -> Result<Transcript, Error> {
    let mut t = Transcript::new(b"Cybershake.X3DH");
    let keep_order = id1.pubkey.as_bytes() < id2.as_bytes();
    {
        let (id1, eph1, id2, eph2) = if keep_order {
            (&id1.pubkey, &eph1.pubkey, id2, eph2)
        } else {
            (id2, eph2, &id1.pubkey, &eph1.pubkey)
        };
        t.append_message(b"id1", id1.as_bytes());
        t.append_message(b"id2", id2.as_bytes());
        t.append_message(b"eph1", eph1.as_bytes());
        t.append_message(b"eph2", eph2.as_bytes());
    }

    let x = challenge_scalar(b"x", &mut t);
    let y = challenge_scalar(b"y", &mut t);

    let (x, y) = if keep_order { (x, y) } else { (y, x) };

    use core::iter;
    let shared_secret = RistrettoPoint::optional_multiscalar_mul(
        iter::once(&(eph1.as_scalar() + (x * id1.as_scalar())))
            .chain(iter::once(&(eph1.as_scalar() * y))),
        iter::once(eph2.as_point().decompress()).chain(iter::once(id2.as_point().decompress())),
    )
    .ok_or(Error::ProtocolError)?;

    t.append_message(b"x3dh", shared_secret.compress().as_bytes());

    Ok(t)
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Error::IoError(error)
    }
}

impl From<Scalar> for PrivateKey {
    fn from(secret: Scalar) -> Self {
        PrivateKey {
            secret,
            pubkey: PublicKey::from(secret * RISTRETTO_BASEPOINT_POINT),
        }
    }
}

impl From<CompressedRistretto> for PublicKey {
    fn from(point: CompressedRistretto) -> Self {
        PublicKey { point }
    }
}

impl From<RistrettoPoint> for PublicKey {
    fn from(point: RistrettoPoint) -> Self {
        PublicKey::from(point.compress())
    }
}

impl PrivateKey {
    /// Converts the private key to an underlying Ristretto scalar.
    pub fn as_scalar(&self) -> &Scalar {
        &self.secret
    }

    /// Converts the private key to its binary encoding.
    pub fn as_secret_bytes(&self) -> &[u8] {
        &self.secret.as_bytes()[..]
    }

    /// Converts the private key to its public counterpart.
    pub fn to_public_key(&self) -> PublicKey {
        self.pubkey
    }

    /// Blinds the private key.
    fn blind(&self, salt: &[u8; 16]) -> Self {
        PrivateKey::from(self.secret + keyblinding_factor(&self.pubkey.point, salt))
    }
}

impl PublicKey {
    /// Converts the public key to an underlying compressed Ristretto point.
    pub fn as_point(&self) -> &CompressedRistretto {
        &self.point
    }

    /// Converts the public key to its binary encoding.
    pub fn as_bytes(&self) -> &[u8] {
        &self.point.as_bytes()[..]
    }

    /// Blinds the public key.
    fn blind(&self, salt: &[u8; 16]) -> Option<Self> {
        self.point.decompress().map(|p| {
            PublicKey::from(p + keyblinding_factor(&self.point, salt) * RISTRETTO_BASEPOINT_POINT)
        })
    }

    /// Reads pubkey from a reader.
    async fn read_from<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Self, Error> {
        let mut buf = [0u8; 32];
        reader.read_exact(&mut buf[..]).await?;
        Ok(Self::from(CompressedRistretto(buf)))
    }
}

fn keyblinding_factor(pubkey: &CompressedRistretto, salt: &[u8; 16]) -> Scalar {
    let mut t = Transcript::new(b"Cybershake.keyblinding");
    t.append_message(b"key", pubkey.as_bytes());
    t.append_message(b"salt", &salt[..]);
    challenge_scalar(b"factor", &mut t)
}

fn challenge_scalar(label: &'static [u8], transcript: &mut Transcript) -> Scalar {
    let mut buf = [0u8; 64];
    transcript.challenge_bytes(label, &mut buf);
    Scalar::from_bytes_mod_order_wide(&buf)
}

fn encode_u64le(i: u64) -> [u8; 8] {
    let mut buf = [0u8; 8];
    LittleEndian::write_u64(&mut buf, i);
    buf
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;
    use tokio::net::{TcpStream, TcpListener};

    #[tokio::test]
    async fn test() {
        let bob_private_key = PrivateKey::from(Scalar::from_bits([1u8; 32]));
        let alice_private_key = PrivateKey::from(Scalar::from_bits([2u8; 32]));
        let mut alice_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut bob_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();

        let alice_writer = TcpStream::connect(bob_listener.local_addr().unwrap()).await.unwrap();
        let bob_writer = TcpStream::connect(alice_listener.local_addr().unwrap()).await.unwrap();
        let (alice_reader, _) = alice_listener.accept().await.unwrap();
        let (bob_reader, _) = bob_listener.accept().await.unwrap();

        let mut alice_rng = thread_rng();
        let mut bob_rng = thread_rng();

        let (_, mut bob_out, mut alice_inc)  = cybershake(&alice_private_key, alice_reader, bob_writer, 64, &mut alice_rng).await.unwrap();
        let (_, mut alice_out, mut bob_inc)  = cybershake(&bob_private_key, bob_reader, alice_writer, 64, &mut bob_rng).await.unwrap();

        let alice_message = "Hello, Bob";
        let alice_message_bytes: Vec<u8> = alice_message.bytes().collect();
        alice_out.send_message(&alice_message_bytes).await.unwrap();
        let bob_rec = bob_inc.receive_message().await.unwrap();
        assert_eq!(alice_message, String::from_utf8(bob_rec).unwrap());

        let bob_message = "Hello, Alice";
        let bob_message_bytes: Vec<u8> = bob_message.bytes().collect();
        bob_out.send_message(&bob_message_bytes).await.unwrap();
        let alice_rec = alice_inc.receive_message().await.unwrap();
        assert_eq!(bob_message, String::from_utf8(alice_rec).unwrap());
    }
}
