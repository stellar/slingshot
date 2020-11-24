//! Address protocol implementation
//!
//! Address is a 64-byte string that allows anyone to deliver payment w/o exchanging Receivers.
//!
//! Sending funds this way incurs a bit of overhead: extra `data` entry in the transaction,
//! with 73 bytes of data. Last byte is used as a distinguisher to help identify the correct payload
//! out of multiple w/o computational overhead in case of multiple send-to-address outputs.
//!
//! Address consists of two 32-byte public keys (ristretto255 points): control key and encryption key.
//! Encryption key is used to encrypt the payment amount and arbitrary additional data,
//! while the control key allows spending the received funds.
use core::iter;

use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::{IsIdentity, VartimeMultiscalarMul};

use merlin::Transcript;
use zkvm::bulletproofs::PedersenGens;
use zkvm::encoding::Encodable;
use zkvm::{ClearValue, Commitment, Predicate, TranscriptProtocol, Value};

use super::Receiver;

use bech32::{self, FromBase32, ToBase32};
use std::{fmt, ops::Deref};

/// Label address that is a valid single-case 1-83 ASCII
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AddressLabel {
    inner: String,
}

impl AddressLabel {
    /// Validates the address label
    pub fn new(label: String) -> Option<Self> {
        if let Ok(_) = bech32::encode(&label, [0x42u8; 1].to_base32()) {
            Some(Self { inner: label })
        } else {
            None
        }
    }

    /// Casts the label to the plain string reference.
    pub fn as_str(&self) -> &str {
        &self.inner
    }
}

impl Deref for AddressLabel {
    type Target = str;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

/// Address to which funds can be sent
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Address {
    label: AddressLabel,
    control_key: CompressedRistretto,
    encryption_key: CompressedRistretto,
    encryption_key_decompressed: RistrettoPoint,
}

impl Address {
    /// Creates a new address with a label.
    pub(crate) fn new(
        label: AddressLabel,
        control_key: CompressedRistretto,
        encryption_key: RistrettoPoint,
    ) -> Self {
        Self {
            label,
            control_key,
            encryption_key: encryption_key.compress(),
            encryption_key_decompressed: encryption_key,
        }
    }

    /// Returns the label of this address.
    pub fn label(&self) -> &AddressLabel {
        &self.label
    }

    /// Returns the control key
    pub fn control_key(&self) -> &CompressedRistretto {
        &self.control_key
    }

    /// Returns the control key wrapped in opaque ZkVM predicate type.
    pub fn predicate(&self) -> Predicate {
        Predicate::Opaque(self.control_key)
    }

    /// Encodes address as bech32 string with the label as its prefix.
    pub fn to_string(&self) -> String {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.control_key.as_bytes()[..]);
        bytes.extend_from_slice(&self.encryption_key.as_bytes()[..]);
        bech32::encode(&self.label, bytes.to_base32())
            .expect("Label should be 1 to 83 characters long, printable ASCII, w/o mixing case.")
    }

    /// Attempts to decode the address from the string representation.
    pub fn from_string(string: &str) -> Option<Self> {
        let (label, data) = bech32::decode(&string).ok()?;
        let buf = Vec::<u8>::from_base32(&data).ok()?;
        if buf.len() != 64 {
            return None;
        }
        let enckey = CompressedRistretto::from_slice(&buf[32..64]).decompress()?;
        Some(Address {
            label: AddressLabel { inner: label },
            control_key: CompressedRistretto::from_slice(&buf[0..32]),
            encryption_key: enckey.compress(),
            encryption_key_decompressed: enckey,
        })
    }

    /// Encrypts cleartext value as a zkvm Value with open commitments.
    /// Also returns the opaque data containing the ciphertext and nonce necessary for full decryption by the recipient.
    /// The opaque data must be embedded in a `data` entry in the txlog, in a random location in the transaction,
    /// in order to prevent evesdroppers from distinguishing send-to-address output from the change output.
    pub fn encrypt<R: RngCore + CryptoRng>(
        &self,
        value: ClearValue,
        mut rng: R,
    ) -> (Receiver, Vec<u8>) {
        let nonce_scalar = Scalar::random(&mut rng);
        let nonce_point = (&nonce_scalar * &RISTRETTO_BASEPOINT_TABLE).compress();
        let dh = (nonce_scalar * self.encryption_key_decompressed).compress();

        let (flv_blinding, qty_blinding, mut flv_pad, mut qty_pad) = self.derive_keys_from_dh(&dh);

        let encrypted_value = Value {
            qty: Commitment::blinded_with_factor(value.qty, qty_blinding),
            flv: Commitment::blinded_with_factor(value.flv, flv_blinding),
        };

        xor_slice(&mut flv_pad[..], &value.flv.as_bytes()[..]);
        xor_slice(&mut qty_pad[..], &value.qty.to_le_bytes()[..]);

        let mut ciphertext = Vec::with_capacity(73);

        ciphertext.extend(&nonce_point.as_bytes()[..]); // 32 bytes of nonce point
        ciphertext.extend(&flv_pad[..]); // 32 bytes CT for the flavor
        ciphertext.extend(&qty_pad[..]); //  8 bytes CT for the qty (u64-LE)
        let tag = self.compute_distinguisher(&ciphertext[0..72], &encrypted_value);
        ciphertext.push(tag); //  1 byte for the distinguisher

        assert!(ciphertext.len() == 73);

        let receiver = Receiver {
            opaque_predicate: self.control_key.clone(),
            value,
            qty_blinding,
            flv_blinding,
        };
        (receiver, ciphertext)
    }

    /// Attempts to decrypt the candidate data for the given Address and encrypted Value.
    /// This can fail if the candidate data does not match the value (in which case another candidate should be tried),
    /// or if it was malformed by the sender.
    /// This method fails fast if the data has incorrect length or an incorrect distinguisher byte,
    /// so you should feel free to call it on every data entry without any additional checks.
    pub fn decrypt<R: RngCore + CryptoRng>(
        &self,
        value: &Value,
        candidate_data: &[u8],
        decryption_key: &Scalar,
        mut rng: R,
    ) -> Option<Receiver> {
        if candidate_data.len() != 73 {
            return None;
        }
        let tag = candidate_data[72];

        if tag != self.compute_distinguisher(&candidate_data[0..72], value) {
            // no const-time comparison used because we are comparing just one byte, and
            // the tag is not used for integrity check, but only for quick rejection of irrelevant data entries.
            return None;
        }
        let ct = candidate_data;
        let nonce_point = CompressedRistretto::from_slice(&ct[0..32]).decompress()?;

        let dh = (decryption_key * nonce_point).compress();

        let (flv_blinding, qty_blinding, mut flv_pad, mut qty_pad) = self.derive_keys_from_dh(&dh);

        xor_slice(&mut flv_pad[..], &ct[32..64]);
        xor_slice(&mut qty_pad[..], &ct[64..72]);

        let flv = Scalar::from_canonical_bytes(flv_pad)?;
        let qty = u64::from_le_bytes(qty_pad);

        // need to verify:
        // 1) V.flv == flv*B + flv_blinding*B_blinding
        // 2) V.qty == qty*B + qty_blinding*B_blinding
        //
        // Compress the statements with a random challenge:
        // V.flv + ch * V.qty == (flv + ch*qty)*B + (flv_bl + ch*qty_bl)*B_blinding
        //
        // Re-order:
        // identity == - V.flv - ch * V.qty + (flv + ch*qty)*B + (flv_bl + ch*qty_bl)*B_blinding
        let challenge = Scalar::random(&mut rng);
        let gens = PedersenGens::default();

        let p = RistrettoPoint::optional_multiscalar_mul(
            iter::once(-Scalar::one())
                .chain(iter::once(-challenge))
                .chain(iter::once(flv + challenge * Scalar::from(qty)))
                .chain(iter::once(flv_blinding + challenge * qty_blinding)),
            iter::once(value.flv.to_point().decompress())
                .chain(iter::once(value.qty.to_point().decompress()))
                .chain(iter::once(Some(gens.B.clone())))
                .chain(iter::once(Some(gens.B_blinding.clone()))),
        )?;

        if !p.is_identity() {
            return None;
        }

        Some(Receiver {
            opaque_predicate: self.control_key,
            value: ClearValue { qty, flv },
            qty_blinding,
            flv_blinding,
        })
    }

    #[inline(always)]
    fn derive_keys_from_dh(&self, dh: &CompressedRistretto) -> (Scalar, Scalar, [u8; 32], [u8; 8]) {
        let mut t = Transcript::new(b"ZkVM.address.encrypt");
        t.append_message(b"prefix", self.label.as_bytes());
        t.append_message(b"control_key", &self.control_key.as_bytes()[..]);
        t.append_message(b"dh", &dh.as_bytes()[..]);
        let flv_blinding = t.challenge_scalar(b"flv_blinding");
        let qty_blinding = t.challenge_scalar(b"qty_blinding");
        let mut flv_pad = [0u8; 32];
        let mut qty_pad = [0u8; 8];
        t.challenge_bytes(b"flv_pad", &mut flv_pad[..]);
        t.challenge_bytes(b"qty_pad", &mut qty_pad[..]);

        (flv_blinding, qty_blinding, flv_pad, qty_pad)
    }

    /// Computes a short tag that helps quickly throw away irrelevant data entries from a tx.
    /// It is keyed with the address so without knowing the address encryption key,
    /// it is impossible to learn which output is the payment (and contains corresponding data entry),
    /// and which one is a change. If the address is known to a third party, then, like in Bitcoin,
    /// it is trivial to find the output that corresponds to it.
    fn compute_distinguisher(&self, ct: &[u8], value: &Value) -> u8 {
        let mut t = Transcript::new(b"ZkVM.address.distinguisher");
        t.append_message(b"control_key", &self.control_key.as_bytes()[..]);
        t.append_message(b"encryption_key", &self.encryption_key.as_bytes()[..]);
        value
            .encode(&mut t)
            .expect("Encoding to Transcript never fails");
        t.append_message(b"ct", ct);
        let mut result = [0u8; 1];
        t.challenge_bytes(b"tag", &mut result[..]);
        result[0]
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_string())
    }
}

#[inline(always)]
fn xor_slice(a: &mut [u8], b: &[u8]) {
    for i in 0..a.len() {
        a[i] = a[i] ^ b[i];
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use zkvm::VerificationKey;

    #[test]
    fn test_invalid_label() {
        assert_eq!(AddressLabel::new("".to_string()), None);
        assert_eq!(AddressLabel::new("MixedCase".to_string()), None);
        let str84 = "12345678901234567890123456789012345678901234567890123456789012345678901234567890aaax".to_string();
        assert_eq!(AddressLabel::new(str84), None);
        let str83 = "12345678901234567890123456789012345678901234567890123456789012345678901234567890aaa".to_string();
        assert_eq!(AddressLabel::new(str83.clone()), Some(AddressLabel{inner: str83.clone()}));
    }
    #[test]
    fn test_address_encoding() {
        let label = AddressLabel::new("test".to_string()).expect("Valid label");
        let ctrl_scalar = Scalar::from(42u64);
        let encr_scalar = Scalar::from(24u64);

        let ctrl_key = VerificationKey::from_secret(&ctrl_scalar);
        let encr_key = VerificationKey::from_secret(&encr_scalar);

        let addr = Address::new(
            label,
            *ctrl_key.as_point(),
            encr_key.as_point().decompress().unwrap(),
        );
        assert_eq!("test1uq90n36dnmdca0xpvr8we974x89adc54d70fzc4ca8k6yc8g9epca0ntey5jx9jk3q70cwzzjz6jgwx8zm6ezff4ss0f9a5p2junsnc480zqt", addr.to_string());
        assert_eq!("test1uq90n36dnmdca0xpvr8we974x89adc54d70fzc4ca8k6yc8g9epca0ntey5jx9jk3q70cwzzjz6jgwx8zm6ezff4ss0f9a5p2junsnc480zqt", format!("{}", &addr));

        assert_eq!(Some(addr.clone()), Address::from_string("test1uq90n36dnmdca0xpvr8we974x89adc54d70fzc4ca8k6yc8g9epca0ntey5jx9jk3q70cwzzjz6jgwx8zm6ezff4ss0f9a5p2junsnc480zqt"));
        assert_eq!(None, Address::from_string("TEST1uq90n36dnmdca0xpvr8we974x89adc54d70fzc4ca8k6yc8g9epca0ntey5jx9jk3q70cwzzjz6jgwx8zm6ezff4ss0f9a5p2junsnc480zqt"));
        assert_eq!(None, Address::from_string("best1uq90n36dnmdca0xpvr8we974x89adc54d70fzc4ca8k6yc8g9epca0ntey5jx9jk3q70cwzzjz6jgwx8zm6ezff4ss0f9a5p2junsnc480zqt"));
        assert_eq!(None, Address::from_string("test1uq90n36dnmdca0xpvr8we974x89adc54d71fzc4ca8k6yc8g9epca0ntey5jx9jk3q70cwzzjz6jgwx8zm6ezff4ss0f9a5p2junsnc480zqt"));
        assert_eq!(None, Address::from_string("test1uq90n36dnmdca0xpvr8we974x89adc54d71fzc4ca8k6yc8g9epca0ntey5jx9jk3q70cwzzjz6jgwx9zm6ezff4ss0f9a5p2junsnc480zqt"));
    }

    #[test]
    fn test_encryption() {
        let label = AddressLabel::new("test".to_string()).expect("Valid label");
        let ctrl_scalar = Scalar::from(42u64);
        let encr_scalar = Scalar::from(24u64);

        let ctrl_key = VerificationKey::from_secret(&ctrl_scalar);
        let encr_key = VerificationKey::from_secret(&encr_scalar);

        let addr = Address::new(
            label,
            *ctrl_key.as_point(),
            encr_key.as_point().decompress().unwrap(),
        );

        let value = ClearValue {
            flv: Scalar::zero(),
            qty: 1000,
        };

        let (enc_receiver, data) = addr.encrypt(value, rand::thread_rng());
        let enc_value = enc_receiver.blinded_value();

        assert_eq!(data.len(), 73);

        let receiver = addr
            .decrypt(&enc_value, &data, &encr_scalar, rand::thread_rng())
            .unwrap();

        assert_eq!(&receiver.opaque_predicate, ctrl_key.as_point());
        assert_eq!(receiver.value, value);
        assert_eq!(receiver.qty_blinding, enc_value.qty.witness().unwrap().1);
        assert_eq!(receiver.flv_blinding, enc_value.flv.witness().unwrap().1);

        assert!(addr
            .decrypt(&enc_value, &data[0..72], &encr_scalar, rand::thread_rng())
            .is_none());

        // try flipping every bit and check that decryption fails.
        for i in 0..data.len() {
            for j in 0..8 {
                let mut d = data.clone();
                d[i] ^= 1 << j;
                assert!(addr
                    .decrypt(&enc_value, &d, &encr_scalar, rand::thread_rng())
                    .is_none());
            }
        }
    }
}
