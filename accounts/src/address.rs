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

use rand::{CryptoRng, RngCore};
use serde::{Serialize,Deserialize};

use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::VartimeMultiscalarMul;

use merlin::Transcript;
use keytree::{Xprv, Xpub};
use zkvm::{Value,Commitment,ClearValue,TranscriptProtocol};
use zkvm::encoding::Encodable;
use zkvm::bulletproofs::PedersenGens;


use super::Receiver;

/// Address to which funds can be sent
#[derive(Clone,Debug,Serialize,Deserialize)]
pub struct Address {
    control_key: CompressedRistretto,
    encryption_key: CompressedRistretto,
}

impl Address {
    pub fn from_xpub(xpub: &Xpub, seq: u64) -> Self {
        unimplemented!()
    }

    /// Encrypts cleartext value as a zkvm Value with open commitments.
    /// Also returns the opaque data containing the ciphertext and nonce necessary for full decryption by the recipient.
    /// The opaque data must be embedded in a `data` entry in the txlog, in a random location in the transaction,
    /// in order to prevent evesdroppers from distinguishing send-to-address output from the change output.
    pub fn encrypt<R: RngCore + CryptoRng>(&self, value: ClearValue, mut rng: R) -> Option<(Value, Vec<u8>)> {
        let nonce_scalar = Scalar::random(&mut rng);
        let nonce_point = (&nonce_scalar * &RISTRETTO_BASEPOINT_TABLE).compress();
        let dh = (nonce_scalar * self.encryption_key.decompress()?).compress();

        let mut t = Transcript::new(b"ZkVM.address.encrypt");
        t.append_message(b"control_key", &self.control_key.as_bytes()[..]);
        t.append_message(b"dh", &dh.as_bytes()[..]);
        let qty_blinding = t.challenge_scalar(b"qty_blinding");
        let flv_blinding = t.challenge_scalar(b"flv_blinding");
        let mut flv_pad = [0u8; 32];
        let mut qty_pad = [0u8; 8];
        t.challenge_bytes(b"flv_pad", &mut flv_pad[..]);
        t.challenge_bytes(b"qty_pad", &mut qty_pad[..]);

        let encrypted_value = Value {
            qty: Commitment::blinded_with_factor(value.qty, qty_blinding),
            flv: Commitment::blinded_with_factor(value.flv, flv_blinding),
        };

        xor_slice(&mut flv_pad[..], &value.flv.as_bytes()[..]);
        xor_slice(&mut qty_pad[..], &value.qty.to_le_bytes()[..]);
        
        let mut ciphertext = Vec::with_capacity(73);

        // 32 bytes of nonce point
        ciphertext.extend(&nonce_point.as_bytes()[..]);

        // 32 bytes CT for the flavor
        ciphertext.extend(&flv_pad[..]);
        
        //  8 bytes CT for the qty (u64-LE)
        ciphertext.extend(&qty_pad[..]);

        //  1 byte for the distinguisher
        let tag = self.compute_distinguisher(&ciphertext[0..72], &encrypted_value);
        ciphertext.push(tag);

        assert!(ciphertext.len() == 73);
        
        Some(
            (
                encrypted_value,
                ciphertext
            )
        )
    }

    /// Attempts to decrypt the candidate data for the given Address and encrypted Value.
    /// This can fail if the candidate data does not match the value (in which case another candidate should be tried),
    /// or if it was malformed by the sender.
    /// This method fails fast if the data has incorrect length or an incorrect distinguisher byte,
    /// so you should feel free to call it on every data entry without any additional checks.
    pub fn decrypt(&self, value: &Value, candidate_data: &[u8], decryption_key: &Scalar) -> Option<Receiver> {
        if candidate_data.len() != 73 {
            return None;
        }
        let tag = candidate_data[72];

        if tag != self.compute_distinguisher(&candidate_data[0..72], value) {
            // no const-time comparison used because we are comparing just one byte, and 
            // the tag is not used for integrity check, but for quick rejection of irrelevant data entries.
            return None;
        }
        let ct = candidate_data;
        let nonce_point = CompressedRistretto::from_slice(&ct[0..32]).decompress()?;
        
        let dh = (decryption_key * nonce_point).compress();
        
        let mut t = Transcript::new(b"ZkVM.address.encrypt");
        t.append_message(b"control_key", &self.control_key.as_bytes()[..]);
        t.append_message(b"dh", &dh.as_bytes()[..]);
        let qty_blinding = t.challenge_scalar(b"qty_blinding");
        let flv_blinding = t.challenge_scalar(b"flv_blinding");
        let mut flv_pad = [0u8; 32];
        let mut qty_pad = [0u8; 8];
        t.challenge_bytes(b"flv_pad", &mut flv_pad[..]);
        t.challenge_bytes(b"qty_pad", &mut qty_pad[..]);

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
        let mut rng = t.build_rng().finalize(&mut rand::thread_rng());
        let challenge = Scalar::random(&mut rng);
        let gens = PedersenGens::default();

        let p = RistrettoPoint::optional_multiscalar_mul(
            [
                -Scalar::one(),
                -challenge,
                flv + challenge * Scalar::from(qty),
                flv_blinding + challenge * qty_blinding,
            ].into_iter(),
            [
                value.flv.to_point().decompress(),
                value.qty.to_point().decompress(),
                Some(gens.B),
                Some(gens.B_blinding)
            ].into_iter(),
        )?;

        if !p.is_identity() {
            return None;
        }
        
        Receiver {
            opaque_predicate: self.control_key,
            value: ClearValue {
                qty,
                flv
            }
         qty_blinding: Scalar,
        
            /// Blinding factor for the flavor commitment.
            pub flv_blinding: Scalar,
        }
        
        // TODO: read flv scalar and qty u64, reconstruct pedersen commitment
        // and compare with the value in multiscalar mul operation.

        unimplemented!()
    }


    fn compute_distinguisher(&self, ct: &[u8], value: &Value) -> u8 {
        let mut t = Transcript::new(b"ZkVM.address.distinguisher");
        t.append_message(b"control_key", &self.control_key.as_bytes()[..]);
        t.append_message(b"encryption_key", &self.encryption_key.as_bytes()[..]);
        value.encode(&mut t).expect("Encoding to Transcript never fails");
        t.append_message(b"ct", ct);
        let mut result = [0u8; 1];
        t.challenge_bytes(b"tag", &mut result[..]);
        result[0]
    }

}

#[inline(always)]
fn xor_slice(a: &mut [u8], b: &[u8]) {
    for i in 0..a.len() {
        a[i] = a[i] ^ b[i];
    }
}
