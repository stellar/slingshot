use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use keytree::Xpub;
use merlin::Transcript;
use musig::VerificationKey;
use serde::{Deserialize, Serialize};
use zkvm::{Anchor, ClearValue, Commitment, Contract, PortableItem, Predicate, Value};

use crate::{XpubDerivation,Sequence};

#[derive(Copy, Clone, Eq, Hash, Debug, PartialEq, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ReceiverID([u8; 32]);

/// Receiver describes the destination for the payment.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Receiver {
    /// Address to which the payment must be sent.
    pub opaque_predicate: CompressedRistretto,

    /// Cleartext amount of payment: qty and flavor.
    pub value: ClearValue,

    /// Blinding factor for the quantity commitment.
    pub qty_blinding: Scalar,

    /// Blinding factor for the flavor commitment.
    pub flv_blinding: Scalar,
}

/// Private annotation to the receiver that describes derivation path
/// DEPRECATED?
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReceiverWitness {
    /// Account's sequence number at which this receiver was generated.
    pub sequence: Sequence,

    /// Receiver that can be shared with the payer.
    pub receiver: Receiver,
}

/// Contains the anchor for the contract that allows computing the ContractID.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReceiverReply {
    /// ID of the receiver to which this info applies
    pub receiver_id: ReceiverID,

    /// Contract's anchor necessary to compute the contract ID
    pub anchor: Anchor,
}

impl ReceiverWitness {
    /// Creates a new receiver for the Xpub, sequence number and a value
    pub fn new(xpub: &Xpub, sequence: Sequence, value: ClearValue) -> ReceiverWitness {
        ReceiverWitness {
            sequence,
            receiver: xpub.receiver_at_sequence(sequence, value),
        }
    }

    /// Returns `Predicate::Key`
    pub fn predicate(&self) -> Predicate {
        // If we have a witness object, we know that our predicate is
        // (1) correct Ristretto point,
        // (2) a simple public key.
        // Therefore, we can simply unwrap.
        // TBD: We can derive the pubkey on the fly
        // with static guarantees of correctness.
        Predicate::Key(VerificationKey::from_compressed(self.receiver.opaque_predicate).unwrap())
    }

    /// Creates a new contract for the given receiver and an anchor.
    pub fn contract(&self, anchor: Anchor) -> Contract {
        Contract {
            predicate: self.predicate(),
            payload: vec![PortableItem::Value(self.receiver.blinded_value())],
            anchor,
        }
    }
}

impl Receiver {
    /// Returns the unique identifier of the receiver.
    pub fn id(&self) -> ReceiverID {
        let mut t = Transcript::new(b"ZkVM.accounts.receiver");
        t.append_message(b"predicate", self.opaque_predicate.as_bytes());
        t.append_u64(b"qty", self.value.qty);
        t.append_message(b"flv", self.value.flv.as_bytes());
        t.append_message(b"qty_blinding", self.qty_blinding.as_bytes());
        t.append_message(b"flv_blinding", self.flv_blinding.as_bytes());
        let mut receiver = ReceiverID([0u8; 32]);
        t.challenge_bytes(b"receiver_id", &mut receiver.0);
        receiver
    }

    /// Returns the predicate object.
    pub fn predicate(&self) -> Predicate {
        Predicate::Opaque(self.opaque_predicate)
    }

    /// Constructs a value object from the qty, flavor and blinding factors.
    pub fn blinded_value(&self) -> Value {
        Value {
            qty: Commitment::blinded_with_factor(self.value.qty, self.qty_blinding),
            flv: Commitment::blinded_with_factor(self.value.flv, self.flv_blinding),
        }
    }

    /// Verifies that the value is encrypted with blinding factors of the receiver.
    pub fn verify_value(&self, value: &Value) -> bool {
        // TBD: make a Commitment::verify_batch function to check multiple commitments at once.
        value == &self.blinded_value()
    }

    /// Creates a new contract for the given receiver and an anchor.
    pub fn contract(&self, anchor: Anchor) -> Contract {
        Contract {
            predicate: self.predicate(),
            payload: vec![PortableItem::Value(self.blinded_value())],
            anchor,
        }
    }
}
