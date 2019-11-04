//! Accounts is an API for accounts build around UTXO-based blockchain state.
/*
Workflow
========

Recipient needs to tell the sender the amount and blinding factors,
and then be able to obtain a utxo proof in order to be able to spend the funds.

    Sender                                                         Recipient
    ------------------------------------------------------------------------
                                             Shows the payment URL (e.g. QR).
    Makes a request to the payment URL.
                                 Request ------>
                                            Derives a one-time key from xpub.
                                                  Generates blinding factors.
                                             Creates a Receiver with exptime.
                                          Stores Receiver as pending payment.

                        <------ Receiver

    Confirms payment details.
    Selects utxos to cover the payment amount
    Forms a transaction with maxtime=min(sender's exptime, receiver exptime).
    Send back the ReceiverReply that allows constructing a contract ID.

                              ReceiverReply ------->

                                   Reconstruct contract ID from ReceiverReply.
                           Store the ReceiverReply together with the receiver.

                        <--------- ACK

    Store the ReceiverReply for the change output.
    Publish the transaction.
                                   ...

                       Both when new block is published:

              Detect an insertion to the utreexo with the contract id,
              create the proof and keep updating the proof.

              Based on the block's timestamp, prune all expired receivers.
    ------------------------------------------------------------------------

This scheme is compatible with SPV recipient and/or sender.


Questions:
1. When do we want to scan the txs to detect payments instead of looking for utxo proof only?
   Only when the sender does not send back the tx, but simply publishes it. When is this relevant?
   Probably never - you still need some service to collect and maintain utxo proofs for you.

2. Consistency issue: if we publish tx, but recipient never received contract contents - they cannot accept payment.
   If they pretend to fail, but have received contract - they can publish the tx and receive funds, while user does not.
   => resolvable by:
   (a) receipt token - recipient and sender atomically swap money for the receipt token, which acts as a proof of completed
       payment.
       Problem: need to figure out how to mutually sign a proof
   (b) tx must have exptime, even if recipient fails to accept tx,
       the sender still watches the chain for their tx confirmation until it expires.
       Con: sender cannot be sure whether to spend the same utxo or the new change utxo until tx expires.
   (c) do not send the entire tx to the recipient, instead send a contract breakdown.
       this way regardless of the recipient's reply, they won't be able to publish tx,
       so the sender can avoid publishing it unless recipient acknowledged the payment details.
*/

use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use keytree::{Xprv, Xpub};
use merlin::Transcript;
use musig::VerificationKey;
use serde::{Deserialize, Serialize};
use zkvm::{
    Anchor, ClearValue, Commitment, Contract, PortableItem, Predicate, TranscriptProtocol, Value,
};

#[cfg(test)]
mod tests;

#[derive(Copy, Clone, Eq, Hash, Debug, PartialEq, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ReceiverID([u8; 32]);

/// State of the account
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Account {
    /// Account's root extended public key.
    pub xpub: Xpub,

    /// Account's current sequence number.
    pub sequence: u64,
}

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
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReceiverWitness {
    /// Account's sequence number at which this receiver was generated.
    pub sequence: u64,

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

    /// Creates a new contract for the given receiver and an anchor.
    pub fn contract(&self, anchor: Anchor) -> Contract {
        Contract {
            predicate: self.predicate(),
            payload: vec![PortableItem::Value(self.blinded_value())],
            anchor,
        }
    }
}

impl Account {
    /// Creates a new account with a zero sequence number.
    pub fn new(xpub: Xpub) -> Self {
        Self { xpub, sequence: 0 }
    }

    /// Creates a new receiver and increments the sequence number.
    pub fn generate_receiver(&mut self, value: ClearValue) -> ReceiverWitness {
        let seq = self.sequence;
        self.sequence += 1;

        let key = self.xpub.derive_key(|t| t.append_u64(b"sequence", seq));
        let (qty_blinding, flv_blinding) = self.derive_blinding_factors(&value);

        ReceiverWitness {
            sequence: seq,
            receiver: Receiver {
                opaque_predicate: key.into_compressed(),
                value,
                qty_blinding,
                flv_blinding,
            },
        }
    }

    /// Derives signing key for the current sequence number.
    pub fn derive_signing_key(sequence: u64, xprv: &Xprv) -> Scalar {
        xprv.derive_key(|t| t.append_u64(b"sequence", sequence))
    }

    /// Selects UTXOs to match the given receiver's qty and flavor.
    /// Returns the list of selected UTXOs and an amount of _change_ quantity
    /// that needs to balance the spent utxos.
    pub fn select_utxos<I, T>(value: &ClearValue, utxos: I) -> Option<(Vec<T>, ClearValue)>
    where
        I: IntoIterator<Item = T>,
        T: AsRef<ClearValue>,
    {
        let (collected_utxos, total_spent) = utxos
            .into_iter()
            .filter(|utxo| utxo.as_ref().flv == value.flv)
            .fold(
                (Vec::new(), 0u64),
                |(mut collected_utxos, mut total_spent), utxo| {
                    if total_spent < value.qty {
                        total_spent += utxo.as_ref().qty;
                        collected_utxos.push(utxo);
                    }
                    (collected_utxos, total_spent)
                },
            );

        // Check if have sufficient funds.
        // TBD: change to return an appropriate Err()
        if total_spent < value.qty {
            return None;
        }

        let change = ClearValue {
            qty: total_spent - value.qty,
            flv: value.flv,
        };
        Some((collected_utxos, change))
    }

    /// Derives blinding factors for the quantity and flavor.
    /// Q: Why deterministic derivation?
    /// A: Blinding factors are high-entropy, so loss of such data is fatal.
    ///    While loss of low-entropy metadata such as qty and flavor is recoverable
    ///    from multiple other systems (analytics, counter-parties), or even by bruteforce search.
    fn derive_blinding_factors(&self, value: &ClearValue) -> (Scalar, Scalar) {
        // Blinding factors are deterministically derived in order to avoid
        // having to backup secret material.
        // It can be always re-created from the single root xpub.
        let mut t = Transcript::new(b"ZkVM.accounts.blinding");
        t.append_message(b"xpub", &self.xpub.to_bytes());
        t.append_u64(b"sequence", self.sequence);
        t.append_u64(b"qty", value.qty);
        t.append_message(b"flv", value.flv.as_bytes());
        let q = t.challenge_scalar(b"qty_blinding");
        let f = t.challenge_scalar(b"flv_blinding");
        (q, f)
    }
}
