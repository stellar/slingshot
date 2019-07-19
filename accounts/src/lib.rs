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
    Forms a transaction with maxtime=min(sender's exptime, receiver exptime).
    Send back the ContractInfo that allows constructing a contract ID.

                              ContractInfo ------->

                                   Reconstruct contract ID from ContractInfo.
                           Store the ContractInfo together with the receiver.

                        <--------- ACK 

    Store the ContractInfo for the change output.
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

use curve25519_dalek::scalar::Scalar;
use keytree::{Xpub,Xprv};
use zkvm::{Anchor,Commitment, CommitmentWitness, Contract, Data, Predicate};

#[derive(Copy, Clone, Eq, Hash, Debug, PartialEq, Default)]
pub struct ReceiverID([u8; 32]);

/// State of the account
pub struct Account {
    pub xpub: Xpub,
    pub sequence: u64,
}

/// Receiver describes the destination for the payment.
pub struct Receiver {
    pub predicate: Predicate,
    pub qty: u64,
    pub flv: Scalar,
    pub qty_blinding: Scalar,
    pub flv_blinding: Scalar,
    pub expiration_ms: u64,
}

/// Contains the anchor for the contract that allows computing the ContractID.
pub struct ContractInfo {
    pub receiver_id: ReceiverID,
    pub anchor: Anchor,
}

impl Receiver {

    pub fn id(&self) -> ReceiverID {
        unimplemented!()
    }
}



