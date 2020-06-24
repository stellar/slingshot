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
mod address;
mod derivation;
mod receiver;
#[cfg(test)]
mod tests;

pub use derivation::{XprvDerivation, XpubDerivation};
pub use receiver::{Receiver, ReceiverID, ReceiverReply, ReceiverWitness};
