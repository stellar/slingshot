use core::borrow::Borrow;
use std::collections::HashMap;
use std::mem;

use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use serde::{Deserialize, Serialize};
use zkvm::bulletproofs::BulletproofGens;

use accounts::{Address, Receiver, Sequence, XprvDerivation, XpubDerivation};
use keytree::{Xprv, Xpub};
use musig::{Multisignature, VerificationKey};

use blockchain::utreexo;
use blockchain::{BlockTx, BlockchainState};
use zkvm::{
    self, Anchor, ClearValue, Contract, ContractID, PortableItem, Predicate, Program, TxLog,
    VerifiedTx,
};

use rand::{thread_rng, RngCore};

/// Simple wallet implementation that keeps all data in a single serializable structure.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Wallet {
    /// Prefix used by addresses in this wallet.
    address_label: String,

    /// Extended pubkey from which all pubkeys and blinding factors are derived.
    xpub: Xpub,

    /// Current sequence number
    sequence: Sequence,

    /// Map of predicate -> receiver
    receivers: HashMap<CompressedRistretto, (Sequence, Receiver, OutputKind)>, // TODO: add expiration time?

    /// Map of predicate -> sequence & address
    addresses: HashMap<CompressedRistretto, (Sequence, Address)>, // TODO: add expiration time?

    /// All utxos tracked by the wallet
    utxos: HashMap<ContractID, Utxo>,
}

/// Balance of a certain asset that consists of a number of spendable UTXOs.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Balance {
    /// Flavor of the asset in this balance
    pub flavor: Scalar,

    /// Total qty of the asset
    pub total: u64,

    /// List of spendable utxos.
    pub utxos: Vec<Utxo>,
}

/// Contract details of the utxo
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Utxo {
    /// Receiver for this utxo.
    receiver: Receiver,
    /// Contract's anchor necessary to reconstruct a contract from Receiver.
    anchor: Anchor,
    /// Sequence used for derivation.
    sequence: Sequence,
    /// Utreexo proof for this utxo.
    proof: utreexo::Proof, // transient for outgoing and unconfirmed utxos
    /// Kind of the output: is it an incoming payment ("theirs") or a change ("ours")
    kind: OutputKind,
    /// Whether this utxo is confirmed.
    confirmed: bool,
    /// Indicates spentness: Some("was confirmed") for spent and None for unspent.
    spent: Option<bool>,
}

/// Errors that may occur during transaction creation.
pub enum WalletError {
    /// There are not enough funds to make the payment
    InsufficientFunds,

    /// Signing key (xprv) does not match the wallet's public key.
    XprvMismatch,
}

/// Kind of the output: is it an incoming payment ("theirs") or a change ("ours")
#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize)]
enum OutputKind {
    Incoming,
    Change,
}

/// Implements the interface for storing addresses, transactions and outputs.
///
/// Important assumptions:
/// 1. User supplies confirmed transactions and Catchup structure in order.
/// 2. Unconfirmed transactions are inserted in topological order (children after parents),
///    and removed in reverse topological order (children before parents).
impl Wallet {
    /// Creates a wallet initialized with Xpub from which all keys are derived.
    pub fn new(address_label: String, xpub: Xpub) -> Self {
        Self {
            address_label,
            xpub,
            sequence: 0,
            receivers: Default::default(),
            addresses: Default::default(),
            utxos: Default::default(),
        }
    }

    /// Creates a new address and records it
    pub fn create_address(&mut self) -> Address {
        let seq = self.sequence;
        self.sequence += 1;
        let (addr, _decryption_key) = self
            .xpub
            .address_at_sequence(self.address_label.clone(), seq);
        self.addresses
            .insert(addr.control_key().clone(), (seq, addr.clone()));
        addr
    }

    /// Creates a new receiver and record it
    pub fn create_receiver(&mut self, value: ClearValue) -> (Sequence, Receiver) {
        let seq = self.sequence;
        self.sequence += 1;
        let recvr = self.xpub.receiver_at_sequence(seq, value);
        self.receivers.insert(
            recvr.opaque_predicate.clone(),
            (seq, recvr.clone(), OutputKind::Incoming),
        );
        (seq, recvr)
    }

    /// Creates a blockchain seeded with the given values.
    pub fn seed_blockchain(
        &mut self,
        timestamp_ms: u64,
        values: impl IntoIterator<Item = ClearValue>,
    ) -> BlockchainState {
        let mut anchor = Anchor::from_raw_bytes([0; 32]);

        let mut utxos = Vec::new();
        for value in values {
            anchor = anchor.ratchet();
            let (seq, recvr) = self.create_receiver(value);
            utxos.push(Utxo {
                receiver: recvr,
                sequence: seq,
                anchor,
                proof: utreexo::Proof::Transient,
                kind: OutputKind::Incoming,
                confirmed: true,
                spent: None,
            });
        }
        let (bc_state, proofs) = BlockchainState::make_initial(
            timestamp_ms,
            utxos.iter().map(|utxo| utxo.contract_id()),
        );

        // Store utxos with updated proofs
        self.utxos.extend(
            utxos
                .into_iter()
                .zip(proofs.into_iter())
                .map(|(mut utxo, proof)| {
                    utxo.proof = proof;
                    (utxo.contract_id(), utxo)
                }),
        );

        bc_state
    }

    /// Processes confirmed trasactions, overwriting the pending state.
    pub fn process_confirmed_txs<T>(&mut self, txs: T, catchup: &utreexo::Catchup)
    where
        T: IntoIterator,
        T::Item: Borrow<VerifiedTx>,
    {
        for tx in txs.into_iter() {
            let tx = tx.borrow();
            // Remove consumed utxos.
            for cid in tx.log.inputs() {
                self.utxos.remove(cid);
            }
            // Add new unspent utxos.
            for c in tx.log.outputs() {
                if let Some((seq, recvr, kind)) = self.receiver_for_output(c, &tx.log) {
                    self.utxos.insert(
                        c.id(),
                        Utxo {
                            receiver: recvr,
                            sequence: seq,
                            anchor: c.anchor,
                            proof: utreexo::Proof::Transient,
                            kind,
                            confirmed: true,
                            spent: None,
                        },
                    );
                }
            }
        }

        // Now the confirmed utxos contain:
        // (1) previously stored utxos with non-transient utreexo proofs
        // (2) newly added utxos with transient utreexo proofs
        // We shall update all the proofs using the catchup map:
        // old utxos will get up-to-date proofs,
        // and the new ones will get the proofs for the first time.
        let hasher = utreexo::utreexo_hasher();
        for (cid, utxo) in self.utxos.iter_mut() {
            // Transient proofs in the unconfirmed utxos are either updated (if those became confirmed),
            // or remain transient. This can fail only if existing proofs are inconsistent with the catchup map
            // which may happen if the confirmed txs and catchup map are not applied sequentially.
            let mut current_proof = utreexo::Proof::Transient;
            mem::swap(&mut utxo.proof, &mut current_proof);
            let new_proof = catchup
                .update_proof(cid, current_proof, &hasher)
                .expect("Please make sure that catchup maps are applied in sequence.");
            utxo.proof = new_proof;
        }
    }

    /// Removes all unconfirmed utxos, so they can be re-created anew with `add_unconfirmed_tx` call.
    pub fn clear_unconfirmed_utxos(&mut self) {
        self.utxos.retain(|_, utxo| {
            // make sure to preserve confirmed utxos that are spent as unconfirmed
            if !utxo.confirmed {
                // Erase spent status and restore the original confirmed flag
                if let Some(was_confirmed) = utxo.spent {
                    utxo.spent = None;
                    utxo.confirmed = was_confirmed;
                }
            }
            utxo.confirmed
        });
    }

    /// Adds an unconfirmed tx.
    /// Important: the caller is responsible to call this method in topological order (children added after parents).
    pub fn add_unconfirmed_tx(&mut self, tx: &VerifiedTx) {
        // 1. Mark all known inputs as spent.
        for cid in tx.log.inputs() {
            if let Some(utxo) = self.utxos.get_mut(cid) {
                utxo.spent = Some(utxo.confirmed);
                utxo.confirmed = false;
            }
        }
        // 2. Insert new outputs as unspent.
        for c in tx.log.outputs() {
            if let Some((seq, recvr, kind)) = self.receiver_for_output(c, &tx.log) {
                self.utxos.insert(
                    c.id(),
                    Utxo {
                        receiver: recvr,
                        sequence: seq,
                        anchor: c.anchor,
                        proof: utreexo::Proof::Transient,
                        kind,
                        confirmed: false,
                        spent: None,
                    },
                );
            }
        }
    }

    /// Removes an unconfirmed transaction, which reverses the spent/unspent states of pending utxos.
    /// Important: the caller is responsible to call this method in reverse topological order (children removed before parents).
    pub fn remove_unconfirmed_tx(&mut self, tx: &VerifiedTx) {
        // 1. Mark all spent as unspent.
        for cid in tx.log.inputs() {
            if let Some(utxo) = self.utxos.get_mut(cid) {
                if let Some(was_confirmed) = utxo.spent {
                    utxo.confirmed = was_confirmed;
                    utxo.spent = None;
                }
            }
        }

        // 2. Remove utxos created by the outputs of this transaction.
        for cid in tx.log.outputs().map(|c| c.id()) {
            self.utxos.remove(&cid);
        }
    }

    /// Returns all spendable utxos, including unconfirmed change utxos.
    pub fn spendable_utxos(&self) -> impl Iterator<Item = Utxo> + '_ {
        self.utxos.iter().filter_map(|(cid, utxo)| {
            if utxo.spent == None && (utxo.confirmed || utxo.kind == OutputKind::Change) {
                Some(utxo.clone())
            } else {
                None
            }
        })
    }

    /// Returns a list of asset balances, one per asset flavor.
    pub fn balances(&self) -> impl Iterator<Item = Balance> {
        self.spendable_utxos()
            .fold(HashMap::new(), |mut hm: HashMap<Scalar, Balance>, utxo| {
                let value = utxo.value();
                match hm.get_mut(&value.flv) {
                    Some(balance) => {
                        balance.total += value.qty;
                        balance.utxos.push(utxo.clone());
                    }
                    None => {
                        hm.insert(
                            value.flv.clone(),
                            Balance {
                                flavor: value.flv,
                                total: value.qty,
                                utxos: vec![utxo.clone()],
                            },
                        );
                    }
                }
                hm
            })
            .into_iter()
            .map(|(_, bal)| bal)
    }

    /// Attempts to build and sign a transaction paying a value to a given address.
    ///
    /// IMPORTANT: This does not immediately index the change output for use in the next tx.
    /// You should add the returned transaction to the mempool and after it is verified,
    /// index it in the wallet via `add_unconfirmed_tx`.
    /// After that you can sign another transaction and use the full balance
    /// that includes the change value from the previously signed transaction.
    pub fn pay_to_address(
        &mut self,
        value: ClearValue,
        address: Address,
        xprv: &Xprv,
        bp_gens: &BulletproofGens,
    ) -> Result<BlockTx, WalletError> {
        let (receiver, ct) = address.encrypt(value, thread_rng());
        self.create_payment_transaction(receiver, xprv, bp_gens, |p| {
            // add the payment ciphertext to the txlog
            p.push(zkvm::String::Opaque(ct));
            p.log();
        })
    }

    /// Attempts to build and sign a transaction paying a value to a given receiver.
    ///
    /// IMPORTANT: This does not immediately index the change output for use in the next tx.
    /// You should add the returned transaction to the mempool and after it is verified,
    /// index it in the wallet via `add_unconfirmed_tx`.
    /// After that you can sign another transaction and use the full balance
    /// that includes the change value from the previously signed transaction.
    pub fn pay_to_receiver(
        &mut self,
        value: ClearValue,
        receiver: Receiver,
        xprv: &Xprv,
        bp_gens: &BulletproofGens,
    ) -> Result<BlockTx, WalletError> {
        self.create_payment_transaction(receiver, xprv, bp_gens, |_| {})
    }

    /// Attempts to build and sign a transaction paying a value to a given address.
    ///
    /// IMPORTANT: This does not immediately index the change output for use in the next tx.
    /// You should add the returned transaction to the mempool and after it is verified,
    /// index it in the wallet via `add_unconfirmed_tx`.
    /// After that you can sign another transaction and use the full balance
    /// that includes the change value from the previously signed transaction.
    fn create_payment_transaction(
        &mut self,
        receiver: Receiver,
        xprv: &Xprv,
        bp_gens: &BulletproofGens,
        program_builder: impl FnOnce(&mut Program),
    ) -> Result<BlockTx, WalletError> {
        let payment_value = receiver.blinded_value();
        let payment_predicate = receiver.predicate();

        if xprv.as_xpub() != &self.xpub {
            return Err(WalletError::XprvMismatch);
        }

        let (utxos_to_spend, change_clear_value) = receiver
            .value
            .select_coins(self.spendable_utxos())
            .ok_or(WalletError::InsufficientFunds)?;

        let (seq, change_receiver) = self.create_receiver(change_clear_value);
        let change_value = change_receiver.value;

        let coin_flip = thread_rng().next_u64();

        // Sender forms a tx paying to this receiver.
        //    Now recipient is receiving a new utxo, sender is receiving a change utxo.
        let unsigned_tx = {
            // Note: for clarity, we are not randomizing inputs and outputs in this example.
            // The real transaction must randomize all the things
            let program = zkvm::Program::build(|mut p| {
                // claim all the collected utxos
                for utxo in utxos_to_spend.iter() {
                    p.push(utxo.contract_witness());
                    p.input();
                    p.signtx();
                }

                shuffler(
                    &mut p,
                    coin_flip,
                    |p| {
                        p.push(payment_value.qty);
                        p.push(payment_value.flv);
                    },
                    |p| {
                        p.push(change_value.qty);
                        p.push(change_value.flv);
                    },
                );

                p.cloak(utxos_to_spend.len(), 2);

                shuffler(
                    &mut p,
                    coin_flip,
                    |p| {
                        p.push(payment_predicate);
                        p.output(1);
                    },
                    |p| {
                        p.push(change_receiver.predicate());
                        p.output(1);
                    },
                );

                program_builder(p);
            });
            let header = zkvm::TxHeader {
                version: 1u64,
                mintime_ms: 0u64,
                maxtime_ms: u64::max_value(),
            };

            // Build the UnverifiedTx
            zkvm::Prover::build_tx(program, header, &bp_gens)
                .expect("We are supposed to compose the program correctly.")
        };
        let txid = unsigned_tx.txid;

        // Sign the tx.
        let tx = {
            let mut signtx_transcript = merlin::Transcript::new(b"ZkVM.signtx");
            signtx_transcript.append_message(b"txid", &txid);

            // Derive individual signing keys for each input, according to its sequence number.
            // In this example all inputs are coming from the same account (same xpub).
            let signing_keys = utxos_to_spend
                .iter()
                .map(|utxo| xprv.key_at_sequence(utxo.sequence))
                .collect::<Vec<_>>();

            let sig = musig::Signature::sign_multi(
                &signing_keys[..],
                unsigned_tx.signing_instructions.clone(),
                &mut signtx_transcript,
            )
            .unwrap();

            unsigned_tx.sign(sig)
        };

        let utreexo_proofs = utxos_to_spend.into_iter().map(|utxo| utxo.proof).collect();

        Ok(BlockTx {
            tx,
            proofs: utreexo_proofs,
        })
    }

    /// Returns a pair of a sequence number and a receiver
    fn receiver_for_output(
        &self,
        contract: &Contract,
        txlog: &TxLog,
    ) -> Option<(Sequence, Receiver, OutputKind)> {
        let k = contract.predicate.to_point();
        let value: &zkvm::Value = contract.extract()?;

        // 1. Check if we have an incoming receiver for this output and whether it can be used.
        if let Some((seq, receiver, kind)) = self.receivers.get(&k) {
            // Make sure the value is encrypted correctly
            if receiver.verify_value(value) {
                return Some((*seq, *receiver, *kind));
            }
        }

        // 2. Check if we have an address, and then try to decrypt the output and get the receiver out.
        if let Some((seq, address)) = self.addresses.get(&k) {
            let (_addr, deckey) = self
                .xpub
                .address_at_sequence(address.label().to_string(), *seq);
            // Try all data entries - no worries, the decrypt fails quickly on obviously irrelevant entries.
            for data in txlog.data_entries() {
                if let Some(receiver) = address.decrypt(value, data, &deckey, thread_rng()) {
                    return Some((*seq, receiver, OutputKind::Incoming));
                }
            }
        }
        None
    }
}

impl AsRef<ClearValue> for Utxo {
    fn as_ref(&self) -> &ClearValue {
        &self.receiver.value
    }
}

impl Utxo {
    /// Convert utxo to a Contract instance
    pub fn contract(&self) -> Contract {
        self.receiver.contract(self.anchor)
    }

    /// Preserves Predicate as ::Key, not as ::Opaque
    pub fn contract_witness(&self) -> Contract {
        // Since we successfully matched on a pre-registered receiver, we know that our predicate is
        // (1) a correct Ristretto point,
        // (2) a simple public key.
        // Therefore, we can simply unwrap.
        let predicate = Predicate::Key(
            VerificationKey::from_compressed(self.receiver.opaque_predicate).unwrap(),
        );
        // TBD: Instead of unwrap-decompressing the key, derive it directly from xpub with a given sequence number.

        Contract {
            predicate,
            payload: vec![PortableItem::Value(self.receiver.blinded_value())],
            anchor: self.anchor,
        }
    }

    /// Returns the UTXO ID
    pub fn contract_id(&self) -> ContractID {
        self.contract().id()
    }

    pub fn value(&self) -> ClearValue {
        self.receiver.value
    }
}

fn shuffler<T>(
    ctx: &mut T,
    random: u64,
    a: impl FnOnce(&mut T) -> (),
    b: impl FnOnce(&mut T) -> (),
) {
    if random % 2 == 0 {
        a(ctx);
        b(ctx);
    } else {
        b(ctx);
        a(ctx);
    }
}
