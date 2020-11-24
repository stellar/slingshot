use core::borrow::Borrow;
use std::collections::HashMap;
use std::mem;
use thiserror::Error;

use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use serde::{Deserialize, Serialize};
use zkvm::bulletproofs::BulletproofGens;

use accounts::{Address, AddressLabel, Receiver, Sequence, XprvDerivation, XpubDerivation};
use keytree::{Xprv, Xpub};
use musig::{Multisignature, VerificationKey};
use token::{Token, XprvDerivation as TKXprvDeriv, XpubDerivation as TKXpubDeriv};

use blockchain::utreexo;
use blockchain::{BlockTx, BlockchainState};
use zkvm::{
    self, Anchor, ClearValue, Contract, ContractID, PortableItem, Predicate, Program, TxLog,
    UnsignedTx, VerifiedTx,
};

use rand::{thread_rng, RngCore};

/// Simple wallet implementation that keeps all data in a single serializable structure.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Wallet {
    /// Prefix used by addresses in this wallet.
    address_label: AddressLabel,

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

    /// List of registered assets mapped from the flavor to the asset alias.
    assets: HashMap<Scalar, String>,
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
#[derive(Clone, Error, Debug)]
pub enum WalletError {
    /// There are not enough funds to make the payment.
    #[error("There are not enough funds to make the payment.")]
    InsufficientFunds,
    /// Signing key (xprv) does not match the wallet's public key.
    #[error("Signing key (xprv) does not match the wallet's public key.")]
    XprvMismatch,
    /// Asset with a given flavor is not found in this wallet.
    #[error("Asset with a given flavor is not found in this wallet.")]
    AssetNotFound,
    /// Address label does not match the wallet's label.
    /// This typically means that an address from one ledger is used by mistake
    /// to receive funds from another ledger.
    #[error("Address label is not expected by this wallet.")]
    AddressLabelMismatch,
}

/// Single-account tx builder API.
#[derive(Clone, Debug)]
pub struct TxBuilder {
    xpub: Xpub,
    actions: Vec<TxAction>,
}

/// Built, but not signed transaction.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BuiltTx {
    /// Raw unsigned ZkVM tx.
    pub unsigned_tx: UnsignedTx,
    /// Utreexo proofs for the inputs used in the program.
    pub proofs: Vec<utreexo::Proof>,
    /// Key derivation info for each `signtx` instance used in the program.
    pub signtx_items: Vec<SigntxInstruction>,
}

/// Key derivation info for a `signtx` invocation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SigntxInstruction {
    /// The key for issuance.
    Issue(Xpub, String),
    /// The key for input.
    Input(Xpub, Sequence),
}

/// A high-level description of the tx action that
/// will turn into specific ZkVM instructions under the hood.
#[derive(Clone, Debug)]
enum TxAction {
    IssueToAddress(ClearValue, Address),
    IssueToReceiver(Receiver),
    TransferToAddress(ClearValue, Address),
    TransferToReceiver(Receiver),
    Memo(Vec<u8>),
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
    pub fn new(address_label: AddressLabel, xpub: Xpub) -> Self {
        Self {
            address_label,
            xpub,
            sequence: 0,
            receivers: Default::default(),
            addresses: Default::default(),
            utxos: Default::default(),
            assets: Default::default(),
        }
    }

    /// Creates a new asset.
    pub fn create_asset(&mut self, alias: String) -> Token {
        let token = self.xpub.derive_token(&alias);
        self.assets.insert(token.flavor(), alias);
        token
    }

    /// Finds asset description for a given flavor.
    pub fn find_asset(&self, flavor: Scalar) -> Option<(&str, Token)> {
        self.assets
            .get(&flavor)
            .map(|alias| (alias.as_str(), self.xpub.derive_token(&alias)))
    }

    /// Lists all registered assets.
    pub fn list_assets<'a>(&'a self) -> impl Iterator<Item = (&'a str, Token)> {
        //let xpub = self.xpub;
        self.assets
            .iter()
            .map(move |(_flv, alias)| (alias.as_str(), self.xpub.derive_token(&alias)))
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
    /// TBD: add safer API to accept blocks and check which were already processed and which were not.
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
                let mut balance = hm.entry(value.flv).or_insert_with(|| Balance {
                    flavor: value.flv,
                    total: 0,
                    utxos: Vec::with_capacity(1),
                });
                balance.total += value.qty;
                balance.utxos.push(utxo.clone());
                hm
            })
            .into_iter()
            .map(|(_, bal)| bal)
    }

    pub fn build_tx(
        &mut self,
        bp_gens: &BulletproofGens,
        closure: impl FnOnce(&mut TxBuilder),
    ) -> Result<BuiltTx, WalletError> {
        let mut rng = thread_rng();
        let mut builder = TxBuilder::new(self.xpub);
        closure(&mut builder);

        // Collect issuances of each asset
        let grouped_issuances = builder
            .actions
            .iter()
            .filter_map(|action| match action {
                TxAction::IssueToAddress(v, _a) => Some(*v),
                TxAction::IssueToReceiver(r) => Some(r.value),
                _ => None,
            })
            .try_fold(
                HashMap::new(),
                |mut hm: HashMap<Scalar, (String, Token, u64)>, value| {
                    if let Some((alias, token)) = self.find_asset(value.flv) {
                        let mut pair =
                            hm.entry(value.flv)
                                .or_insert((alias.to_string(), token, value.qty));
                        pair.2 += value.qty;
                        Ok(hm)
                    } else {
                        Err(WalletError::AssetNotFound)
                    }
                },
            )?;

        // Collect transfers of each asset
        let grouped_transfers = builder
            .actions
            .iter()
            .filter_map(|action| match action {
                TxAction::TransferToAddress(v, _) => Some(*v),
                TxAction::TransferToReceiver(r) => Some(r.value),
                _ => None,
            })
            .fold(HashMap::new(), |mut hm: HashMap<Scalar, u64>, value| {
                *(hm.entry(value.flv).or_default()) += value.qty;
                hm
            });

        let mut outputs = Vec::<Receiver>::new();

        // Collect utxos and change outputs for each asset transferred
        let (inputs, _) = grouped_transfers.into_iter().try_fold(
            (Vec::<Utxo>::new(), &mut outputs),
            |(mut inputs, outputs), (flv, qty)| {
                let (utxos_to_spend, change_clear_value) = ClearValue { qty, flv }
                    .select_coins(self.spendable_utxos())
                    .ok_or(WalletError::InsufficientFunds)?;

                let (_seq, change_receiver) = self.create_receiver(change_clear_value);

                inputs.extend(utxos_to_spend.into_iter());
                outputs.push(change_receiver);

                Ok((inputs, outputs))
            },
        )?;

        let mut memos = Vec::<Vec<u8>>::new();

        // Collect all outputs, so we can shuffle them.
        // Also collect all memos with ciphertext.
        builder.actions.into_iter().try_fold(
            (&mut outputs, &mut memos),
            |(outs, memos), action| {
                match action {
                    TxAction::IssueToAddress(value, addr)
                    | TxAction::TransferToAddress(value, addr) => {
                        if addr.label() != &self.address_label {
                            return Err(WalletError::AddressLabelMismatch);
                        }
                        let (recvr, ct) = addr.encrypt(value, &mut rng);
                        outs.push(recvr);
                        memos.push(ct);
                    }
                    TxAction::IssueToReceiver(recvr) | TxAction::TransferToReceiver(recvr) => {
                        outs.push(recvr);
                    }
                    TxAction::Memo(buf) => {
                        memos.push(buf);
                    }
                }
                Ok((outs, memos))
            },
        )?;

        // Canonically order memos and outputs so we do not leak the order of operations.
        memos.sort_by(|a, b| a.as_slice().cmp(b.as_slice()));
        outputs.sort_by(|a, b| {
            let p1 = a.opaque_predicate.as_bytes();
            let p2 = b.opaque_predicate.as_bytes();
            // sort by publicly-visible predicates, and if they match,
            // sort by unpredictable blinding factors to not leak the order of operations.
            // (we try to avoid computing too many hashes here)
            p1.cmp(p2)
                .then_with(|| a.qty_blinding.as_bytes().cmp(b.qty_blinding.as_bytes()))
        });

        let program = zkvm::Program::build(|p| {
            // issue all the assets
            for (_flv, (_alias, token, qty)) in grouped_issuances.iter() {
                token.issue(p, *qty);
            }
            // spend all the selected utxos
            for utxo in inputs.iter() {
                p.push(utxo.contract_witness());
                p.input();
                p.signtx();
            }

            // prepare outputs for cloak mixer
            for recvr in outputs.iter() {
                let v = recvr.blinded_value();
                p.push(v.qty);
                p.push(v.flv);
            }

            // merge/split assets
            p.cloak(inputs.len(), outputs.len());

            // lock outputs under new predicates
            for recvr in outputs.iter() {
                p.push(recvr.predicate());
                p.output(1);
            }

            // write all the memos (including ciphertexts from spend-to-address)
            for memo in memos.into_iter() {
                p.push(zkvm::String::Opaque(memo));
                p.log();
            }
        });

        let header = zkvm::TxHeader {
            version: 1u64,
            mintime_ms: 0u64,
            maxtime_ms: u64::max_value(),
        };

        // Build the UnverifiedTx
        let unsigned_tx = zkvm::Prover::build_tx(program, header, &bp_gens)
            .expect("We are supposed to compose the program correctly.");

        let issuing_items = grouped_issuances
            .iter()
            .map(|(_flv, (alias, _, _))| SigntxInstruction::Issue(self.xpub, alias.clone()));
        let spending_items = inputs
            .iter()
            .map(|utxo| SigntxInstruction::Input(self.xpub, utxo.sequence));

        let signtx_items = issuing_items.chain(spending_items).collect::<Vec<_>>();
        let utreexo_proofs = inputs.into_iter().map(|utxo| utxo.proof).collect();

        Ok(BuiltTx {
            unsigned_tx,
            proofs: utreexo_proofs,
            signtx_items,
        })
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
        self.build_tx(bp_gens, |b| b.transfer_to_address(value, address))?
            .sign(&xprv)
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
        receiver: Receiver,
        xprv: &Xprv,
        bp_gens: &BulletproofGens,
    ) -> Result<BlockTx, WalletError> {
        self.build_tx(bp_gens, |b| b.transfer_to_receiver(receiver))?
            .sign(xprv)
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
            let (_addr, deckey) = self.xpub.address_at_sequence(address.label().clone(), *seq);
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

impl TxBuilder {
    /// Creates an empty tx builder.
    fn new(xpub: Xpub) -> Self {
        TxBuilder {
            xpub,
            actions: Vec::new(),
        }
    }
    /// Issues the requested amount to the address.
    pub fn issue_to_address(&mut self, value: ClearValue, address: Address) {
        self.actions.push(TxAction::IssueToAddress(value, address));
    }
    /// Issues the requested amount to the receiver.
    pub fn issue_to_receiver(&mut self, receiver: Receiver) {
        self.actions.push(TxAction::IssueToReceiver(receiver));
    }
    /// Transfers the requested amount to the address.
    pub fn transfer_to_address(&mut self, value: ClearValue, address: Address) {
        self.actions
            .push(TxAction::TransferToAddress(value, address));
    }
    /// Transfers the requested amount to the receiver.
    pub fn transfer_to_receiver(&mut self, receiver: Receiver) {
        self.actions.push(TxAction::TransferToReceiver(receiver));
    }
    /// Attaches free-form textual memo.
    pub fn memo(&mut self, memo: Vec<u8>) {
        self.actions.push(TxAction::Memo(memo));
    }
}

impl BuiltTx {
    /// Signs the transaction with a private key.
    /// Xprv must match the wallet's xprv.
    pub fn sign(self, xprv: &Xprv) -> Result<BlockTx, WalletError> {
        let txid = self.unsigned_tx.txid;
        let mut signtx_transcript = merlin::Transcript::new(b"ZkVM.signtx");
        signtx_transcript.append_message(b"txid", &self.unsigned_tx.txid);

        let signing_keys = self
            .signtx_items
            .into_iter()
            .map(|item| {
                let (xpub, key) = match item {
                    SigntxInstruction::Issue(xpub, alias) => {
                        (xpub, xprv.issuing_key(alias.as_str()))
                    }
                    SigntxInstruction::Input(xpub, seq) => (xpub, xprv.key_at_sequence(seq)),
                };
                if &xpub != xprv.as_xpub() {
                    Err(WalletError::XprvMismatch)
                } else {
                    Ok(key)
                }
            })
            .collect::<Result<Vec<_>, _>>()?;

        let sig = musig::Signature::sign_multi(
            &signing_keys[..],
            self.unsigned_tx.signing_instructions.clone(),
            &mut signtx_transcript,
        )
        .unwrap();

        let tx = self.unsigned_tx.sign(sig);

        Ok(BlockTx {
            tx,
            proofs: self.proofs,
        })
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
