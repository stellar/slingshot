use std::collections::HashMap;

use curve25519_dalek::scalar::Scalar;
use zkvm::bulletproofs::BulletproofGens;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

use accounts::{Receiver, ReceiverWitness, XprvDerivation};
use keytree::Xprv;
use musig::Multisignature;

use blockchain::utreexo;
use zkvm::{Anchor, ClearValue, Contract, ContractID, Tx, TxEntry, TxLog, VerifiedTx};
use super::json;

/// User's wallet account data
#[derive(Clone, Serialize, Deserialize)]
pub struct Account {
    /// Name of the account
    pub alias: String,

    /// Account's root wallet key
    // (we don't store it encrypted for now to make the demo simpler,
    // but later we'll switch this to encrypted store)
    pub xprv: Xprv,

    /// User's account state
    pub sequence: u64,

    /// Annotated txs related to this account
    pub txs: Vec<AnnotatedTx>,

    /// All utxos known to the user - their own and outgoing.
    pub utxos: Vec<UtxoWithStatus>,
}

/// Contract details of the utxo
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Utxo {
    pub receiver: Receiver,
    pub anchor: Anchor,
    pub sequence: u64,         // 0 for outgoing utxos
    pub proof: utreexo::Proof, // transient for outgoing and unconfirmed utxos
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UtxoWithStatus {
    status: UtxoStatus,
    utxo: Utxo,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub enum UtxoStatus {
    /// Account's incoming payment that is just promised by the sender.
    /// Created even before the account has seen an unconfirmed transaction in a mempool.
    Incoming,

    /// Account's outgoing payment that belong to someone else.
    /// We track these so we can annotate this account's transactions.
    Outgoing,

    /// Received utxo contains a utreexo proof that's always being updated.
    Received,

    /// Our utxo that we marked as spent. It's not removed right away until we process
    /// transaction and annotate our own txs.
    Spent,
}


/// Tx annotated with
#[derive(Clone, Serialize, Deserialize)]
pub struct AnnotatedTx {
    pub block_height: Option<u64>,
    pub raw_tx: zkvm::Tx,
    // entry position, cleartext value
    pub known_entries: Vec<(usize, ClearValue)>,
}

/// Balance of a certain asset that consists of a number of spendable UTXOs.
#[derive(Clone,Debug,Serialize,Deserialize)]
pub struct Balance {
    /// Flavor of the asset in this balance
    pub flavor: Scalar,

    /// Total qty of the asset
    pub total: u64,

    /// List of spendable utxos.
    pub utxos: Vec<Utxo>,
}

impl Account {
    /// Creates a new user account with a privkey and pre-seeded collection of utxos
    pub fn new(alias: impl Into<String>, root_xprv: &Xprv) -> Self {
        let alias = alias.into();

        let xprv = root_xprv.derive_intermediate_key(|t| {
            t.append_message(b"account_alias", alias.as_bytes());
        });

        Self {
            alias,
            xprv,
            sequence: 0,
            txs: Vec::new(),
            utxos: Vec::new(),
        }
    }

    pub fn generate_receiver(&mut self, value: ClearValue) -> ReceiverWitness {
        let seq = self.sequence;
        self.sequence += 1;
        ReceiverWitness::new(self.xprv.as_xpub(), seq, value)
    }

    /// Generates a bunch of initial utxos
    pub fn mint_utxos(
        &mut self,
        mut anchor: Anchor,
        flv: Scalar,
        qtys: impl IntoIterator<Item = u64>,
    ) -> (Vec<Utxo>, Anchor) {
        let mut results = Vec::new();
        for qty in qtys {
            // anchors are not unique, but it's irrelevant for this test
            anchor = anchor.ratchet();

            let receiver_witness = self.generate_receiver(ClearValue { qty, flv });

            results.push(Utxo {
                receiver: receiver_witness.receiver,
                sequence: receiver_witness.sequence,
                anchor,
                proof: utreexo::Proof::Transient,
            });
        }
        (results, anchor)
    }

    pub fn remove_utxo(&mut self, contract_id: ContractID) -> Option<UtxoWithStatus> {
        // Remove spent anchoring utxo
        let maybe_i = self
            .utxos
            .iter()
            .position(|o| o.contract_id() == contract_id);

        if let Some(i) = maybe_i {
            Some(self.utxos.remove(i))
        } else {
            None
        }
    }

    pub fn spend_utxo(&mut self, contract_id: ContractID) {
        // Remove spent anchoring utxo
        let maybe_i = self
            .utxos
            .iter()
            .position(|o| o.contract_id() == contract_id);

        if let Some(i) = maybe_i {
            self.utxos[i].mark_as_spent();
        }
    }

    pub fn update_utxo_proofs(&mut self, catchup: &utreexo::Catchup) {
        // Catch up utxoproofs for all the confirmed utxos.
        let hasher = utreexo::utreexo_hasher();
        let updated_proofs = self
            .utxos
            .iter()
            .map(|utxo| {
                catchup.update_proof(&utxo.contract_id(), utxo.any_utxo().proof.clone(), &hasher)
            })
            .collect::<Vec<_>>();

        // Once all proofs are succesfully updated, apply them to our storage.
        for (maybe_proof, utxo) in updated_proofs.into_iter().zip(self.utxos.iter_mut()) {
            if let Ok(p) = maybe_proof {
                utxo.as_mut_utxo().proof = p;
            } else {
                eprintln!("Proof update failed for {:?}", utxo);
            }
        }
    }

    /// Processes a block: detects spends, new outputs and updates utxo proofs.
    pub fn process_block(
        &mut self,
        vtxs: &[VerifiedTx],
        txs: &[Tx],
        block_height: u64,
        catchup: &utreexo::Catchup,
    ) {
        println!(
            "Node {:?} is processing block {}...",
            &self.alias, block_height
        );

        for (tx_index, vtx) in vtxs.iter().enumerate() {
            if let Some(atx) = self.process_tx(&txs[tx_index], &vtx.log, Some(block_height)) {
                self.txs.push(atx);
            }
        }

        self.update_utxo_proofs(catchup);
    }

    /// Attempts to annotate the tx, and returns Some if this tx belongs to the account.
    /// IMPORTANT: this modifies the wallet's utxo set.
    pub fn process_tx(
        &mut self,
        tx: &Tx,
        txlog: &TxLog,
        block_height: Option<u64>,
    ) -> Option<AnnotatedTx> {
        let mut known_entries = Vec::new();
        let mut our_tx = false;
        for (entry_index, entry) in txlog.iter().enumerate() {
            match entry {
                TxEntry::Input(contract_id) => {
                    if let Some(utxo) = self.remove_utxo(*contract_id) {
                        known_entries.push((entry_index, utxo.value()));
                        if let Some(_) = utxo.our_utxo() {
                            our_tx = true;
                        }
                    }
                }
                TxEntry::Output(contract) => {
                    let cid = contract.id();

                    if let Some(i) = self.utxos.iter().position(|utxo| utxo.contract_id() == cid) {
                        let utxo = &self.utxos[i];
                        known_entries.push((entry_index, utxo.value()));
                        if let Some(_) = utxo.our_utxo() {
                            our_tx = true;
                        }
                        self.utxos[i].mark_incoming_as_received()
                    }
                }
                _ => {}
            }
        }

        if our_tx {
            Some(AnnotatedTx {
                block_height,
                raw_tx: tx.clone(),
                known_entries,
            })
        } else {
            None
        }
    }

    /// Returns a list of asset balances, one per asset flavor.
    pub fn balances(&self) -> Vec<Balance> {
        self
            .utxos
            .iter()
            .filter_map(UtxoWithStatus::spendable_utxo)
            .fold(
                HashMap::new(),
                |mut hm: HashMap<Scalar, Balance>, utxo| {
                    let value = utxo.value();
                    match hm.get_mut(&value.flv) {
                        Some(balance) => {
                            balance.total += value.qty;
                            balance.utxos.push(utxo.clone());
                        }
                        None => {
                            hm.insert(value.flv.clone(), Balance {
                                flavor: value.flv,
                                total: value.qty,
                                utxos: vec![utxo.clone()]
                            });
                        }
                    }
                    hm
                },
            ).into_iter().map(|(_, bal)| bal).collect()
    }


    // pub fn balances(&self) -> JsonValue {
    //     // 1. Enumerate all confirmed utxos and stack up values by flavor.
    //     // 2. Then, annotate each flavor with the asset name.

    //     // HashMap<encoded flavor => (balance, Vec<Utxo>)>
    //     let map = self
    //         .utxos
    //         .iter()
    //         .filter_map(UtxoWithStatus::spendable_utxo)
    //         .fold(
    //             HashMap::new(),
    //             |mut hm: HashMap<Vec<u8>, (u64, Vec<Utxo>)>, utxo| {
    //                 let value = utxo.value();
    //                 let key = value.flv.as_bytes().to_vec();
    //                 match hm.get_mut(&key) {
    //                     Some((total, list)) => {
    //                         *total += value.qty;
    //                         list.push(utxo.clone());
    //                     }
    //                     None => {
    //                         hm.insert(key, (value.qty, vec![utxo.clone()]));
    //                     }
    //                 }
    //                 hm
    //             },
    //         );
    //     json!(map
    //         .iter()
    //         .map(|(flv, (balance, utxos))| {
    //             let alias = assets
    //                 .iter()
    //                 .find(|&asset| asset.flavor().as_bytes() == &flv[..])
    //                 .map(|x| x.alias.clone())
    //                 .unwrap_or(hex::encode(flv));

    //             json!({
    //                 "alias": alias,
    //                 "flavor_hex": hex::encode(&flv),
    //                 "flv": flv,
    //                 "qty": balance,
    //                 "utxos": utxos.iter().map(|utxo| {
    //                     json!({
    //                         "contract_id": hex::encode(&utxo.contract_id()),
    //                         "qty": utxo.value().qty
    //                     })
    //                 } ).collect::<Vec<_>>()
    //             })
    //         })
    //         .collect::<Vec<_>>())
    // }

    /// Constructs an issuance transaction and a reply to the recipient.
    pub fn prepare_issuance_tx(
        &mut self,
        issuance_key: Scalar,
        issuance_metadata: zkvm::String,
        payment_receiver: &accounts::Receiver,
        bp_gens: &BulletproofGens,
    ) -> Result<
        (
            zkvm::Tx,
            zkvm::TxID,
            Vec<utreexo::Proof>,
            accounts::ReceiverReply,
        ),
        &'static str,
    > {
        let anchoring_utxo = &self
            .utxos
            .iter()
            .filter_map(UtxoWithStatus::spendable_utxo)
            .next()
            .ok_or("Issuer needs at least one available UTXO to anchor the transaction.")?
            .clone();
        let change_receiver_witness = self.generate_receiver(anchoring_utxo.receiver.value);
        let change_receiver = change_receiver_witness.receiver;
        let change_seq = change_receiver_witness.sequence;

        // Sender forms a tx paying to this receiver.
        // Now recipient is receiving a new utxo, sender is receiving a change utxo.
        let utx = {
            // Note: for clarity, we are not randomizing inputs and outputs in this example.
            // The real transaction must randomize all the things
            let program = zkvm::Program::build(|p| {
                p.push(anchoring_utxo.contract_witness());
                p.input();
                p.signtx();

                let issuance_predicate =
                    zkvm::Predicate::Key(zkvm::VerificationKey::from_secret(&issuance_key));

                p.push(zkvm::Commitment::blinded(payment_receiver.value.qty)) // stack: qty
                    .var() // stack: qty-var
                    .push(zkvm::Commitment::unblinded(payment_receiver.value.flv)) // stack: qty-var, flv
                    .var() // stack: qty-var, flv-var
                    .push(issuance_metadata) // stack: qty-var, flv-var, data
                    .push(issuance_predicate) // stack: qty-var, flv-var, data, flv-pred
                    .issue() // stack: issue-contract
                    .signtx(); // stack: issued-value

                let pmnt = payment_receiver.blinded_value();
                p.push(pmnt.qty);
                p.push(pmnt.flv);

                let change = change_receiver.blinded_value();
                p.push(change.qty);
                p.push(change.flv);

                p.cloak(2, 2);

                p.push(payment_receiver.predicate());
                p.output(1);

                p.push(change_receiver.predicate());
                p.output(1);
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
        let txid = utx.txid;

        // Alice sends ReceiverReply to Bob with contract's anchor.
        // Determine the payment contract's anchor and send it to Bob via ReceiverReply

        // Collect all anchors for outputs.
        let mut iterator = utx.txlog.iter().filter_map(|e| match e {
            TxEntry::Output(contract) => Some(contract.anchor),
            _ => None,
        });
        let payment_anchor = iterator
            .next()
            .expect("We have just built 2 outputs above.");
        let change_anchor = iterator
            .next()
            .expect("We have just built 2 outputs above.");

        let reply = accounts::ReceiverReply {
            receiver_id: payment_receiver.id(),
            anchor: payment_anchor,
        };

        let change_utxo = Utxo {
            receiver: change_receiver,
            anchor: change_anchor,
            sequence: change_seq,
            proof: utreexo::Proof::Transient,
        };

        // Sign the tx.
        let tx = {
            let mut signtx_transcript = merlin::Transcript::new(b"ZkVM.signtx");
            signtx_transcript.append_message(b"txid", &utx.txid.0);

            // Derive individual signing keys for each input, according to its sequence number.
            // In this example all inputs are coming from the same account (same xpub).
            let spending_key = self.xprv.key_at_sequence(anchoring_utxo.sequence);

            let signing_keys = vec![spending_key, issuance_key];

            let sig = musig::Signature::sign_multi(
                &signing_keys[..],
                utx.signing_instructions.clone(),
                &mut signtx_transcript,
            )
            .unwrap();

            utx.sign(sig)
        };

        let utxo_proofs = vec![anchoring_utxo.proof.clone()];
        let cid = anchoring_utxo.contract_id();
        self.spend_utxo(cid);

        // Save the change utxo - it is spendable right away, via a chain of unconfirmed txs.
        // FIXME: Strictly speaking, this is an "Incoming" utxo because we haven't yet published tx,
        // but we currently don't do persistent changes when new txs land in a mempool,
        // so if we mark it as Incoming, we won't be able to spend it until it's confirmed in a block.
        // WARNING: This will cause an issue if the tx is not going to get into mempool.
        //          However, it's similar to having mempool cleared -
        //          we need a proper solution to rollback utxo storage when some
        //          txs get fail to get into block.
        self.utxos.push(change_utxo.received());

        // remember the outgoing payment
        self.utxos.push(
            Utxo {
                receiver: payment_receiver.clone(),
                anchor: reply.anchor,
                sequence: 0,
                proof: utreexo::Proof::Transient,
            }
            .outgoing(),
        );

        Ok((tx, txid, utxo_proofs, reply))
    }

    /// Constructs a payment transaction and a reply to the recipient.
    pub fn prepare_payment_tx(
        &mut self,
        payment_receiver: &accounts::Receiver,
        bp_gens: &BulletproofGens,
    ) -> Result<
        (
            zkvm::Tx,
            zkvm::TxID,
            Vec<utreexo::Proof>,
            accounts::ReceiverReply,
        ),
        &'static str,
    > {
        let (spent_utxos, change_value) = payment_receiver
            .value
            .select_coins(
                self.utxos
                    .iter()
                    .filter_map(UtxoWithStatus::spendable_utxo)
                    .cloned(),
            )
            .ok_or("Insufficient funds!")?;

        let maybe_change_receiver_witness = if change_value.qty > 0 {
            Some(self.generate_receiver(change_value))
        } else {
            None
        };

        // Sender forms a tx paying to this receiver.
        //    Now recipient is receiving a new utxo, sender is receiving a change utxo.
        let utx = {
            // Note: for clarity, we are not randomizing inputs and outputs in this example.
            // The real transaction must randomize all the things
            let program = zkvm::Program::build(|p| {
                // claim all the collected utxos
                for stored_utxo in spent_utxos.iter() {
                    p.push(stored_utxo.contract_witness());
                    p.input();
                    p.signtx();
                }

                let pmnt = payment_receiver.blinded_value();
                p.push(pmnt.qty);
                p.push(pmnt.flv);

                if let Some(crw) = &maybe_change_receiver_witness {
                    let change = crw.receiver.blinded_value();
                    p.push(change.qty);
                    p.push(change.flv);
                }

                p.cloak(
                    spent_utxos.len(),
                    maybe_change_receiver_witness
                        .as_ref()
                        .map(|_| 2)
                        .unwrap_or(1),
                );

                p.push(payment_receiver.predicate());
                p.output(1);

                if let Some(crw) = &maybe_change_receiver_witness {
                    p.push(crw.receiver.predicate());
                    p.output(1);
                }
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
        let txid = utx.txid;

        // Alice sends ReceiverReply to Bob with contract's anchor.
        // Determine the payment contract's anchor and send it to Bob via ReceiverReply

        // Collect all anchors for outputs.
        let mut iterator = utx.txlog.iter().filter_map(|e| match e {
            TxEntry::Output(contract) => Some(contract.anchor),
            _ => None,
        });

        let payment_anchor = iterator
            .next()
            .expect("We have just built the outputs above.");

        let maybe_change_utxo = maybe_change_receiver_witness.map(|crw| {
            let change_anchor = iterator
                .next()
                .expect("We have just built the outputs above.");
            Utxo {
                receiver: crw.receiver,
                anchor: change_anchor,
                sequence: crw.sequence,
                proof: utreexo::Proof::Transient,
            }
        });

        let reply = accounts::ReceiverReply {
            receiver_id: payment_receiver.id(),
            anchor: payment_anchor,
        };

        // Sign the tx.
        let tx = {
            let mut signtx_transcript = merlin::Transcript::new(b"ZkVM.signtx");
            signtx_transcript.append_message(b"txid", &utx.txid.0);

            // Derive individual signing keys for each input, according to its sequence number.
            // In this example all inputs are coming from the same account (same xpub).
            let signing_keys = spent_utxos
                .iter()
                .map(|utxo| self.xprv.key_at_sequence(utxo.sequence))
                .collect::<Vec<_>>();

            let sig = musig::Signature::sign_multi(
                &signing_keys[..],
                utx.signing_instructions.clone(),
                &mut signtx_transcript,
            )
            .unwrap();

            utx.sign(sig)
        };

        let utxo_proofs = spent_utxos
            .iter()
            .map(|utxo| utxo.proof.clone())
            .collect::<Vec<_>>();

        let contract_ids = spent_utxos
            .iter()
            .map(|utxo| utxo.contract_id())
            .collect::<Vec<_>>();

        // Mark all spent utxos.
        for cid in contract_ids.iter() {
            self.spend_utxo(*cid);
        }

        // Save the change utxo
        if let Some(change_utxo) = maybe_change_utxo {
            // Save the change utxo - it is spendable right away, via a chain of unconfirmed txs.
            // FIXME: Strictly speaking, this is an "Incoming" utxo because we haven't yet published tx,
            // but we currently don't do persistent changes when new txs land in a mempool,
            // so if we mark it as Incoming, we won't be able to spend it until it's confirmed in a block.
            // WARNING: This will cause an issue if the tx is not going to get into mempool.
            //          However, it's similar to having mempool cleared -
            //          we need a proper solution to rollback utxo storage when some
            //          txs get fail to get into block.
            self.utxos.push(change_utxo.received());
        }

        // Remember the outgoing payment
        self.utxos.push(
            Utxo {
                receiver: payment_receiver.clone(),
                anchor: reply.anchor,
                sequence: 0,
                proof: utreexo::Proof::Transient,
            }
            .outgoing(),
        );

        Ok((tx, txid, utxo_proofs, reply))
    }

    /// Converts the wallet to a JSON object
    pub fn to_json(&self) -> JsonValue {
        json::to_json_value(&self)
    }
}

// impl AnnotatedTx {
//     pub fn tx_details(&self, assets: &[AssetRecord]) -> JsonValue {
//         let precomputed_tx = self
//             .raw_tx
//             .precompute()
//             .expect("Our blockchain does not have invalid transactions.");

//         json!({
//             "block_height": self.block_height,
//             "generic_tx": BlockRecord::tx_details(&self.raw_tx),
//             "inputs": &precomputed_tx.log.iter().enumerate().filter_map(|(i,e)| {
//                 e.as_input().map(|cid| {
//                     self.annotated_entry(i, cid, assets)
//                 })
//             })
//             .collect::<Vec<_>>(),

//             "outputs": &precomputed_tx.log.iter().enumerate().filter_map(|(i,e)| {
//                 e.as_output().map(|c| {
//                     self.annotated_entry(i, c.id(), assets)
//                 })
//             })
//             .collect::<Vec<_>>(),
//         })
//     }

//     fn find_known_value(&self, entry_index: usize) -> Option<ClearValue> {
//         self.known_entries
//             .iter()
//             .find(|&(i, _)| *i == entry_index)
//             .map(|(_, value)| *value)
//     }

//     fn annotated_entry(
//         &self,
//         entry_index: usize,
//         cid: ContractID,
//         assets: &[AssetRecord],
//     ) -> JsonValue {
//         json!({
//             "id": &util::to_json_value(&cid),
//             "value": self.find_known_value(entry_index).map(|value| {
//                 // If found a known entry, find asset alias for its flavor.
//                 let maybe_alias = assets
//                     .iter()
//                     .find(|&asset| asset.flavor() == value.flv)
//                     .map(|x| x.alias.clone());
//                 json!({
//                     "qty": value.qty,
//                     "flv": &util::to_json_value(&value.flv),
//                     "alias": maybe_alias
//                 })
//             })
//         })
//     }
// }

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
        ReceiverWitness {
            sequence: self.sequence,
            receiver: self.receiver.clone(),
        }
        .contract(self.anchor)
    }
    /// Returns the UTXO ID
    pub fn contract_id(&self) -> ContractID {
        self.contract().id()
    }

    pub fn value(&self) -> ClearValue {
        self.receiver.value
    }

    pub fn outgoing(self) -> UtxoWithStatus {
        UtxoWithStatus {
            status: UtxoStatus::Outgoing,
            utxo: self,
        }
    }

    pub fn incoming(self) -> UtxoWithStatus {
        UtxoWithStatus {
            status: UtxoStatus::Incoming,
            utxo: self,
        }
    }

    pub fn received(self) -> UtxoWithStatus {
        UtxoWithStatus {
            status: UtxoStatus::Received,
            utxo: self,
        }
    }
}

impl UtxoWithStatus {
    pub fn value(&self) -> ClearValue {
        self.any_utxo().value()
    }

    /// Convert utxo to a Contract instance
    pub fn contract(&self) -> Contract {
        self.any_utxo().contract()
    }

    /// Returns the UTXO ID
    pub fn contract_id(&self) -> ContractID {
        self.any_utxo().contract_id()
    }

    pub fn mark_as_spent(&mut self) {
        self.status = UtxoStatus::Spent;
    }

    pub fn mark_incoming_as_received(&mut self) {
        match self.status {
            UtxoStatus::Incoming => {
                self.status = UtxoStatus::Received;
            }
            UtxoStatus::Received => {}
            UtxoStatus::Spent => {}
            UtxoStatus::Outgoing => {}
        }
    }

    pub fn into_utxo(self) -> Utxo {
        self.utxo
    }

    pub fn as_mut_utxo(&mut self) -> &mut Utxo {
        &mut self.utxo
    }

    pub fn any_utxo(&self) -> &Utxo {
        &self.utxo
    }

    /// A utxo that belongs to us, even if not spendable yet.
    pub fn our_utxo(&self) -> Option<&Utxo> {
        match self.status {
            UtxoStatus::Incoming => Some(&self.utxo),
            UtxoStatus::Received => Some(&self.utxo),
            UtxoStatus::Spent => Some(&self.utxo),
            UtxoStatus::Outgoing => None,
        }
    }

    /// A utxo that belongs to us, which is also safe to spend.
    pub fn spendable_utxo(&self) -> Option<&Utxo> {
        match self.status {
            UtxoStatus::Incoming => None,
            UtxoStatus::Received => Some(&self.utxo),
            UtxoStatus::Spent => None,
            UtxoStatus::Outgoing => None,
        }
    }

    /// A utxo that we know about, but it's not ours.
    pub fn outgoing_utxo(&self) -> Option<&Utxo> {
        match self.status {
            UtxoStatus::Incoming => None,
            UtxoStatus::Received => None,
            UtxoStatus::Spent => None,
            UtxoStatus::Outgoing => Some(&self.utxo),
        }
    }
}

