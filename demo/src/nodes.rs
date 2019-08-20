use bulletproofs::BulletproofGens;
use curve25519_dalek::scalar::Scalar;
use keytree::Xprv;
use serde::{Deserialize, Serialize};

use zkvm::blockchain::{Block, BlockchainState};
use zkvm::utreexo;
use zkvm::{Anchor, ClearValue, Contract, ContractID, TxEntry};

use accounts::{Account, ReceiverWitness};

use super::util;

/// The complete state of the user node: their wallet and their blockchain state.
#[derive(Clone, Serialize, Deserialize)]
pub struct Node {
    /// Current blockchain state of the node
    pub blockchain: BlockchainState,
    /// User's wallet data
    pub wallet: Wallet,
}

/// User's wallet account data
#[derive(Clone, Serialize, Deserialize)]
pub struct Wallet {
    /// Name of the account
    pub alias: String,

    /// User's root wallet key
    pub xprv: Xprv,

    /// User's account metadata
    pub account: Account,

    /// Annotated txs related to this wallet
    pub txs: Vec<AnnotatedTx>,

    /// User's balances
    pub utxos: Vec<ConfirmedUtxo>,

    /// User's pending incoming payments
    pub pending_utxos: Vec<PendingUtxo>,
}

/// UTXO that has not been confirmed yet. It is formed from Receiver and ReceiverReply.
/// Users convert pending utxos into ConfirmedUtxo when they detect the output in the blockchain.
#[derive(Clone, Serialize, Deserialize)]
pub struct PendingUtxo {
    receiver_witness: ReceiverWitness,
    anchor: Anchor,
}

/// Stored utxo with underlying quantities, blinding factors and a utxo proof.
#[derive(Clone, Serialize, Deserialize)]
pub struct ConfirmedUtxo {
    receiver_witness: ReceiverWitness,
    anchor: Anchor,
    proof: utreexo::Proof,
}

/// Tx annotated with 
#[derive(Clone, Serialize, Deserialize)]
pub struct AnnotatedTx {
    raw_tx: zkvm::Tx,
    known_inputs: Vec<(usize, ConfirmedUtxo)>,
    known_outputs: Vec<(usize, ConfirmedUtxo)>,
}

impl Node {
    /// Creates a new node
    pub fn new(alias: impl Into<String>, blockchain: BlockchainState) -> Self {
        Node {
            blockchain,
            wallet: Wallet::new(alias),
        }
    }

    /// Processes a block: detects spends, new outputs and updates utxo proofs.
    pub fn process_block(&mut self, block: &Block, bp_gens: &BulletproofGens) {
        // 9. Alice/Bob process blockchain:
        //     a. SPV nodes:
        //        1. Network sends to Bob and Alice new blockheader and a changeset:
        //           - added utxo IDs,
        //           - merkle proof set (combined in one tree when optimized) for all deleted utxo ids.
        //        2. Alice/Bob apply changes, producing a new utreexo (and verifying it), and a catchup struct.
        //     b. Full nodes:
        //        1. Network sends to Bob and Alice new block
        //        2. Alice/Bob verify+apply changes, producing a catchup struct.
        let (verified_block, new_state) = self.blockchain.apply_block(&block, &bp_gens).unwrap();

        // In a real node utxos will be indexed by ContractID, so lookup will be more efficient.
        let hasher = utreexo::NodeHasher::new();
        for (tx_index, vtx) in verified_block.txs.iter().enumerate() {
            // FIXME: we don't need to retain utxo proofs in these utxos,
            // so PendingUtxo is a better type here, but not a good name.
            // Should rename PendingUtxo to something more close to "ProoflessUtxo".
            // Or `UtxoWitness` and `TrackedUtxo`, etc.
            let mut known_inputs = Vec::new();
            let mut known_outputs =  Vec::new();
            for (entry_index, entry) in vtx.log.iter().enumerate() {
                match entry {
                    TxEntry::Input(contract_id) => {
                        // Delete confirmed utxos
                        if let Some(i) = self
                            .wallet
                            .utxos
                            .iter()
                            .position(|utxo| utxo.contract_id() == *contract_id)
                        {
                            let spent_utxo = self.wallet.utxos.remove(i);
                            known_inputs.push((entry_index, spent_utxo));
                        }
                    }
                    TxEntry::Output(contract) => {
                        // Make pending utxos confirmed
                        let cid = contract.id();
                        if let Some(i) = self
                            .wallet
                            .pending_utxos
                            .iter()
                            .position(|utxo| utxo.contract_id() == cid)
                        {
                            let pending_utxo = self.wallet.pending_utxos.remove(i);
                            let proof = new_state.catchup.update_proof(&cid, None, &hasher).unwrap();
                            let new_utxo = pending_utxo.to_confirmed(proof);
                            self.wallet.utxos.push(new_utxo.clone());
                            known_outputs.push((entry_index, new_utxo));
                        }
                    }
                    _ => {}
                }
            }
            // If this tx has anything that has to do with this wallet, add it to the annotated txs list.
            if known_inputs.len() + known_outputs.len() > 0 {
                let raw_tx = block.txs[tx_index].clone();
                let atx = AnnotatedTx {
                    raw_tx,
                    known_inputs,
                    known_outputs,
                };
                self.wallet.txs.push(atx);
            }
        }

        // Catch up utxoproofs for all the confirmed utxos.
        let updated_proofs = self
            .wallet
            .utxos
            .iter()
            .map(|utxo| {
                new_state.catchup.update_proof(
                    &utxo.contract_id(),
                    Some(utxo.proof.clone()),
                    &hasher,
                )
            })
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        // Once all proofs are succesfully updated, apply them to our storage.
        for (p, utxo) in updated_proofs.into_iter().zip(self.wallet.utxos.iter_mut()) {
            utxo.proof = p;
        }

        // Switch the node to the new state.
        self.blockchain = new_state;
    }
}

impl Wallet {
    /// Creates a new user account with a privkey and pre-seeded collection of utxos
    pub fn new(alias: impl Into<String>) -> Self {
        let alias = alias.into();
        let xprv = util::xprv_from_string(&alias);

        Self {
            alias,
            xprv,
            account: Account::new(xprv.to_xpub()),
            txs: Vec::new(),
            utxos: Vec::new(),
            pending_utxos: Vec::new(),
        }
    }

    /// Generates a bunch of initial utxos
    pub fn mint_utxos(
        &mut self,
        mut anchor: Anchor,
        flv: Scalar,
        qtys: impl IntoIterator<Item = u64>,
    ) -> (Vec<PendingUtxo>, Anchor) {
        let mut results = Vec::new();
        for qty in qtys {
            // anchors are not unique, but it's irrelevant for this test
            anchor = anchor.ratchet();

            let receiver_witness = self.account.generate_receiver(ClearValue { qty, flv });

            results.push(PendingUtxo {
                receiver_witness,
                anchor,
            });
        }
        (results, anchor)
    }
}

impl AsRef<ClearValue> for ConfirmedUtxo {
    fn as_ref(&self) -> &ClearValue {
        &self.receiver_witness.receiver.value
    }
}

impl PendingUtxo {
    /// Convert utxo to a Contract instance
    pub fn contract(&self) -> Contract {
        self.receiver_witness.contract(self.anchor)
    }

    /// Returns the UTXO ID
    pub fn contract_id(&self) -> ContractID {
        self.contract().id()
    }

    /// Converts pending utxo into stored utxo
    pub fn to_confirmed(self, proof: utreexo::Proof) -> ConfirmedUtxo {
        ConfirmedUtxo {
            receiver_witness: self.receiver_witness,
            anchor: self.anchor,
            proof,
        }
    }
}

impl ConfirmedUtxo {
    /// Convert utxo to a Contract instance
    pub fn contract(&self) -> Contract {
        self.receiver_witness.contract(self.anchor)
    }

    /// Returns the UTXO ID
    pub fn contract_id(&self) -> ContractID {
        self.contract().id()
    }
}
