use merlin::Transcript;
use rand::SeedableRng;
use rand_chacha::ChaChaRng;
use serde::{Deserialize, Serialize};
use bulletproofs::BulletproofGens;
use curve25519_dalek::scalar::Scalar;
use keytree::Xprv;
use musig::Signature;

use zkvm::blockchain::{Block, BlockchainState};
use zkvm::utreexo;
use zkvm::{Anchor, ClearValue, Contract, ContractID, Program, Prover, TxEntry, TxHeader};

use accounts::{Account, ReceiverReply, ReceiverWitness};

use super::schema::*;

// Stored data

#[derive(Debug,Queryable,Insertable)]
pub struct BlockRecord {
    pub height: i32, // FIXME: diesel doesn't allow u64 here...
    pub block_json: String,
    pub state_json: String, // latest state will be used for *the* network state
}

#[derive(Debug,Queryable,Insertable)]
pub struct AssetRecord {
    pub alias: String,
    pub xprv_json: String,
}

#[derive(Debug,Queryable,Insertable)]
pub struct NodeRecord {
    pub alias: String,
    pub state_json: String,
}




/// The complete state of the user node: their wallet and their blockchain state.
#[derive(Clone, Serialize, Deserialize)]
struct Node {
    /// Current blockchain state of the node
    blockchain: BlockchainState,
    /// User's wallet data
    wallet: Wallet,
}

/// User's wallet account data
#[derive(Clone, Serialize, Deserialize)]
struct Wallet {
    /// User's root wallet key
    xprv: Xprv,

    /// User's account metadata
    account: Account,

    /// User's balances
    utxos: Vec<ConfirmedUtxo>,

    /// User's pending incoming payments
    pending_utxos: Vec<PendingUtxo>,
}

/// UTXO that has not been confirmed yet. It is formed from Receiver and ReceiverReply.
/// Users convert pending utxos into ConfirmedUtxo when they detect the output in the blockchain.
#[derive(Clone, Serialize, Deserialize)]
struct PendingUtxo {
    receiver_witness: ReceiverWitness,
    anchor: Anchor,
}

/// Stored utxo with underlying quantities, blinding factors and a utxo proof.
#[derive(Clone, Serialize, Deserialize)]
struct ConfirmedUtxo {
    receiver_witness: ReceiverWitness,
    anchor: Anchor,
    proof: utreexo::Proof,
}

/// Processes a block
fn process_block(node: &mut Node, block: &Block, bp_gens: &BulletproofGens) {
    // 9. Alice/Bob process blockchain:
    //     a. SPV nodes:
    //        1. Network sends to Bob and Alice new blockheader and a changeset:
    //           - added utxo IDs,
    //           - merkle proof set (combined in one tree when optimized) for all deleted utxo ids.
    //        2. Alice/Bob apply changes, producing a new utreexo (and verifying it), and a catchup struct.
    //     b. Full nodes:
    //        1. Network sends to Bob and Alice new block
    //        2. Alice/Bob verify+apply changes, producing a catchup struct.
    let (verified_block, new_state) = node.blockchain.apply_block(&block, &bp_gens).unwrap();

    // In a real node utxos will be indexed by ContractID, so lookup will be more efficient.
    let hasher = utreexo::NodeHasher::new();
    for entry in verified_block.entries() {
        match entry {
            TxEntry::Input(contract_id) => {
                // Delete confirmed utxos
                if let Some(i) = node
                    .wallet
                    .utxos
                    .iter()
                    .position(|utxo| utxo.contract_id() == *contract_id)
                {
                    node.wallet.utxos.remove(i);
                }
            }
            TxEntry::Output(contract) => {
                // Make pending utxos confirmed
                let cid = contract.id();
                if let Some(i) = node
                    .wallet
                    .pending_utxos
                    .iter()
                    .position(|utxo| utxo.contract_id() == cid)
                {
                    let pending_utxo = node.wallet.pending_utxos.remove(i);
                    let proof = new_state.catchup.update_proof(&cid, None, &hasher).unwrap();
                    node.wallet.utxos.push(pending_utxo.to_confirmed(proof));
                }
            }
            _ => {}
        }
    }

    // Catch up utxoproofs for all the confirmed utxos.
    let updated_proofs = node
        .wallet
        .utxos
        .iter()
        .map(|utxo| {
            new_state
                .catchup
                .update_proof(&utxo.contract_id(), Some(utxo.proof.clone()), &hasher)
        })
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    // Once all proofs are succesfully updated, apply them to our storage.
    for (p, utxo) in updated_proofs.into_iter().zip(node.wallet.utxos.iter_mut()) {
        utxo.proof = p;
    }

    // Switch the node to the new state.
    node.blockchain = new_state;
}

impl Wallet {
    /// Creates a new user account with a privkey and pre-seeded collection of utxos
    pub fn new(seed: [u8; 32]) -> Self {
        let xprv = Xprv::random(&mut ChaChaRng::from_seed(seed));

        Self {
            xprv,
            account: Account::new(xprv.to_xpub()),
            utxos: Vec::new(),
            pending_utxos: Vec::new(),
        }
    }

    /// Generates a bunch of mock utxos
    fn generate_pending_utxos(&mut self, anchor_seed: [u8; 32]) -> Vec<PendingUtxo> {
        // Create some utxos
        let mut results = Vec::new();

        let mut anchor = Anchor::from_raw_bytes(anchor_seed);

        // Create a few contracts with values of different quantities and flavors {0, 1}.
        for flv_i in 0..2u64 {
            let flv = Scalar::from(flv_i);
            for q in 0..6u64 {
                // 1, 2, 4, 8, 16, 32
                let qty = 1u64 << q;
                // anchors are not unique, but it's irrelevant for this test
                anchor = anchor.ratchet();

                let receiver_witness = self.account.generate_receiver(ClearValue { qty, flv });

                results.push(PendingUtxo {
                    receiver_witness,
                    anchor,
                });
            }
        }

        results
    }
}

impl AsRef<ClearValue> for ConfirmedUtxo {
    fn as_ref(&self) -> &ClearValue {
        &self.receiver_witness.receiver.value
    }
}

impl PendingUtxo {
    /// Convert utxo to a Contract instance
    fn contract(&self) -> Contract {
        self.receiver_witness.contract(self.anchor)
    }

    /// Returns the UTXO ID
    fn contract_id(&self) -> ContractID {
        self.contract().id()
    }

    /// Converts pending utxo into stored utxo
    fn to_confirmed(self, proof: utreexo::Proof) -> ConfirmedUtxo {
        ConfirmedUtxo {
            receiver_witness: self.receiver_witness,
            anchor: self.anchor,
            proof,
        }
    }
}

impl ConfirmedUtxo {
    /// Convert utxo to a Contract instance
    fn contract(&self) -> Contract {
        self.receiver_witness.contract(self.anchor)
    }

    /// Returns the UTXO ID
    fn contract_id(&self) -> ContractID {
        self.contract().id()
    }
}
