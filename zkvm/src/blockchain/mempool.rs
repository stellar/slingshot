//! "Memory pool" is a data structure for managing _unconfirmed transactions_.
//! It decides which transactions to accept from other peers and relay further.
//!
//! Generally, transactions are sorted by _feerate_: the amount of fees paid per byte.
//! What if transaction does not pay high enough fee? At best it’s not going to be relayed anywhere.
//! At worst, it’s going to be relayed and dropped by some nodes, and relayed again by others, etc.
//!
//! There are three ways out of this scenario:
//!
//! 1. Simply wait longer until the transaction gets published.
//!    Once a year, when everyone goes on vacation, the network gets less loaded and your transaction may get its slot.
//! 2. Replace the transaction with another one, with a higher fee. This is known as "replace-by-fee" (RBF).
//!    This has a practical downside: one need to re-communicate blinding factors with the recipient when making an alternative tx.
//! 3. Create a chained transaction that pays a higher fee to cover for itself and for the parent.
//!    This is known as "child pays for parent" (CPFP).
//!
//! In this implementation we are implementing a CPFP strategy
//! to make prioritization more accurate and allow users "unstuck" their transactions.
//!
use crate::ContractID; //, TxEntry, TxHeader, TxLog, VerifiedTx};
use crate::FeeRate;
use crate::VerifiedTx;
use core::cell::RefCell;
use std::borrow::Borrow;
use std::collections::HashMap;
use std::ops::{Deref, DerefMut};
use std::rc::Rc;

use super::errors::BlockchainError;
use super::state::BlockchainState;
use crate::merkle::Hasher;
use crate::tx::{TxEntry, TxLog};
use crate::utreexo;

/// Main API to the memory pool.
pub struct Mempool<Tx: MempoolTx> {
    /// Current blockchain state.
    state: BlockchainState,

    /// State of confirmed outputs.
    work_utreexo: utreexo::WorkForest,

    /// State of available outputs.
    utxos: HashMap<ContractID, UtxoStatus<Tx>>,

    /// Tx with the lowest feerate. None when the mempool is empty.
    lowest_tx: Option<Ref<Tx>>,

    /// Total size of the mempool.
    current_size: usize,

    /// Maximum allowed size of the mempool.
    max_size: usize,

    /// Current timestamp.
    timestamp_ms: u64,
}

/// Trait for the items in the mempool.
pub trait MempoolTx {
    /// Returns a reference to a verified transaction
    fn verified_tx(&self) -> &VerifiedTx;

    /// Returns a collection of Utreexo proofs for the transaction.
    fn utreexo_proofs(&self) -> &[utreexo::Proof];

    fn txlog(&self) -> &TxLog {
        &self.verified_tx().log
    }

    fn feerate(&self) -> FeeRate {
        self.verified_tx().feerate
    }
}

/// Small per-peer LRU buffer where low-fee transactions are parked
/// until they are either kicked out, or get promoted to mempool due to CPFP.
/// All the changes to mempool are made through this peer pool, so
/// the transactions can be parked and unparked from there.
pub struct Peerpool {
    // TODO: add the peer pool later and for now add txs directly to mempool.
}

/// Reference-counted reference to a transaction.
struct Ref<Tx: MempoolTx> {
    inner: Rc<RefCell<Node<Tx>>>,
}

enum Input<Tx: MempoolTx> {
    /// Input is marked as confirmed - we don't really care where in utreexo it is.
    Confirmed,
    /// Parent tx and an index in parent.outputs list.
    Unconfirmed(Ref<Tx>, usize),
}

enum Output<Tx: MempoolTx> {
    /// Currently unoccupied output.
    Unspent,

    /// Child transaction and an index in child.inputs list.
    Spent(Ref<Tx>, usize),
}

struct Node<Tx: MempoolTx> {
    tx: Tx,

    total_feerate: FeeRate,
    // list of inputs - always fully initialized
    inputs: Vec<Input<Tx>>,
    // list of outputs - always fully initialized
    outputs: Vec<Output<Tx>>,

    // doubly-linked list to lower-feerate and higher-feerate txs.
    // ø ø - tx is outside the mempool (e.g. in PeerPool)
    // x ø - tx is the highest-paying
    // x x - tx is in the middle of a list
    // ø x - tx is the lowest-paying
    lower: Option<Ref<Tx>>,
    higher: Option<Ref<Tx>>,
}

impl<Tx: MempoolTx> Mempool<Tx> {
    /// Creates a new mempool with the given size limit, timestamp
    pub fn new(max_size: usize, state: BlockchainState, timestamp_ms: u64) -> Self {
        let work_utreexo = state.utreexo.work_forest();
        Mempool {
            state,
            work_utreexo,
            utxos: HashMap::new(),
            lowest_tx: None,
            current_size: 0,
            max_size,
            timestamp_ms,
        }
    }

    /// The fee paid by an incoming tx must cover with the minimum feerate both
    /// the size of the incoming tx and the size of the evicted tx:
    ///
    /// new_fee ≥ min_feerate * (evicted_size + new_size).
    ///
    /// This method returns the effective feerate of the lowest-priority tx,
    /// which also contains the total size that must be accounted for.
    pub fn min_feerate(&self) -> FeeRate {
        self.lowest_tx
            .as_ref()
            .map(|r| r.borrow().effective_feerate())
            .unwrap_or(FeeRate::zero())
    }

    /// Add a transaction.
    /// Fails if the transaction attempts to spend a non-existent output.
    /// Does not check the feerate.
    fn append(&mut self, item: Tx) -> Result<(), BlockchainError> {
        unimplemented!()
    }

    /// Removes the lowest-feerate transactions to reduce the size of the mempool to the maximum allowed.
    /// User may provide a buffer that implements Extend to collect and inspect all evicted transactions.
    fn compact(&mut self, evicted_txs: impl core::iter::Extend<Tx>) {
        unimplemented!()
    }
}

impl<Tx: MempoolTx> Node<Tx> {
    fn self_feerate(&self) -> FeeRate {
        self.tx.feerate()
    }

    fn effective_feerate(&self) -> FeeRate {
        core::cmp::max(self.self_feerate(), self.total_feerate)
    }

    fn into_ref(self) -> Ref<Tx> {
        Ref {
            inner: Rc::new(RefCell::new(self)),
        }
    }
}

/// The fee paid by an incoming tx must cover with the minimum feerate both
/// the size of the incoming tx and the size of the evicted tx:
///
/// `new_fee > min_feerate * (evicted_size + new_size)`
///
/// This method returns the effective feerate of the lowest-priority tx,
/// which also contains the total size that must be accounted for.
///
/// This is equivalent to:
///
/// `new_fee*evicted_size > min_fee * (evicted_size + new_size)`
///
fn is_feerate_sufficient(feerate: FeeRate, min_feerate: FeeRate) -> bool {
    let evicted_size = min_feerate.size() as u64;
    feerate.fee() * evicted_size > min_feerate.fee() * (evicted_size + (feerate.size() as u64))
}

/// Attempts to apply transaction changes
fn apply_tx<'a, 'b, Tx: MempoolTx>(
    tx: Tx,
    utreexo: &utreexo::Forest,
    utxo_view: &mut UtxoView<'a, 'b, Tx>,
    hasher: &Hasher<ContractID>,
) -> Result<Ref<Tx>, BlockchainError> {
    let mut utreexo_proofs = tx.utreexo_proofs().iter();

    // Start by collecting the inputs and
    let inputs = tx
        .txlog()
        .inputs()
        .map(|cid| {
            let utxoproof = utreexo_proofs
                .next()
                .ok_or(BlockchainError::UtreexoProofMissing)?;

            match (utxo_view.get(cid).into_option(), utxoproof) {
                (Some(UtxoStatus::UnconfirmedUnspent(srctx, i)), _proof) => {
                    Ok(Input::Unconfirmed(srctx.clone(), *i))
                }
                (Some(_), _proof) => Err(BlockchainError::InvalidUnconfirmedOutput),
                (None, utreexo::Proof::Committed(path)) => {
                    // check the path
                    utreexo
                        .verify(cid, path, hasher)
                        .map_err(|e| BlockchainError::UtreexoError(e))?;
                    Ok(Input::Confirmed)
                }
                (None, utreexo::Proof::Transient) => Err(BlockchainError::UtreexoProofMissing),
            }
        })
        .collect::<Result<Vec<_>, _>>()?;

    let outputs = tx
        .txlog()
        .outputs()
        .map(|_| Output::Unspent)
        .collect::<Vec<_>>();

    let new_ref = Node {
        total_feerate: tx.feerate(),
        inputs,
        outputs,
        lower: None, // will be connected by the caller
        higher: None,
        tx,
    }
    .into_ref();

    // At this point the spending was checked, so we can do mutating changes.
    // 1. If we are spending an unconfirmed tx in the front of the view - we can link it back to
    //    its child. If it's in the back, we should not link.
    // 2. For each input we should store a "spent" status into the UtxoView.
    // 3. for each output we should store an "unspent" status into the utxoview.
    for (input_index, cid) in new_ref.borrow().tx.txlog().inputs().enumerate() {
        // if the spent output is unconfirmed in the front of the view - modify it to link.
        if let Some(UtxoStatus::UnconfirmedUnspent(srctx, output_index)) =
            utxo_view.get(cid).front_value()
        {
            srctx.borrow_mut().outputs[*output_index] = Output::Spent(new_ref.clone(), input_index);
        }
    }

    for (input_status, cid) in new_ref
        .borrow()
        .inputs
        .iter()
        .zip(new_ref.borrow().tx.txlog().inputs())
    {
        let status = match input_status {
            Input::Confirmed => UtxoStatus::ConfirmedSpent,
            Input::Unconfirmed(_, _) => UtxoStatus::UnconfirmedSpent,
        };
        utxo_view.set(*cid, status);
    }

    for (i, cid) in new_ref
        .borrow()
        .tx
        .txlog()
        .outputs()
        .map(|c| c.id())
        .enumerate()
    {
        utxo_view.set(cid, UtxoStatus::UnconfirmedUnspent(new_ref.clone(), i));
    }

    Ok(new_ref)
}

/// Status of the utxo cached by the mempool
enum UtxoStatus<Tx: MempoolTx> {
    /// unspent output originating from the i'th output in the given unconfirmed tx
    UnconfirmedUnspent(Ref<Tx>, usize),

    /// unconfirmed output is spent by another unconfirmed tx
    UnconfirmedSpent,

    /// spent output stored in utreexo
    ConfirmedSpent,
}

struct UtxoView<'a, 'b: 'a, Tx: MempoolTx> {
    hashmap: &'a mut HashMap<ContractID, UtxoStatus<Tx>>,
    backing: Option<&'b HashMap<ContractID, UtxoStatus<Tx>>>,
}

impl<Tx: MempoolTx> UtxoStatus<Tx> {
    fn is_unconfirmed_spent(&self) -> bool {
        match self {
            UtxoStatus::UnconfirmedSpent => true,
            _ => false,
        }
    }
}

impl<Tx: MempoolTx> Ref<Tx> {
    fn borrow(&self) -> impl Deref<Target = Node<Tx>> + '_ {
        RefCell::borrow(&self.inner)
    }

    fn borrow_mut(&self) -> impl DerefMut<Target = Node<Tx>> + '_ {
        RefCell::borrow_mut(&self.inner)
    }

    fn clone(&self) -> Self {
        Ref {
            inner: self.inner.clone(),
        }
    }

    // Removes all back references from parent to children recursively,
    // and also the linkedlist references.
    // The only references remaining are forward references from children to parents,
    // that are auto-destroyed in reverse order when children are dropped.
    fn unlink(&self) {
        for out in self.borrow().outputs.iter() {
            if let Output::Spent(child, _) = out {
                child.unlink()
            }
        }
        let mut tx = self.borrow_mut();
        for out in tx.outputs.iter_mut() {
            *out = Output::Unspent;
        }
        tx.lower = None;
        tx.higher = None;
    }
}

enum ViewResult<T> {
    None,
    Front(T),
    Backing(T),
}

impl<T> ViewResult<T> {
    fn into_option(self) -> Option<T> {
        match self {
            ViewResult::None => None,
            ViewResult::Front(x) => Some(x),
            ViewResult::Backing(x) => Some(x),
        }
    }

    fn front_value(self) -> Option<T> {
        match self {
            ViewResult::Front(x) => Some(x),
            _ => None,
        }
    }
}

impl<'a, 'b: 'a, Tx: MempoolTx> UtxoView<'a, 'b, Tx> {
    fn get(&self, contract_id: &ContractID) -> ViewResult<&UtxoStatus<Tx>> {
        let front = self.hashmap.get(contract_id);
        if let Some(x) = front {
            ViewResult::Front(x)
        } else if let Some(x) = self.backing.and_then(|b| b.get(contract_id)) {
            ViewResult::Backing(x)
        } else {
            ViewResult::None
        }
    }
    fn set(&mut self, contract_id: ContractID, status: UtxoStatus<Tx>) -> Option<UtxoStatus<Tx>> {
        // If backing is None and we are storing UnconfirmedSpent, we simply remove the existing item.
        // In such case we are operating on the root storage, where we don't even need to store the spent status of the utxos.
        if self.backing.is_none() && status.is_unconfirmed_spent() {
            return self.hashmap.remove(&contract_id);
        }
        self.hashmap.insert(contract_id, status)
    }
}
