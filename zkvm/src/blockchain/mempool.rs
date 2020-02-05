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
use core::cell::{Cell, RefCell};
use core::cmp::Ordering;
use core::hash::Hash;

use std::collections::HashMap;
use std::rc::{Rc, Weak};
use std::time::Instant;

use super::errors::BlockchainError;
use super::state::{check_tx_header, BlockchainState};
use crate::merkle::Hasher;
use crate::tx::TxLog;
use crate::utreexo::{self, UtreexoError};
use crate::ContractID; //, TxEntry, TxHeader, TxLog, VerifiedTx};
use crate::FeeRate;
use crate::VerifiedTx;

/// Mempool error conditions.
#[derive(Debug, Fail)]
pub enum MempoolError {
    /// Occurs when a blockchain check failed.
    #[fail(display = "Blockchain check failed.")]
    BlockchainError(BlockchainError),

    /// Occurs when utreexo operation failed.
    #[fail(display = "Utreexo operation failed.")]
    UtreexoError(UtreexoError),

    /// Occurs when a transaction attempts to spend a non-existent unconfirmed output.
    #[fail(display = "Transaction attempts to spend a non-existent unconfirmed output.")]
    InvalidUnconfirmedOutput,

    /// Occurs when a transaction does not have a competitive fee and cannot be included in mempool.
    #[fail(
        display = "Transaction has low fee relative to all the other transactions in the mempool."
    )]
    LowFee,

    /// Occurs when a transaction spends too long chain of unconfirmed outputs, making it expensive to handle.
    #[fail(display = "Transaction spends too long chain of unconfirmed outputs.")]
    TooDeep,
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

/// Main API to the memory pool.
pub struct Mempool2<Tx, PeerID>
where
    Tx: MempoolTx,
    PeerID: Hash + Eq,
{
    /// Current blockchain state.
    state: BlockchainState,

    /// State of available outputs.
    utxos: UtxoMap<Tx>,

    /// Transactions ordered by feerate from the lowest to the highest.
    /// Note: this list is not ordered while mempool is under max_size and
    /// re-sorted every several insertions.
    ordered_txs: Vec<Ref<Tx>>,

    /// Temporarily parked transactions
    peer_pools: HashMap<PeerID, Peerpool<Tx>>,

    /// Total size of the mempool in bytes.
    current_size: usize,

    /// Maximum allowed size of the mempool in bytes (per FeeRate.size() of individual txs).
    max_size: usize,

    /// Maximum allowed depth of the mempool (0 = can only spend confirmed outputs).
    max_depth: usize,

    /// Current timestamp.
    timestamp_ms: u64,
}

struct Peerpool<Tx: MempoolTx> {
    utxos: UtxoMap<Tx>,
    lru: Vec<Ref<Tx>>,
    max_size: usize,
    current_size: usize,
}

#[derive(Debug)]
struct Node<Tx: MempoolTx> {
    // Actual transaction object managed by the mempool.
    tx: Tx,
    //
    seen_at: Instant,
    // Cached total feerate. None when it needs to be recomputed.
    cached_total_feerate: Cell<Option<FeeRate>>,
    // List of input statuses corresponding to tx inputs.
    inputs: Vec<Input<Tx>>,
    // List of output statuses corresponding to tx outputs.
    outputs: Vec<Output<Tx>>,
}

#[derive(Debug)]
enum Input<Tx: MempoolTx> {
    /// Input is marked as confirmed - we don't really care where in utreexo it is.
    Confirmed,
    /// Parent tx and an index in parent.outputs list.
    /// Normally, the
    Unconfirmed(WeakRef<Tx>, usize, Depth),
}

#[derive(Debug)]
enum Output<Tx: MempoolTx> {
    /// Currently unoccupied output.
    Unspent,

    /// Child transaction and an index in child.inputs list.
    Spent(WeakRef<Tx>, usize),
}

type Ref<Tx> = Rc<RefCell<Node<Tx>>>;
type WeakRef<Tx> = Weak<RefCell<Node<Tx>>>;

/// Map of the utxo statuses from the contract ID to the spent/unspent status
/// of utxo and a reference to the relevant tx in the mempool.
type UtxoMap<Tx> = HashMap<ContractID, UtxoStatus<Tx>>;

/// Depth of the unconfirmed tx.
/// Mempool does not allow deep chains of unconfirmed spends to minimize DoS risk for recursive operations.
type Depth = usize;

/// Status of the utxo cached by the mempool
enum UtxoStatus<Tx: MempoolTx> {
    /// unspent output originating from the i'th output in the given unconfirmed tx.
    /// if the tx is dropped, this is considered a nonexisted output.
    UnconfirmedUnspent(WeakRef<Tx>, usize, Depth),

    /// unconfirmed output is spent by another unconfirmed tx
    UnconfirmedSpent,

    /// spent output stored in utreexo
    ConfirmedSpent,
}

impl<Tx, PeerID> Mempool2<Tx, PeerID>
where
    Tx: MempoolTx,
    PeerID: Hash + Eq,
{
    /// Creates a new mempool with the given size limit and the current timestamp.
    pub fn new(
        max_size: usize,
        max_depth: Depth,
        state: BlockchainState,
        timestamp_ms: u64,
    ) -> Self {
        Mempool2 {
            state,
            utxos: HashMap::new(),
            ordered_txs: Vec::with_capacity(max_size / 2000),
            peer_pools: HashMap::new(),
            current_size: 0,
            max_size,
            max_depth,
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
        if self.current_size < self.max_size {
            None
        } else {
            self.ordered_txs
                .first()
                .map(|r| r.borrow().effective_feerate())
        }
        .unwrap_or(FeeRate::zero())
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
    pub fn is_feerate_sufficient(feerate: FeeRate, min_feerate: FeeRate) -> bool {
        let evicted_size = min_feerate.size() as u64;
        feerate.fee() * evicted_size >= min_feerate.fee() * (evicted_size + (feerate.size() as u64))
    }

    /// Adds a tx and evicts others, if needed.
    pub fn try_append(
        &mut self,
        peer_id: PeerID,
        tx: Tx,
        evicted_txs: &mut impl core::iter::Extend<Tx>,
    ) -> Result<(), MempoolError> {
        if self.current_size >= self.max_size {
            if !Self::is_feerate_sufficient(tx.feerate(), self.min_feerate()) {
                // TODO: insert into a peer pool.
                return Err(MempoolError::LowFee);
            }
        }
        self.append(tx)?;
        self.compact(evicted_txs);
        Ok(())
    }

    /// Add a transaction.
    /// Fails if the transaction attempts to spend a non-existent output.
    /// Does not check the feerate and does not compact the mempool.
    fn append(&mut self, tx: Tx) -> Result<(), MempoolError> {
        check_tx_header(
            &tx.verified_tx().header,
            self.timestamp_ms,
            self.state.tip.version,
        )?;

        let mut utxo_view = UtxoView {
            utxomap: &mut self.utxos,
            backing: None,
        };
        let tx_size = tx.feerate().size();
        let newtx = utxo_view.apply_tx(
            tx,
            &self.state.utreexo,
            self.max_depth,
            Instant::now(),
            &utreexo::utreexo_hasher(),
        )?;

        self.ordered_txs.push(newtx);
        self.current_size += tx_size;

        Ok(())
    }

    /// Removes the lowest-feerate transactions to reduce the size of the mempool to the maximum allowed.
    /// User may provide a buffer that implements Extend to collect and inspect all evicted transactions.
    fn compact(&mut self, evicted_txs: &mut impl core::iter::Extend<Tx>) {
        // if we are not full, don't do anything, not even re-sort the list.
        if self.current_size < self.max_size {
            return;
        }

        self.order_transactions();

        // keep evicting items until we are 95% full.
        while self.current_size * 100 > self.max_size * 95 {
            self.evict_lowest(evicted_txs);
        }
    }

    fn order_transactions(&mut self) {
        self.ordered_txs
            .sort_unstable_by(|a, b| a.borrow().cmp(&b.borrow()));
    }

    /// Evicts the lowest tx and returns true if the mempool needs to be re-sorted.
    /// If we evict a single tx or a simple chain of parents and children, then this returns false.
    /// However, if there is a non-trivial graph, some adjacent tx may need their feerates recomputed,
    /// so we need to re-sort the list.
    fn evict_lowest(&mut self, evicted_txs: &mut impl core::iter::Extend<Tx>) {
        if self.ordered_txs.len() == 0 {
            return;
        }

        let lowest = self.ordered_txs.remove(0);
        let (needs_reorder, total_evicted) = Self::evict_tx(&lowest, &mut self.utxos, evicted_txs);
        self.current_size -= total_evicted;

        if needs_reorder {
            self.order_transactions();
        }
    }

    /// Evicts tx and its subchildren recursively, updating the utxomap accordingly.
    /// Returns a flag indicating that we need to reorder txs, and the total number of bytes evicted.
    fn evict_tx(
        txref: &Ref<Tx>,
        utxos: &mut UtxoMap<Tx>,
        evicted_txs: &mut impl core::iter::Extend<Tx>,
    ) -> (bool, usize) {
        // 1. immediately mark the node as evicted, taking its Tx out of it.
        // 2. for each input: restore utxos as unspent.
        // 3. for each input: if unconfirmed and non-evicted, invalidate feerate and set the reorder flag.
        // 4. recursively evict children.
        // 5. for each output: remove utxo records.

        unimplemented!()
    }
}

impl<Tx: MempoolTx> Node<Tx> {
    fn self_feerate(&self) -> FeeRate {
        self.tx.feerate()
    }

    fn into_ref(self) -> Ref<Tx> {
        Rc::new(RefCell::new(self))
    }

    fn effective_feerate(&self) -> FeeRate {
        core::cmp::max(self.self_feerate(), self.total_feerate())
    }

    fn total_feerate(&self) -> FeeRate {
        self.cached_total_feerate.get().unwrap_or_else(|| {
            let fr = self.compute_total_feerate();
            self.cached_total_feerate.set(Some(fr));
            fr
        })
    }

    fn compute_total_feerate(&self) -> FeeRate {
        // go through all children and get their effective feerate and divide it by the number of parents
        let mut result_feerate = self.self_feerate();
        for output in self.outputs.iter() {
            if let Output::Spent(childtx, _) = output {
                if let Some(childtx) = childtx.upgrade() {
                    // The discount is a simplification that allows us to recursively add up descendants' feerates
                    // without opening a risk of overcounting in case of diamond-shaped graphs.
                    // This comes with a slight unfairness to users where a child of two parents
                    // is not contributing fully to the lower-fee parent.
                    // However, in common case this discount has no effect since the child spends only one parent.
                    let unconfirmed_parents = childtx
                        .borrow()
                        .inputs
                        .iter()
                        .filter(|i| {
                            if let Input::Unconfirmed(_, _, _) = i {
                                true
                            } else {
                                false
                            }
                        })
                        .count();
                    let child_feerate = childtx
                        .borrow()
                        .effective_feerate()
                        .discount(unconfirmed_parents);
                    result_feerate = result_feerate.combine(child_feerate);
                }
            }
        }
        result_feerate
    }

    // Compares tx priorities. The Ordering::Less indicates that the transaction has lower priority.
    fn cmp(&self, other: &Self) -> Ordering {
        self.effective_feerate()
            .cmp(&other.effective_feerate())
            .then_with(|| {
                // newer txs -> lower priority
                self.seen_at.cmp(&other.seen_at).reverse()
            })
    }
}

impl<Tx: MempoolTx> UtxoStatus<Tx> {
    fn is_unconfirmed_spent(&self) -> bool {
        match self {
            UtxoStatus::UnconfirmedSpent => true,
            _ => false,
        }
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

struct UtxoView<'a, 'b: 'a, Tx: MempoolTx> {
    utxomap: &'a mut UtxoMap<Tx>,
    backing: Option<&'b UtxoMap<Tx>>,
}

impl<'a, 'b: 'a, Tx: MempoolTx> UtxoView<'a, 'b, Tx> {
    fn get(&self, contract_id: &ContractID) -> ViewResult<&UtxoStatus<Tx>> {
        let front = self.utxomap.get(contract_id);
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
            return self.utxomap.remove(&contract_id);
        }
        self.utxomap.insert(contract_id, status)
    }

    /// Attempts to apply transaction changes
    fn apply_tx(
        &mut self,
        tx: Tx,
        utreexo: &utreexo::Forest,
        max_depth: Depth,
        seen_at: Instant,
        hasher: &Hasher<ContractID>,
    ) -> Result<Ref<Tx>, MempoolError> {
        let mut utreexo_proofs = tx.utreexo_proofs().iter();

        // Start by collecting the inputs and do not perform any mutations until we check all of them.
        let inputs = tx
            .txlog()
            .inputs()
            .map(|cid| {
                let utxoproof = utreexo_proofs.next().ok_or(UtreexoError::InvalidProof)?;

                match (self.get(cid).into_option(), utxoproof) {
                    (Some(UtxoStatus::UnconfirmedUnspent(srctx, i, depth)), _proof) => {
                        match srctx.upgrade() {
                            Some(srctx) => {
                                Ok(Input::Unconfirmed(Rc::downgrade(&srctx), *i, *depth))
                            }
                            None => Err(MempoolError::InvalidUnconfirmedOutput),
                        }
                    }
                    (Some(_), _proof) => Err(MempoolError::InvalidUnconfirmedOutput),
                    (None, utreexo::Proof::Committed(path)) => {
                        // check the path
                        utreexo.verify(cid, path, hasher)?;
                        Ok(Input::Confirmed)
                    }
                    (None, utreexo::Proof::Transient) => {
                        Err(MempoolError::UtreexoError(UtreexoError::InvalidProof))
                    }
                }
            })
            .collect::<Result<Vec<_>, _>>()?;

        // if this is 0, then we only spend confirmed outputs.
        // unconfirmed start with 1.
        let max_spent_depth = inputs
            .iter()
            .map(|inp| {
                if let Input::Unconfirmed(_src, _i, depth) = inp {
                    *depth
                } else {
                    0
                }
            })
            .max()
            .unwrap_or(0);

        if max_spent_depth > max_depth {
            return Err(MempoolError::TooDeep);
        }

        let outputs = tx
            .txlog()
            .outputs()
            .map(|_| Output::Unspent)
            .collect::<Vec<_>>();

        let new_ref = Node {
            seen_at,
            cached_total_feerate: Cell::new(Some(tx.feerate())),
            inputs,
            outputs,
            tx,
        }
        .into_ref();

        // At this point the spending was checked, so we can do mutating changes.
        // 1. If we are spending an unconfirmed tx in the front of the view - we can link it back to
        //    its child. If it's in the back, we should not link.
        // 2. For each input we should store a "spent" status into the UtxoView.
        // 3. for each output we should store an "unspent" status into the utxoview.

        // 1. link to the parents if they are in the same pool.
        for (input_index, cid) in new_ref.borrow().tx.txlog().inputs().enumerate() {
            // if the spent output is unconfirmed in the front of the view - modify it to link.
            if let Some(UtxoStatus::UnconfirmedUnspent(srctx, output_index, _depth)) =
                self.get(cid).front_value()
            {
                if let Some(srctx) = srctx.upgrade() {
                    let mut srctx = srctx.borrow_mut();
                    srctx.outputs[*output_index] =
                        Output::Spent(Rc::downgrade(&new_ref), input_index);
                    srctx.cached_total_feerate.set(None);
                }
            }
        }

        // 2. mark spent utxos as spent
        for (input_status, cid) in new_ref
            .borrow()
            .inputs
            .iter()
            .zip(new_ref.borrow().tx.txlog().inputs())
        {
            let status = match input_status {
                Input::Confirmed => UtxoStatus::ConfirmedSpent,
                Input::Unconfirmed(_, _, _) => UtxoStatus::UnconfirmedSpent,
            };
            self.set(*cid, status);
        }

        // 3. add outputs as unspent.
        for (i, cid) in new_ref
            .borrow()
            .tx
            .txlog()
            .outputs()
            .map(|c| c.id())
            .enumerate()
        {
            self.set(
                cid,
                UtxoStatus::UnconfirmedUnspent(Rc::downgrade(&new_ref), i, max_spent_depth + 1),
            );
        }

        Ok(new_ref)
    }
}

impl From<BlockchainError> for MempoolError {
    fn from(err: BlockchainError) -> Self {
        MempoolError::BlockchainError(err)
    }
}

impl From<UtreexoError> for MempoolError {
    fn from(err: UtreexoError) -> Self {
        MempoolError::UtreexoError(err)
    }
}
