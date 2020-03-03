//! "Memory pool" is a data structure for managing _unconfirmed transactions_.
//! It decides which transactions to accept from other peers and relay further.
//!
//! Generally, transactions are sorted by _feerate_: the amount of fees paid per byte.
//! What if transaction does not pay high enough fee? At best it’s not going to be relayed anywhere.
//! At worst, it’s going to be relayed and dropped by some nodes, and relayed again by others, etc.
//!
//! This situation poses two problems:
//! 1. Denial of service risk: low-fee transactions that barely make it to the mempool
//!    can get re-relayed many times over, consuming bandwidth of the network,
//!    while the same fee is amortized over all the relay cycles, lowering the cost of attack.
//! 2. Stuck transactions: as nodes reject double-spend attempts, user may have to wait indefinitely
//!    until his low-fee transaction is either completely forgotten or finally published in a block.
//!
//! There are two ways to address stuck transactions:
//!
//! 1. Replace the transaction with another one, with a higher fee. This is known as "replace-by-fee" (RBF).
//!    This has a practical downside: one need to re-communicate blinding factors with the recipient when making an alternative tx.
//!    So in this implementation we do not support RBF at all.
//! 2. Create a chained transaction that pays a higher fee to cover for itself and for the parent.
//!    This is known as "child pays for parent" (CPFP). This is implemented here.
//!
//! The DoS risk is primarily limited by requiring transactions pay not only for themselves, but also for
//! the cost of relaying the transactions that are being evicted. The evicted transaction is now unlikely to be mined,
//! so the cost of relaying it must be covered by some other transaction.
//!
//! There is an additional problem, though. After the mempool is partially cleared by a newly published block,
//! the previously evicted transaction may come back and will be relayed once again.
//! At first glance, it is not a problem because someone's transaction that cause the eviction has already paid for the first relay.
//! However, for the creator of the transaction potentially unlimited number of relays comes at a constant (low) cost.
//! This means, the network may have to relay twice as much traffic due to such bouncing transactions,
//! and the actual users of the network may need to pay twice as much.
//!
//! To address this issue, we need to efficiently remember the evicted transaction. Then, to accept it again,
//! we require it to have the effective feerate = minimum feerate + flat feerate. If the transaction pays by itself,
//! it is fine to accept it again. The only transaction likely to return again and again is the one paying a very low fee,
//! so the bump by flat feerate would force it to be paid via CPFP (parked and wait for a higher-paying child).
//!
//! How do we "efficiently remember" evicted transactions? We will use a pair of bloom filters: one to
//! remember all the previously evicted tx IDs ("tx filter"), another one for all the outputs
//! that were spent by the evicted tx ("spends filter").
//! When a new transaction attempts to spend an output marked in the filter:
//! 1. If the transaction also exists in the tx filter, then it is the resurrection of a previously evicted transaction,
//!    and the usual rule with extra flat fee applies (low probablity squared that it's a false positive and we punish a legitimate tx).
//! 2. If the transaction does not exist in the tx filter, it is likely a double spend of a previously evicted tx,
//!    and we outright reject it. There is a low chance (<1%) of false positive reported by the spends filter, but
//!    if this node does not relay a legitimate transaction, other >99% nodes will since
//!    all nodes initialize filters with random keys.
//! Both filters are reset every 24h.

use core::cell::{Cell, RefCell};
use core::cmp::{max, Ordering};
use core::hash::Hash;
use core::mem;
use core::ops::{Deref, DerefMut};

use std::collections::HashMap;
use std::rc::{Rc, Weak};
use std::time::Instant;

use super::errors::BlockchainError;
use super::state::{check_tx_header, BlockchainState};
use crate::merkle::Hasher;
use crate::tx::{Tx,TxHeader,TxLog,TxID};
use crate::utreexo::{self, UtreexoError};
use crate::ContractID;
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
#[derive(Clone,Debug)]
struct MempoolTx {
    id: TxID,
    rawtx: Tx,
    utreexo_proofs: Vec<utreexo::Proof>,
    txlog: TxLog,
    feerate: FeeRate,
}

impl MempoolTx {
    fn header(&self) -> &TxHeader {
        &self.rawtx.header
    }
}

/// Configuration of the mempool.
#[derive(Clone, Debug)]
pub struct Config {
    /// Maximum size of mempool in bytes
    pub max_size: usize,

    /// Maximum size of peerpool in bytes (to fit <100 transactions)
    pub max_peerpool_size: usize,

    /// Maximum depth of unconfirmed transactions allowed.
    /// 0 means node only allows spending confirmed outputs.
    pub max_depth: usize,

    /// Minimum feerate required when the mempool is empty.
    /// Transactions paying less than this are not relayed.
    pub flat_feerate: FeeRate,
}

/// Main API to the memory pool.
pub struct Mempool2<PeerID>
where
    PeerID: Hash + Eq + Clone,
{
    /// Current blockchain state.
    state: BlockchainState,

    /// State of available outputs.
    utxos: UtxoMap,

    /// Sorted in topological order
    txs: Vec<Rc<Node>>,
    peerpools: HashMap<PeerID, Peerpool>,
    current_size: usize,
    config: Config,
    hasher: Hasher<ContractID>,
}

struct Peerpool {
    utxos: UtxoMap,
    lru: Vec<Rc<Node>>,
    current_size: usize,
}

/// Node in the tx graph.
#[derive(Debug)]
struct Node {
    // Actual transaction object managed by the mempool.
    tx: RefCell<Option<MempoolTx>>,
    // The first time the tx was seen
    seen_at: Instant,
    // Cached total feerate. None when it needs to be recomputed.
    cached_total_feerate: Cell<Option<FeeRate>>,
    // List of input statuses corresponding to tx inputs.
    inputs: Vec<RefCell<Input>>,
    // List of output statuses corresponding to tx outputs.
    outputs: Vec<RefCell<Output>>,
}

#[derive(Debug)]
enum Input {
    /// Input is marked as confirmed - we don't really care where in utreexo it is.
    /// This is also used by peerpool when spending an output from the main pool, to avoid mutating updates.
    Confirmed,
    /// Parent tx and an index in parent.outputs list.
    Unconfirmed(Rc<Node>, Index, Depth),
}

#[derive(Debug)]
enum Output {
    /// Currently unoccupied output.
    Unspent,

    /// Child transaction and an index in child.inputs list.
    /// Normally, the weakref is dropped at the same time as the strong ref, during eviction.
    Spent(Weak<Node>, Index),
}

/// Map of the utxo statuses from the contract ID to the spent/unspent status
/// of utxo and a reference to the relevant tx in the mempool.
type UtxoMap = HashMap<ContractID, UtxoStatus>;
type Depth = usize;
type Index = usize;

/// Status of the utxo cached by the mempool
enum UtxoStatus {
    /// Output is unspent and exists in the utreexo accumulator
    Confirmed,

    /// Output is unspent and is located in the i'th output in the given unconfirmed tx.
    Unconfirmed(Rc<Node>, Index, Depth),

    /// Output is marked as spent
    Spent,
}

impl<PeerID> Mempool2<PeerID>
where
    PeerID: Hash + Eq + Clone,
{
    /// Creates a new mempool with the given size limit and the current timestamp.
    pub fn new(state: BlockchainState, mut config: Config) -> Self {
        config.flat_feerate = config.flat_feerate.normalize();
        Mempool2 {
            state,
            utxos: HashMap::new(),
            ordered_txs: Vec::with_capacity(config.max_size / 2000),
            peerpools: HashMap::new(),
            current_size: 0,
            config,
            hasher: utreexo::utreexo_hasher(),
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
        let actual_min_feerate = self
            .ordered_txs
            .first()
            .and_then(|r| r.borrow().as_ref().map(|x| x.effective_feerate()))
            .unwrap_or_default();

        if self.is_full() {
            max(actual_min_feerate, self.config.flat_feerate)
        } else {
            self.config.flat_feerate
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
    pub fn is_feerate_sufficient(feerate: FeeRate, min_feerate: FeeRate) -> bool {
        let mut evicted_size = min_feerate.size() as u64;
        if evicted_size == 1 {
            // special case when we have a normalized fee.
            evicted_size = 0;
        }
        feerate.fee() * evicted_size >= min_feerate.fee() * (evicted_size + (feerate.size() as u64))
    }

    /// Adds a tx and evicts others, if needed.
    pub fn try_append(
        &mut self,
        tx: MempoolTx,
        peer_id: PeerID,
        evicted_txs: &mut impl core::iter::Extend<MempoolTx>,
    ) -> Result<(), MempoolError> {
        // TODO: check if the tx must be applied to a peerpool,
        // then add it there - it will otherwise fail in the main pool.

        if !Self::is_feerate_sufficient(tx.feerate(), self.min_feerate()) {
            // TODO: try to add to peerpool
            return Err(MempoolError::LowFee);
        }
        self.append(tx)?;
        self.compact(evicted_txs);
        Ok(())
    }

    /// Forgets peer and removes all associated parked transactions.
    pub fn forget_peer(&mut self, peer_id: PeerID) {
        self.peerpools.remove(&peer_id);
    }

    /// Add a transaction to mempool.
    /// Fails if the transaction attempts to spend a non-existent output.
    /// Does not check the feerate and does not compact the mempool.
    fn park_for_peer(&mut self, tx: MempoolTx, peer_id: PeerID) -> Result<(), MempoolError> {
        check_tx_header(
            &tx.verified_tx().header,
            self.state.tip.timestamp_ms,
            self.state.tip.version,
        )?;

        let max_depth = self.config.max_depth;
        let newtx = self
            .peerpool_view(&peer_id)
            .apply_tx(tx, max_depth, Instant::now())?;

        let pool = self.peerpools.entry(peer_id.clone()).or_default();

        // Park the tx
        pool.lru.push(newtx);

        // Find txs that become eligible for upgrade into the mempool
        // and move them there.

        return Err(MempoolError::LowFee);
    }

    /// Add a transaction to mempool.
    /// Fails if the transaction attempts to spend a non-existent output.
    /// Does not check the feerate and does not compact the mempool.
    fn append(&mut self, tx: MempoolTx) -> Result<(), MempoolError> {
        check_tx_header(
            &tx.verified_tx().header,
            self.state.tip.timestamp_ms,
            self.state.tip.version,
        )?;

        let tx_size = tx.feerate().size();
        let max_depth = self.config.max_depth;
        let newtx = self
            .mempool_view()
            .apply_tx(tx, max_depth, Instant::now())?;

        self.ordered_txs.push(newtx);
        self.order_transactions();

        self.current_size += tx_size;

        Ok(())
    }

    /// Removes the lowest-feerate transactions to reduce the size of the mempool to the maximum allowed.
    /// User may provide a buffer that implements Extend to collect and inspect all evicted transactions.
    fn compact(&mut self, evicted_txs: &mut impl core::iter::Extend<MempoolTx>) {
        while self.is_full() {
            self.evict_lowest(evicted_txs);
        }
    }

    fn is_full(&self) -> bool {
        self.current_size > self.config.max_size
    }

    fn order_transactions(&mut self) {
        self.ordered_txs
            .sort_unstable_by(|a, b| Node::optional_cmp(&a.borrow(), &b.borrow()));
    }

    /// Evicts the lowest tx and returns true if the mempool needs to be re-sorted.
    /// If we evict a single tx or a simple chain of parents and children, then this returns false.
    /// However, if there is a non-trivial graph, some adjacent tx may need their feerates recomputed,
    /// so we need to re-sort the list.
    fn evict_lowest(&mut self, evicted_txs: &mut impl core::iter::Extend<MempoolTx>) {
        if self.ordered_txs.len() == 0 {
            return;
        }

        let lowest = self.ordered_txs.remove(0);
        let (needs_reorder, total_evicted) = self.mempool_view().evict_tx(&lowest, evicted_txs);
        self.current_size -= total_evicted;

        if needs_reorder {
            self.order_transactions();
        }
    }

    fn mempool_view(&mut self) -> MempoolView<'_> {
        MempoolView {
            map: &mut self.utxos,
            utreexo: &self.state.utreexo,
            hasher: &self.hasher,
        }
    }

    fn peerpool_view(&mut self, peer_id: &PeerID) -> PeerView<'_> {
        let pool = self.peerpools.entry(peer_id.clone()).or_default();
        PeerView {
            peermap: &mut pool.utxos,
            mainmap: &self.utxos,
            utreexo: &self.state.utreexo,
            hasher: &self.hasher,
        }
    }
}

impl Default for Peerpool {
    fn default() -> Self {
        Peerpool {
            utxos: UtxoMap::new(),
            lru: Vec::new(),
            current_size: 0,
        }
    }
}

impl Node {

    fn self_feerate(&self) -> FeeRate {
        self.tx.feerate()
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

    /// The discount is a simplification that allows us to recursively add up descendants' feerates
    /// without opening a risk of overcounting in case of diamond-shaped graphs.
    /// This comes with a slight unfairness to users where a child of two parents
    /// is not contributing fully to the lower-fee parent.
    /// However, in common case this discount has no effect since the child spends only one parent.
    fn discounted_effective_feerate(&self) -> FeeRate {
        let unconfirmed_parents = self
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
        self.effective_feerate().discount(unconfirmed_parents)
    }

    fn compute_total_feerate(&self) -> FeeRate {
        // go through all children and get their effective feerate and divide it by the number of parents
        let mut result_feerate = self.self_feerate();
        for output in self.outputs.iter() {
            if let Output::Spent(childref, _) = output {
                if let Some(maybe_child) = childref.upgrade() {
                    if let Some(childtx) = maybe_child.borrow().as_ref() {
                        result_feerate =
                            result_feerate.combine(childtx.discounted_effective_feerate());
                    }
                }
            }
        }
        result_feerate
    }

    fn invalidate_cached_feerate(&self) {
        self.cached_total_feerate.set(None);
        for inp in self.inputs.iter() {
            if let Input::Unconfirmed(srcref, _, _) = inp {
                if let Some(srctx) = srcref.borrow().as_ref() {
                    srctx.invalidate_cached_feerate();
                }
            }
        }
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

    // Comparing optional nodes to account for eviction.
    // Evicted nodes naturally have lower priority.
    fn optional_cmp(a: &Option<Self>, b: &Option<Self>) -> Ordering {
        match (a, b) {
            (None, None) => Ordering::Equal,
            (Some(_), None) => Ordering::Greater,
            (None, Some(_)) => Ordering::Less,
            (Some(a), Some(b)) => a.cmp(b),
        }
    }
}

trait UtxoViewTrait {
    /// Returns the status of the utxo for the given contract ID and a utreexo proof.
    /// If the utxo status is not cached within the view,
    /// utreexo proof is used to retrieve it from utreexo.
    fn get(
        &self,
        contract_id: &ContractID,
        proof: &utreexo::Proof,
    ) -> Result<UtxoStatus, MempoolError>;

    /// Stores the status of the utxo in the view.
    fn set(&mut self, contract_id: ContractID, status: UtxoStatus);

    /// Removes the stored status
    fn remove(&mut self, contract_id: &ContractID);

    /// Attempts to apply transaction changes
    fn apply_tx(
        &mut self,
        tx: Tx,
        max_depth: Depth,
        seen_at: Instant,
    ) -> Result<Rc<Node>, MempoolError> {
        let mut utreexo_proofs = tx.utreexo_proofs().iter();

        // Start by collecting the inputs statuses and failing early if any output is spent or does not exist.
        // Important: do not perform any mutations until we check all of them.
        let inputs = tx
            .txlog()
            .inputs()
            .map(|cid| {
                let utxoproof = utreexo_proofs.next().ok_or(UtreexoError::InvalidProof)?;

                match self.get(cid, utxoproof)? {
                    UtxoStatus::Confirmed => Ok(Input::Confirmed),
                    UtxoStatus::Unconfirmed(srctx, i, depth) => {
                        Ok(Input::Unconfirmed(srctx, i, depth))
                    }
                    UtxoStatus::Spent => Err(MempoolError::InvalidUnconfirmedOutput),
                }
            })
            .collect::<Result<Vec<_>, _>>()?;

        // If this is 0, then we only spend confirmed outputs.
        // unconfirmed ones start with 1.
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

        let new_ref = Rc::new(Node {
            seen_at,
            cached_total_feerate: Cell::new(Some(tx.feerate)),
            inputs,
            outputs,
            tx,
        });

        {
            // we cannot have &Node before we pack it into a Ref,
            // so we borrow it afterwards.
            let _dummy = new_ref.borrow();
            let new_node = _dummy
                .as_ref()
                .expect("we just created it above, so it's safe to unwrap");

            // At this point the spending was checked, so we can do mutating changes.

            // 1. link parents to the children (if the weakref to the parent is not nil)
            // 2. mark spent utxos as spent
            for (input_index, (input_status, cid)) in new_node
                .inputs
                .iter()
                .zip(new_node.tx.txlog().inputs())
                .enumerate()
            {
                if let Input::Unconfirmed(srcref, output_index, _depth) = input_status {
                    if let Some(srctx) = srcref.borrow_mut().as_mut() {
                        srctx.outputs[*output_index] =
                            Output::Spent(Rc::downgrade(&new_ref), input_index);
                        srctx.invalidate_cached_feerate();
                    }
                }
                self.set(*cid, UtxoStatus::Spent);
            }

            // 3. add outputs as unspent.
            for (i, cid) in new_node.tx.txlog().outputs().map(|c| c.id()).enumerate() {
                self.set(
                    cid,
                    UtxoStatus::Unconfirmed(new_ref.clone(), i, max_spent_depth + 1),
                );
            }
        }

        Ok(new_ref)
    }

    /// Evicts tx and its subchildren recursively, updating the utxomap accordingly.
    /// Returns a flag indicating if we need to reorder txs, and the total number of bytes evicted.
    fn evict_tx(
        &mut self,
        txref: &Rc<Node>,
        evicted_txs: &mut impl core::iter::Extend<MempoolTx>,
    ) -> (bool, usize) {
        // 1. immediately mark the node as evicted, taking its Tx out of it.
        // 2. for each input: restore utxos as unspent.
        // 3. for each input: if unconfirmed and non-evicted, invalidate feerate and set the reorder flag.
        // 4. recursively evict children.
        // 5. for each output: remove utxo records.

        // TODO: if we evict a tx that's depended upon by some child parked in the peerpool -
        // maybe put it there, or update the peerpool?

        let node: Node = match txref.borrow_mut().take() {
            Some(node) => node,
            None => return (false, 0), // node is already evicted.
        };

        let mut should_reorder = false;

        for (inp, cid) in node.inputs.into_iter().zip(node.tx.txlog().inputs()) {
            match inp {
                Input::Confirmed => {
                    // remove the Spent status in the view that shadowed the Utreexo state
                    self.remove(cid);
                }
                Input::Unconfirmed(srcref, i, depth) => {
                    if let Some(src) = srcref.borrow_mut().as_mut() {
                        should_reorder = true;
                        src.invalidate_cached_feerate();
                        src.outputs[i] = Output::Unspent;
                    }
                    self.set(*cid, UtxoStatus::Unconfirmed(srcref, i, depth));
                }
            }
        }

        let mut evicted_size = node.tx.feerate().size();

        for (out, cid) in node
            .outputs
            .into_iter()
            .zip(node.tx.txlog().outputs().map(|c| c.id()))
        {
            if let Output::Spent(childweakref, _) = out {
                if let Some(childref) = childweakref.upgrade() {
                    let (reorder, size) = self.evict_tx(&childref, evicted_txs);
                    should_reorder = should_reorder || reorder;
                    evicted_size += size;
                }
            }
            // the output was marked as unspent during eviction of the child, and we simply remove it here.
            self.remove(&cid);
        }
        evicted_txs.extend(Some(node.tx));
        (should_reorder, evicted_size)
    }
}

/// View into the state of utxos.
struct MempoolView<'a> {
    map: &'a mut UtxoMap,
    utreexo: &'a utreexo::Forest,
    hasher: &'a Hasher<ContractID>,
}

/// Peer's view has its own R/W map backed by the readonly main map.
/// The peer's map shadows the main mempool map.
struct PeerView<'a> {
    peermap: &'a mut UtxoMap,
    mainmap: &'a UtxoMap,
    utreexo: &'a utreexo::Forest,
    hasher: &'a Hasher<ContractID>,
}

impl<'a> UtxoViewTrait for MempoolView<'a> {
    fn get(
        &self,
        contract_id: &ContractID,
        proof: &utreexo::Proof,
    ) -> Result<UtxoStatus, MempoolError> {
        if let Some(status) = self.map.get(contract_id) {
            Ok(status.clone())
        } else if let utreexo::Proof::Committed(path) = proof {
            self.utreexo.verify(contract_id, path, &self.hasher)?;
            Ok(UtxoStatus::Confirmed)
        } else {
            Err(MempoolError::InvalidUnconfirmedOutput)
        }
    }

    fn remove(&mut self, contract_id: &ContractID) {
        self.map.remove(contract_id);
    }

    /// Stores the status of the utxo in the view.
    fn set(&mut self, contract_id: ContractID, status: UtxoStatus) {
        // if we mark the unconfirmed output as spent, simply remove it from the map to avoid wasting space.
        // this way we'll only store spent flags for confirmed and unspent flags for unconfirmed, while
        // forgetting all intermediately consumed outputs.
        if let UtxoStatus::Spent = status {
            if let Some(UtxoStatus::Unconfirmed(_, _, _)) = self.map.get(&contract_id) {
                self.map.remove(&contract_id);
                return;
            }
        }
        self.map.insert(contract_id, status);
    }
}

impl<'a> UtxoViewTrait for PeerView<'a> {
    fn get(
        &self,
        contract_id: &ContractID,
        proof: &utreexo::Proof,
    ) -> Result<UtxoStatus, MempoolError> {
        if let Some(status) = self.peermap.get(contract_id) {
            Ok(status.clone())
        } else if let Some(status) = self.mainmap.get(contract_id) {
            // treat mainpool outputs as confirmed so we don't modify them
            Ok(match status {
                UtxoStatus::Confirmed => UtxoStatus::Confirmed,
                UtxoStatus::Spent => UtxoStatus::Spent,
                UtxoStatus::Unconfirmed(_txref, _i, _d) => UtxoStatus::Confirmed,
            })
        } else if let utreexo::Proof::Committed(path) = proof {
            self.utreexo.verify(contract_id, path, &self.hasher)?;
            Ok(UtxoStatus::Confirmed)
        } else {
            Err(MempoolError::InvalidUnconfirmedOutput)
        }
    }

    fn remove(&mut self, contract_id: &ContractID) {
        self.peermap.remove(contract_id);
    }

    fn set(&mut self, contract_id: ContractID, status: UtxoStatus) {
        self.peermap.insert(contract_id, status);
    }
}

// We are implementing the Clone manually because `#[derive(Clone)]` adds Clone bounds on `Tx`
impl Clone for UtxoStatus {
    fn clone(&self) -> Self {
        match self {
            UtxoStatus::Confirmed => UtxoStatus::Confirmed,
            UtxoStatus::Spent => UtxoStatus::Spent,
            UtxoStatus::Unconfirmed(txref, i, d) => UtxoStatus::Unconfirmed(txref.clone(), *i, *d),
        }
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
