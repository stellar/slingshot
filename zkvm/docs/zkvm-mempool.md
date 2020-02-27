# ZkVM mempool

## Background

**Memory pool** is a data structure maintained by each peer for managing _unconfirmed transactions_. It decides which transactions to accept from other peers and relay further.

Generally, transactions are sorted by _feerate_: the amount of fees paid per byte. Nodes choose some reasonable limits for their mempool sizes. As mempool becomes full, lowest-paying transactions are **evicted** from it. When a new block is created, it takes the highest-paying transactions. When nodes see a new block, they **clear** their mempools, removing confirmed transactions.

What if transaction does not pay high enough fee? At best it’s not going to be relayed anywhere.
At worst, it’s going to be relayed and dropped by some nodes, and relayed again by others, etc.

This situation poses two problems:

1. **Denial of service risk:** low-fee transactions that barely make it to the mempool can get re-relayed many times over, consuming bandwidth of the network, while the same fee is amortized over all the relay cycles, lowering the cost of attack.
2. **Stuck transactions:** as nodes reject double-spend attempts, user may have to wait indefinitely until his low-fee transaction is either completely forgotten or finally published in a block.

There are two ways to address stuck transactions:

1. Replace the transaction with another one, spending the same outputs, but with a higher fee. This is known as **replace-by-fee** (RBF). This method has a practical downside to the user: one need to re-communicate blinding factors with the recipient when making an alternative tx. So in this implementation we do not support RBF at all.
2. Create a chained transaction that pays a higher fee to cover for itself and for the parent. This is known as **child pays for parent** (CPFP). This is implemented here.

The DoS risk is primarily limited by requiring transactions pay not only for themselves, but also for
the cost of relaying the transactions that are being evicted. The evicted transaction is now unlikely to be confirmed, so the cost of relaying it must be covered by some other transaction.

There is an additional problem, though. After the mempool is partially cleared by a newly published block, the previously evicted transaction may come back and will be relayed once again.
At first glance, it is not a problem because someone's transaction that cause the eviction has already paid for the first relay. However, for the creator of the transaction potentially unlimited number of relays comes at a constant (low) cost. This means, the network may have to relay twice as much traffic due to such bouncing transactions, and the actual users of the network may need to pay twice as much.

To address this issue, we need to efficiently **remember the evicted transaction**. Then, to accept it again, we require it to have the _effective feerate_ = _minimum feerate_ + _flat feerate_. If the transaction pays by itself, it is fine to accept it again. The only transaction likely to return again and again is the one paying a very low fee, so the bump by flat feerate would force it to be paid via CPFP (parked and wait for a higher-paying child).

## Definitions

### Fee

Amount paid by the transaction using the [`fee`](zkvm-spec.md#fee) instruction.
Fee is denominated in [Values](zkvm-spec.md#value-type) with flavor ID = 0.

### Feerate

A **fee rate** is a ratio of the [fees](#fees) divided by the size of the tx in bytes (`<Tx as Encodable>::encoded_length()`).

Feerate is stored as a pair of integers `fee / size` so that feerates can be accurately [combined](#combine-feerates).

### Self feerate

A sum of all fees paid by a transaction, as reflected in the [transaction log](zkvm-spec.md#fee-entry), divided by the size of the transaction.

### Combine feerates

Operation over multiple feerates that produces an average [feerate](#feerate), preserving the total size of the transactions involved.

`Combine(feerate1, feerate2) = (fee1 + fee2) / (size1 + size2)`.

### Discount feerate

Operation over a single feerate to discount its weight when [combined](#combine-feerates) with the [parent transaction](#parent):

`Discount(feerate, n) = floor(fee/n) / floor(size/n)`

### Parent

Transaction that produced an output spent in a given transaction, which is a parent’s [child](#child).

### Child

Transaction that spends an output produced by a given transaction, which is its [parent](#parent).

### RBF

"Replace by Fee". A policy that permits replacing one transaction by another, conflicting with it (spending one or more of the same outputs), if another pays a higher [feerate](#feerate).
This mempool implementation does not support any variant of RBF.

### CPFP

"Child Pays For Parent". A policy that prioritizes transactions by [effective feerate](#effective-feerate).

### Total feerate

A [feerate](#feerate) computed as a [combination](#combine-feerates) of feerates of a transaction, all its [children](#child) and their children, recursively.

### Effective feerate

A maximum between [self feerate](#self-feerate) and [total feerate](#total-feerate).

### Flat feerate

The minimum [feerate](#feerate) that every transaction must pay to be included in the mempool. Configured per node.

### Depth

Transaction has a depth equal to the maximum of the outputs it spends.

Confirmed outputs have depth 0. 

Unconfirmed outputs have the same depth as the transaction.

```
0 ___ tx __ 1
0 ___/  \__ 1 __ tx __ 2
0 ______________/  \__ 2
```

### Maximum depth

Maximum [depth](#depth) of unconfirmed transactions allowed in the mempool. Configured per node.

### Minimum feerate

The maximum of [flat feerate](#flat-feerate) and the lowest [effective feerate](#effective-feerate) in the [mempool](#mempool), if it’s full.
For non-full mempool, it is the [flat feerate](#flat-feerate).

### Required feerate

For a given transaction and its feerate `R`, the required feerate is computed as follows:

1. Compute the [minimum feerate](#minimum-feerate) `M`.
2. If transaction is present in [eviction filter](#eviction-filter), increase `M` by an extra [flat feerate](#flat-feerate), without changing the `M.size`: `M = M.fee + M.size*flat_fee / M.size`
3. The required absolute [effective fee](#fee) (not the _feerate_) is: `M * (M.size + R.size)`.


### Mempool

A data structure that keeps a collection of transactions that are valid for inclusion in a block,
with reference to a current _tip_ and the corresponding Utreexo state.

Mempool verifies incoming transactions and evicts low-priority transactions.
Mempool always keeps transactions sorted in topological order.

Mempools are synchronized among peers, by sending the missing transactions to each other.
Duplicates are silently rejected.

### Eviction filter

Bloom filter that contains the evicted transactions and output IDs spent by them.

Given a valid transaction with ID `T` that spends a set of outputs with IDs `{C}`:

1. If `T` is in the filter: transaction is treated as previously evicted and an additional [flat feerate](#flat-feerate) is [required](#required-feerate).
2. If `T` is not in the filter, but one of output IDs `{C}` is in the filter: transaction is treated as a double spend and rejected (see also [RBF](#rbf)).
3. If neither `T`, nor `{C}` are in the filter: transaction is treated as a new one.

If the false positive occurs at step 1:
a. either an ordinary transaction is required to pay a higher fee than others,
b. or it is a double-spend attempt after eviction that’s accidentally accepted by this node.

If the false positive occurs at step 2: it is an ordinary transaction rejected from this mempool.
Other nodes have a different randomized state of bloom filter, so they are likely to relay it.

Filter is reset every 24 hours in order to keep false positive rate low.

### Peerpool

A small buffer of transactions maintained per peer, used to park transactions with insufficient feerate,
in order to wait for [children](#child) ([CPFP](#cpfp)) that make the parent’s [effective feerate](#effective-feerate) sufficient.

Transactions in the peerpool are not relayed, and are dropped when the peer disconnects.


## Procedures

### Accept transaction

1. It is validated statelessly per ZkVM rules. The peer may be deprioritized or banned if it relays an statelessly invalid transaction.
2. Timestamp is checked w.r.t. to the last block timestamp. Transactions must use generous time bounds to account for clock differences. This simplifies validation logic, as we don't need to allow windowing or check for self-consistency of unconfirmed tx chains.
3. If the tx can be applied to the peerpool, it is parked there. Effective feerates are recalculated for all ancestors. If any tx now has a sufficient effective feerate to enter the mempool, it is moved there. Children are tested and included recursively. If any tx fails to apply to main pool (double spend), it and its children are evicted from peer pool.
4. If the tx can be applied to the main pool, it is applied there. Peer pools are not updated at this point and may contain double-spends, but those have no effect because they are filtered out when a new tx enters peerpool.
5. If the mempool is not full, it must pay the **minimum flat feerate** (configured by the peer).
6. If the mempool is full, it must pay for the evicted tx: `min_feerate * (evicted_tx_size + new_tx_size)`.
7. If the `tx.maxtime` is less than mempool time +24h, an additional flat feerate is required on top of the above. This is because such transaction is more likely to expire and become invalid (unlike unbounded ones), while the network has spent bandwidth on relaying it.
8. If the tx ID is found in a bloom filter: it is treated as resurrected, and must pay the fee as calculated above, but increased by _flat feerate_. If it does not pay sufficiently, it is parked in the peerpool until CPFP happens, or the filter is reset.
9. If the tx spends an output marked in the bloom filter, but its ID is not found: it is rejected as double-spend (we don't support replace-by-fee). If a regular transaction triggers false positive in the filter (<1% risk), it is not accepted or relayed by this node, but other >99% nodes may relay it, since all nodes initialize their filters with random seeds.


### TBD.


## Notes

The above design contains several design decisions worth pointing out:

1. **Transactions are always valid at all levels.** Orphan txs are not allowed and must be sorted out at a transport level. In the future, if we use UDP, we may implement a separate buffer in peer pools for that purpose. Similarly, the transactions are sorted in topological order, so they can be relayed in topological order.
2. **Double spends are not allowed at any level.** This is, obviously, a hard rule for the blockchain, but it also means the replace-by-fee (RBF) is not allowed in mempools. The rationale is that child-pays-for-parent (CPFP) needs to be supported anyway, and replacing confidential transactions requires update of all blinding factors, which normally means another round of communication between the wallets. Also, handling fees when RBF happens across eviction and preventing subtle DoS scenarios is trickier than simply disallow RBF. **Do not** consider this design choice as an endorsement of 0-confirmation transactions; those do not become more secure because this policy is strictly focused on protecting the node itself and does not offer any security to other nodes.
3. **Single-mode relay with peerpools.** Transactions are assumed to be simply relayed in topological order, one by one. There is no separate "package relay" for CPFP. Txs with insufficient fees are parked in a per-peer buffer until a higher-paying child arrives.
4. **Discounted child feerate.** To simplify a [NP-complete task](https://freedom-to-tinker.com/2014/10/27/bitcoin-mining-is-np-hard/) of calculating an optimal subset of tx graph, effective feerate of a parent is computed by simply combining feerates of children. In case a child has several parents, we prevent overcounting by splitting its feerate among all parents. For the most cases it does not treat txs unfairly, but allows adding up feerates in a straightforward manner.




