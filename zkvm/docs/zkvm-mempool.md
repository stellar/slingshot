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

### Orphan

Transaction that spends an output that does not exist.

Orphans may be received because requests for transactions are spread evenly among the peers and can arrive in random order.
This offers a better use of bandwidth and simpler synchronization logic, but requires the node
to track orphan transactions separately in [peerpools](#peerpool).


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

### Peerpool

A small buffer of transactions maintained per peer, used to park transactions with insufficient feerate (waiting for higher-paying [children](#child)) or [orphans](#orphan), waiting for [parents](#parent).

Transactions in the peerpool are not relayed, and are dropped when the peer disconnects.


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


## Procedures

### Accept to mempool

**Transaction is validated statelessly per ZkVM rules.** The peer may be deprioritized or banned if it relays a statelessly invalid transaction.

**Time bounds are checked against to the tip block timestamp.**
Transactions must use generous time bounds to account for clock differences.
This simplifies validation logic, as we don't need to allow windowing or check for self-consistency of unconfirmed tx chains.

**Transaction is checked against [eviction filter](#eviction-filter).**
If it is a double-spend, it is rejected.
If it is coming back after eviction, a [required feerate](#required-feerate) is increased by [flat feerate](#flat-feerate).

**If transaction expires soon** (`tx.maxtime` is less than tip timestamp + 24 hours), an additional [flat feerate](#flat-feerate) is required on top of the above.
This is because such transaction is more likely to expire and become invalid (unlike unbounded ones), while the network will have spent bandwidth on relaying it.

**Transaction feerate is checked** against the [required feerate](#required-feerate).
If it is insufficient, transaction is [accepted to peerpool](#accept-to-peerpool) or discarded.

**Transaction is applied to the mempool state.**
If any output is already spent, transaction is discarded.
If any output is missing, transaction is [accepted to peerpool](#accept-to-peerpool) or discarded.
If transaction’s depth is higher than [maximum depth](#maximum-depth), reject transaction.

Once transaction is added to the mempool state, [effective feerates](#effective-feerate) of its [ancestors](#parent) are recomputed.

**If the mempool size exceeds the maximum size**, a transaction with the lowest effective feerate is evicted, together with all its [descendants](#child).
The procedure repeats until the mempool size is lower than the maximum size.

**Add to the [eviction filter](#eviction-filter)** IDs of the evicted transactions and the IDs of the outputs they were spending.


### Accept to peerpool

If transaction’s depth is higher than [maximum depth](#maximum-depth), reject transaction.

Check if transaction spends inputs correctly. If any output is spent or does not exist, reject transaction.

Recompute effective feerates of ancestors of the newly inserted transaction.
If any passes the required feerate (considering eviction filter and maxtime),
move it and all its descendants with higher effective feerate than the parent’s to the mempool.

While the peerpool size exceeds the maximum, remove the oldest (FIFO) transaction and all its descendants.


### Relaying transactions

A node periodically announces a set of its transactions to all the neighbours by transmitting a list of recently received transaction IDs.

When a list of IDs is received from a peer, node detects IDs that are missing in its mempool and remembers them (per peer).

Periodically, node sends out requests for transactions. It goes in round-robin, and collects lists of transactions, avoiding request for the transactions it already assigned per node.
Then, requests are sent out to all peers.

## Notes

The above design contains several design decisions worth pointing out:

1. **Double spends are not allowed at any level.** This is, obviously, a hard rule for the blockchain, but it also means the replace-by-fee (RBF) is not allowed in mempools. The rationale is that child-pays-for-parent (CPFP) needs to be supported anyway, and replacing confidential transactions requires update of all blinding factors, which normally means another round of communication between the wallets. Also, handling fees when RBF happens across eviction and preventing subtle DoS scenarios is trickier than simply disallow RBF. **Do not** consider this design choice as an endorsement of 0-confirmation transactions; those do not become more secure because this policy is strictly focused on protecting the node itself and does not offer any security to other nodes.
2. **Single-mode relay with peerpools.** Transactions are assumed to be simply relayed in topological order, one by one. There is no separate "package relay" for CPFP. Txs with insufficient fees are parked in a per-peer buffer until a higher-paying child arrives.
3. **Discounted child feerate.** To simplify a [NP-complete task](https://freedom-to-tinker.com/2014/10/27/bitcoin-mining-is-np-hard/) of calculating an optimal subset of tx graph, effective feerate of a parent is computed by simply combining feerates of children. In case a child has several parents, we prevent overcounting by splitting its feerate among all parents. For the most cases it does not treat txs unfairly, but allows adding up feerates in a straightforward manner.




