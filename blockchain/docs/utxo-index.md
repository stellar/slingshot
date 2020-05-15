# UTXO Index

## Goal

A common API for tracking and selecting spendable outputs, indexing unconfirmed transactions and unconfirmed outputs,
that can be used by arbitrary wallet policies.

The details of how contracts and transactions are structured are left to the upstream (wallet) protocol.

## Use case 1: making a transaction

1. select some unspent outputs,
2. form a transaction,
3. submit it to the mempool,
4. mark used outputs as spent, newly created ones as unspent,
5. watch the blockchain and update the status of all outputs and transactions: removing conflicting transactions and marking as confirmed outputs of the confirmed transactions.

## Use case 2: receive payments

1. create a contract predicate,
2. detect new transactions with outputs matching the predicate and store them as incoming payments.

## Use case 3: track utreexo proofs

1. scan a new block,
2. detect spent outputs and remove confirmed utxos,
3. apply `Catchup` structure to all the confirmed utxos to update their proofs,
4. apply `Catchup` structure to all unconfirmed utxos in attempt to update their proofs: those that became confirmed are stored as confirmed utxos.
5. re-apply all unconfirmed transactions to mempool and throw out the conflicting ones.

## Architecture

The indexing protocol is a plugin for the blockchain protocol. The plugin provides a separation between core blockchain logic of verifying the evolving blockchain state, and custom uses of it for the wallets, explorers, analysis tools etc.

Plugin is an object that receives notifications about updates to the blockchain and the mempool:

1. `did_init_node`: the plugin gets a chance to prefill the mempool with its unconfirmed transactions.
2. `did_receive_block`: the plugin receives a new block and a blockchain state, with `Catchup` structure to update proofs for its utxos.
3. `did_receive_unconfirmed_tx`: the plugin can detect incoming payments in the unconfirmed transactions.
4. `did_remove_unconfirmed_tx`: the plugin can detect when a transaction is kicked out of the mempool due to a conflict.

The state of the index consists of:

1. a set of unconfirmed transactions, with the output indices to watch,
2. a collection of confirmed unspent outputs,
3. a collection of predicates to watch, with expiration time.

## Implementation details

The relationship between the node, plugins, delegate and user is the following:

1. User must hold a reference to a Node and feed it with raw events.
2. User must hold references to individual plugins in order to update their state (e.g. add transactions to watch).
3. Node holds references to all Plugins in order to notify them about events.
4. When notified, plugins can interact with the node, say, insert transactions in the mempool.
