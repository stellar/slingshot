# UTXO Indexing Protocol

## Background

The goal of the protocol is to provide a common API for tracking and selecting spendable outputs,
indexing unconfirmed transactions and unconfirmed outputs,
that can be used by arbitrary wallet policies.

In order to make a ZkVM transaction, the user has to:

1. select some unspent outputs,
2. form a transaction,
3. submit it to the mempool,
4. mark used outputs as spent, newly created ones as unspent,
5. watch the blockchain and update the status of all outputs and transactions: removing conflicting transactions and marking as confirmed outputs of the confirmed transactions.

To detect incoming payments, the user has to:

1. create a contract predicate,
2. detect new transactions with outputs matching the predicate and store them as incoming payments,

The protocol we describe here focuses on managing the state of transactions and outputs,
leaving concrete details of how contracts and transactions are structured to the upstream protocols.

There are two API layers with the same functionality: 

1. an embedded API with abstract storage interface (similar to `blockchain::protocol`), 
2. a concrete RPC API to be used from other processes. 

## Operations

