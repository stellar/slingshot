# ZkVM demo

How to run the demo:

```
# Install the required version of Rust (see ./rust-toolchain)
rustup install nightly-2020-05-15

# Install the database tool
cargo install diesel_cli --no-default-features --features "sqlite-bundled"

# Setup database
diesel database reset

# Run the app
ROCKET_PORT=8000 cargo run

# To run additional nodes, let OS assign a random port:
ROCKET_PORT=0 cargo run
```

## Data model

Each user of the application has a secret `seed` that provides
access to the keys to all accounts and assets created by that user.

```
User has many {Node}
User has many {Asset}
```

External accounts are identified by the URL `/pay/<user-id>/<account-alias>`. Whenever we make a payment,
the user specifies the URL. We extract the ID, and add the account to the list of recently used accounts.

When the payment is made, we request a new receiver from the URL,
which is generated automatically by incrementing a sequence number.

Then, we form a transaction and send that account the anchor ID, so the `Output` can be stored.

Since we are within the same system, we are going to do these things in one go.

## User data

Initial account is "Treasury" that has secret user id and allocation of 1B XLM.

Any time a new user is created, it receives 10 XLM so they can issue their own assets.

When we check cookies and read a secret seed from them, we load an appropriate account.

If account does not exist, we create it on the fly and load it up with 10 XLM from treasury.

The user then starts with 10 XLM and the ability to issue any assets.

## Utxo spending race condition

**Problem:**

When two requests simultaneously take the same utxo,
they can update their state and then later fail at submitting their transaction.

We need to make this failure atomic, so if the transaction conflicts with the global mempool state,
all the changes should be rejected.

**Current solution:**

We have a shared mempool state, guarded by a mutex. 

If one thread succeeds at applying the tx to the mempool,
it proceeds with applying changes to the DB.
Concurrent thread fails at applying a double-spend and does not even begin DB transaction.

The problem is different now: if the DB transaction fails for any reason, mempool remains in inconsistent state.


## Block creation race condition

**Problem:**

When there is time to create a block, two concurrent threads may grab mempool mutex at different states.

Need to make sure that we don't attempt to stamp the same block - 
we need to update the mempool state in the same DB transaction as adding a new block.

Maybe we can reconstruct the mempool from actual data in the DB within the same DB tx?

