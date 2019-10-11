# ZkVM transaction lifecycle

Transaction in ZkVM begins its life as a `Program` and a `TxHeader` passed to `Prover::build_tx` which returns an `UnsignedTx`, a transaction that has a fully composed program, a R1CS proof, but lacks an aggregated schnorr signature (for all the `signtx` instructions).

When transaction is signed it transitions from `UnsignedTx` to `Tx`. In this form it can be published in a `Block`.

The block and all the transactions in it are validated in 4 stages:

1. **Stateless tx validation** (`Tx::verify` and `Tx::verify_batch`): 
    * the program is executed, 
    * txlog is computed, 
    * r1cs proof and schnorr signatures are verified.
2. **Tx contextual validation**:
    * tx version and time bounds are checked against the current context (block or mempool).
3. **Block contextual validation**:
    * block's version and timestamp are checked against current context (latest tip),
    * block's txroot is checked against the set of contextually valid transactions.
4. **Partial state validation**:
    * contextually valid tx is applied to the state,
    * modifies the state in place.
5. **Full state validation**:
    * contextually valid block is applied to the state via partial state validation,
    * utxo root is computed and verified to match the commitment,
    * new state is computed and returned.

To keep the API simple, contextual validation for txs and block headers is performed in-place:

* tx version and time bounds are checked when tx is added to mempool, or when txroot is computed for a block.
* block version and timestamp is checked when block is applied to the state.

