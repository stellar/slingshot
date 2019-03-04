use zkvm::Output;

/// UTXO indexer that stores, updates, and 
/// retrieves UTXOs
pub struct Indexer<DB> {
    db: DB,
}

/// Representation of a UTXO
pub struct UTXO {

}

/// Defines a generic DB as key/value store.
/// TBD: is this what we want?
pub trait DBTrait {
    fn get(key: &[u8]) -> Vec<u8>;
    fn store(key: &[u8], value: Vec<u8>);
}

impl<DB> Indexer<DB> where DB: DBTrait {
    /// Adds an expected UTXO to the Indexer's store, to be 
    /// later finalized when given a Merkle proof of the output's 
    /// inclusion in a tx on the blockchain.
    pub fn add_expected_output(output: Output) {
        unimplemented!()
    }

    /// Submits a Merkle proof of the output's inclusion in a TxID,
    /// and finalizes the corresponding expected output.
    pub fn finalize_output() {
        unimplemented!()
    }

    /// Selects UTXOs sufficient to input a given value of the specified
    /// flavor. (use instead: token?)
    /// Chooses UTXOs by consuming the smallest UTXOs in-order until the 
    /// value is satisfied, marking them as consumed. In the event that a 
    /// UTXO is only partially used, the remaining output should be re-indexed
    /// using `add_expected_output()`
    pub fn select_utxo() {
        unimplemented!()
    }
}
