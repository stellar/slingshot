//! UTXO index protocol
use super::protocol::{Node,Delegate};
use super::utreexo;

// TBD: use crate::protocol::Plugin;
//! Plugin interface for tracking blockchain state.
pub trait Plugin {
    /// Called when the node is initialized, so the plugin can prefill the mempool or restore the state.
    fn did_init_node<D: Delegate>(&mut self, node: &mut Node<D>) {}

    /// Called for each block that is received, verified and stored.
    /// This is called after the block is stored, but before the mempool is updated.
    fn did_receive_block<D: Delegate>(&mut self, block: &Block, node: &mut Node<D>) {}

    /// Called for each block that is received, verified and stored.
    fn did_receive_unconfirmed_tx(&mut self, block: &BlockTx) {}

    /// Called for each transaction that's removed from the mempool as conflicting with existing ones.
    fn did_remove_unconfirmed_tx(&mut self, block: &BlockTx) {}
}

pub struct PluginChain<A: Plugin, B: Plugin>(A,B);

impl<A: Plugin, B: Plugin> Plugin for PluginChain<A,B> {
    /// Called when the node is initialized, so the plugin can prefill the mempool or restore the state.
    fn did_init_node<D: Delegate>(&mut self, node: &mut Node<D>) {
        self.0.did_init_node(node);
        self.1.did_init_node(node);
    }

    /// Called for each block that is received, verified and stored.
    /// This is called after the block is stored, but before the mempool is updated.
    fn did_receive_block<D: Delegate>(&mut self, block: &Block, node: &mut Node<D>) {}

    /// Called for each block that is received, verified and stored.
    fn did_receive_unconfirmed_tx(&mut self, block: &BlockTx) {}

    /// Called for each transaction that's removed from the mempool as conflicting with existing ones.
    fn did_remove_unconfirmed_tx(&mut self, block: &BlockTx) {}
}


//! Interface for the storage of unspent outputs and unconfirmed transactions.
pub trait IndexDelegate {
    
}

pub struct Index {
    
}

impl Plugin for Index {
    fn did_init_node<D: Delegate>(&mut self, node: &mut Node<D>) {
        // TBD: get the stored transactions and re-add them to mempool.
        // if some txs fail, 
    }

    /// Called for each block that is received, verified and stored.
    fn did_receive_block(&mut self, block: &Block) {}

    /// Called for each block that is received, verified and stored.
    fn did_receive_unconfirmed_tx(&mut self, block: &BlockTx) {}

    /// Called for each transaction that's removed from the mempool.
    fn did_remove_unconfirmed_tx(&mut self, block: &BlockTx) {}  
}