use super::hash::Hash;
use super::proof::{Proof, ProofStep};
use super::utreexo::{parent, Utreexo};

use std::collections::HashMap;

pub struct Update {
    pub(crate) updated: HashMap<Hash, ProofStep>
}

impl Update {
    pub fn new() -> Update {
        return Update {
            updated: HashMap::new(),
        };
    }

    pub fn add(&mut self, l: &Hash, r: &Hash) {
        self.updated.insert(l.clone(), ProofStep { h: r.clone(), left: false });
        self.updated.insert(r.clone(), ProofStep { h: l.clone(), left: true });
    }

    pub fn proof(&self, utreexo: &Utreexo, leaf: &Hash) -> Proof {
        let mut item = leaf.clone();
        let mut result = Proof {
            leaf: item.clone(),
            steps: Vec::new(),
        };
        loop {
            match self.updated.get(&item) {
                None => return result,
                Some(step) => {
                    result.steps.push(step.clone());
                    item = parent(&item, &step);
                }
            }
        }
    }
}
