use super::hash::Hash;
use super::proof::{Proof, ProofStep};
use super::utreexo::Utreexo;

use std::collections::HashMap;

pub struct Update {
    pub(crate) u: Utreexo,
    pub(crate) updated: HashMap<Hash, ProofStep>,
}

impl Update {
    pub fn new(u: Utreexo) -> Update {
        return Update {
            u: u,
            updated: HashMap::new(),
        };
    }

    pub fn add(&mut self, l: &Hash, r: &Hash) {
        self.updated.insert(l.clone(), ProofStep { h: r.clone(), left: false });
        self.updated.insert(r.clone(), ProofStep { h: l.clone(), left: true });
    }

    pub fn proof(&self, leaf: &Hash) -> Proof {
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
                    if step.left {
                        item = (self.u.hasher)(&step.h, &item);
                    } else {
                        item = (self.u.hasher)(&item, &step.h);
                    }
                }
            }
        }
    }
}
