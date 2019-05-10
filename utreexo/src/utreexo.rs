use super::error::UError;
use super::hash::Hash;
use super::proof::{Proof, ProofStep};
use super::update::Update;

use merlin::Transcript;

#[derive(Clone, PartialEq)]
pub struct Utreexo {
    pub roots: Vec<Option<Hash>>,
}

impl Utreexo {
    pub fn new() -> Utreexo {
        return Utreexo {
            roots: Vec::new(),
        };
    }

    pub fn update(&mut self, deletions: &[Proof], insertions: &[Hash]) -> Result<Update, UError> {
        let mut new_roots: Vec<Vec<Hash>> = Vec::new();
        for (i, opt) in self.roots.iter().enumerate() {
            new_roots.push(Vec::new());
            if let Some(root) = opt {
                new_roots[i].push(root.clone());
            }
        }

        let mut upd = Update::new();

        for d in deletions {
            self.del_helper(d, &mut new_roots)?;
        }

        if new_roots.is_empty() {
            new_roots.push(Vec::new());
        }
        new_roots[0].extend_from_slice(insertions);

        let mut i = 0;
        while i < new_roots.len() {
            while new_roots[i].len() > 1 {
                let b = new_roots[i].pop().unwrap();
                let a = new_roots[i].pop().unwrap();
                let h = parent_hash(&a, &b);
                
                if new_roots.len() <= i+1 {
                    new_roots.push(Vec::new());
                }
                new_roots[i+1].push(h);
                upd.add(&a, &b);
            }
            i += 1;
        }

        i = new_roots.len();
        while i > 0 {
            i -= 1;
            if !new_roots[i].is_empty() {
                break;
            }
            new_roots.pop();
        }

        for (i, h) in new_roots.iter().enumerate() {
            if self.roots.len() <= i {
                self.roots.push(if h.is_empty() { None } else { Some(h[0].clone()) });
            } else {
                self.roots[i] = if h.is_empty() { None } else { Some(h[0].clone()) };
            }
        }
        self.roots.truncate(new_roots.len());

        Ok(upd)
    }

    fn del_helper(&self, p: &Proof, new_roots: &mut Vec<Vec<Hash>>) -> Result<(), UError> {
        if self.roots.len() <= p.steps.len() {
            return Err(UError::Invalid);
        }
        if let None = self.roots[p.steps.len()] {
            return Err(UError::Invalid);
        }
        
        let mut height = 0;
        let mut hash = p.leaf.clone();
        loop {
            if height < new_roots.len() {
                if let Some(index) = find_root(&hash, &new_roots[height]) {
                    // Remove hash from new_roots.
                    new_roots[height].remove(index);

                    // If height < p.steps.len(),
		    // then an earlier deletion "opened up" self.roots[p.steps.len()]
		    // and we just removed that subroot from new_roots.
		    // Now verify the remainder of p.steps against the unmodified tree.
                    loop {
                        if height >= p.steps.len() {
                            return if &hash == self.roots[height].as_ref().unwrap() {
                                Ok(())
                            } else {
                                Err(UError::Invalid)
                            }
                        }
                        hash = parent(&hash, &p.steps[height]);
                        height += 1;
                    }
                }
            }


            if height >= p.steps.len() {
                return Err(UError::Invalid);
            }
            while height >= new_roots.len() {
                new_roots.push(Vec::new());
            }
            let s = &p.steps[height];
            new_roots[height].push(s.h.clone());
            hash = parent(&hash, s);
            height += 1;
        }
    }
}

pub(crate) fn parent(h: &Hash, step: &ProofStep) -> Hash {
    parent_hash(
        if step.left { &step.h } else { &h },
        if step.left { &h } else { &step.h }
    )
}

fn parent_hash(left: &Hash, right: &Hash) -> Hash {
    let mut t = Transcript::new(b"utreexo");
    t.append_message(b"left", &left.0);
    t.append_message(b"right", &right.0);
    
    let mut result = Hash([0u8; 32]);
    t.challenge_bytes(b"parent", &mut result.0);
    result
}

fn find_root(h: &Hash, hashes: &[Hash]) -> Option<usize> {
    for (i, hh) in hashes.iter().enumerate() {
        if h == hh {
            return Some(i);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utreexo() {
        let mut items = [Hash([0u8; 32]); 12];
        for i in 0..12 {
            items[0] = Hash([i; 32]);
        }

        let mut u = Utreexo::new();

        // Try to delete from an empty tree, should give an invalid-proof error.
        let p1 = Proof {
            leaf: items[0].clone(),
            steps: vec![],
        };
        match u.update(&[p1], &[]) {
            Err(uerr) => assert_eq!(uerr, UError::Invalid),
            _ => panic!("unexpected success deleting from empty tree"),
        }

        // Add 11 leaves.
        let mut proofs: Vec<Proof> = Vec::new();
        match u.update(&[], &items[..11]) {
            Err(uerr) => panic!("error {} inserting items into empty tree", uerr),
            Ok(upd) => {
                for i in 0..11 {
                    proofs.push(upd.proof(&u, &items[i]));
                }
            }
        }

        // Remove one of them.
        match u.update(&proofs[..10], &[]) {
            Err(uerr) => panic!("error {} removing an item from the tree", uerr),
            Ok(upd) => {
                for i in 0..10 {
                    assert!(proofs[i].update(&u, &upd).is_ok());
                }
                let mut p10 = proofs[10].clone();
                match p10.update(&u, &upd) {
                    Err(uerr) => assert_eq!(uerr, UError::Invalid),
                    _ => panic!("unexpected success updating proof of deleted value"),
                }
            }
        }

        let saved = u.clone();
        match u.update(&[proofs[10].clone()], &[]) {
            Err(uerr) => assert_eq!(uerr, UError::Invalid),
            _ => panic!("unexpected success re-deleting deleted value"),
        }
        assert!(saved == u);
    }
}
