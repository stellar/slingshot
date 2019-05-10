use super::error::UError;
use super::hash::Hash;
use super::update::Update;
use super::utreexo::{parent, Utreexo};

#[derive(Clone)]
pub struct ProofStep {
    pub h: Hash,
    pub left: bool,
}

#[derive(Clone)]
pub struct Proof {
    pub leaf: Hash,
    pub steps: Vec<ProofStep>,
}

impl Proof {
    pub fn update(&mut self, utreexo: &Utreexo, upd: &Update) -> Result<(), UError> {
        let mut h = self.leaf.clone();
        let mut i = 0;
        while i <= self.steps.len() {
            if utreexo.roots.len() > i {
                if let Some(hh) = &utreexo.roots[i] {
                    if &h == hh {
                        self.steps.truncate(i);
                        return Ok(());
                    }
                }
            }

            let step = match upd.updated.get(&h) {
                Some(s) => {
                    self.steps.truncate(i);
                    self.steps.push(s.clone());
                    s
                }
                None => {
                    if i == self.steps.len() {
                        break;
                    }
                    &self.steps[i]
                }
            };

            h = parent(&h, &step);
            i += 1;
        }

        Err(UError::Invalid)
    }
}
