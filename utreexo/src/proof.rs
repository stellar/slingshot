use super::error::UError;
use super::hash::Hash;
use super::update::Update;

#[derive(Clone)]
pub struct ProofStep {
    pub h: Hash,
    pub left: bool,
}

pub struct Proof {
    pub leaf: Hash,
    pub steps: Vec<ProofStep>,
}

impl Proof {
    pub fn update(&mut self, u: Update) -> Result<(), UError> {
        let mut h = self.leaf.clone();
        let mut i = 0;
        while i <= self.steps.len() {
            if u.u.roots.len() > i {
                if let Some(hh) = &u.u.roots[i] {
                    if &h == hh {
                        self.steps.truncate(i);
                        return Ok(());
                    }
                }
            }

            let step = match u.updated.get(&h) {
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

            h = if step.left {
                (u.u.hasher)(&step.h, &h)
            } else {
                (u.u.hasher)(&h, &step.h)
            };

            i += 1;
        }

        Err(UError::Invalid)
    }
}
