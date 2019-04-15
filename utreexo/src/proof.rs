use super::hash::Hash;

#[derive(Clone)]
pub struct ProofStep {
    pub h: Hash,
    pub left: bool,
}

pub struct Proof {
    pub leaf: Hash,
    pub steps: Vec<ProofStep>,
}
