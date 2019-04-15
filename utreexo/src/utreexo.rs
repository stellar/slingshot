use super::hash::Hash;

pub type HashFn = fn(&Hash, &Hash) -> Hash;

pub struct Utreexo {
    pub roots: Vec<Option<Hash>>,
    pub hasher: HashFn
}

impl Utreexo {
    pub fn new(hasher: HashFn) -> Utreexo {
        return Utreexo {
            roots: Vec::new(),
            hasher: hasher
        }
    }
}
