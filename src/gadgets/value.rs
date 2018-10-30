use bulletproofs::r1cs::{Assignment, Variable};

#[derive(Clone, Debug)]
pub struct Value {
    pub q: (Variable, Assignment), // quantity
    pub a: (Variable, Assignment), // issuer
    pub t: (Variable, Assignment), // tag
}
