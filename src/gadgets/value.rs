use bulletproofs::r1cs::{Assignment, Variable};

// Helper struct for ease of working with 
// 3-tuples of variables and assignments
#[derive(Clone, Debug)]
pub struct Value {
    pub q: (Variable, Assignment), // quantity
    pub a: (Variable, Assignment), // issuer
    pub t: (Variable, Assignment), // tag
}
