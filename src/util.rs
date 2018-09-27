use bulletproofs::circuit_proof::assignment::Assignment;
use bulletproofs::circuit_proof::Variable;

#[derive(Clone, Debug)]
pub struct Value {
    pub q: (Variable, Assignment), // quantity
    pub a: (Variable, Assignment), // issuer
    pub t: (Variable, Assignment), // tag
}
