use bulletproofs::circuit_proof::assignment::Assignment;
use bulletproofs::circuit_proof::Variable;

#[derive(Clone, Debug)]
pub struct Value {
    pub q: (Variable, Assignment), // quantity
    pub a: (Variable, Assignment), // issuer
    pub t: (Variable, Assignment), // tag
}

impl Value {
    pub fn assignments(&self) -> (Assignment, Assignment, Assignment) {
        (self.q.1, self.a.1, self.t.1)
    }
    pub fn flavor(&self) -> (Assignment, Assignment) {
        (self.a.1, self.t.1)
    }
}
