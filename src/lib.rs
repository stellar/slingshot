extern crate bulletproofs;
extern crate curve25519_dalek;
extern crate merlin;
extern crate rand;

mod assignment_holder;
mod gadgets;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
