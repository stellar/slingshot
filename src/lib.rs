
extern crate bulletproofs;
extern crate curve25519_dalek;
extern crate rand;
extern crate merlin;

mod gadgets;
mod assignment_holder;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
