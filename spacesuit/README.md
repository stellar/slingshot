# Spacesuit: Interstellar's implementation of cloaked transactions

This library provides a pure-Rust implementation of [Cloak][cloak], a confidential assets
protocol based on the [Bulletproofs][bp_website] zero-knowledge circuit proof system.

The implementation of the Cloak protocol for [Interstellar][interstellar] is called [Spacesuit][spacesuit_crate].
It uses [this implementation][bp_repo] of Bulletproofs circuit proofs in Rust.

## Documentation

Specs for the Cloak protocol can be [found here][cloak].

## WARNING

This code is still research-quality. It is not (yet) suitable for deployment.

## Tests 

Run tests with `cargo test`.

## Benchmarks

This crate uses [criterion.rs][criterion] for benchmarks. Run
benchmarks with `cargo bench`.

## About

This is a research project sponsored by [Interstellar][interstellar],
developed by Henry de Valence, Cathie Yun, and Oleg Andreev.

The Spacesuit repository was moved from [this location][old_repo] on 2/7/2019.


[bp_website]: https://crypto.stanford.edu/bulletproofs/
[bp_repo]: https://github.com/dalek-cryptography/bulletproofs/
[interstellar]: https://interstellar.com/
[cloak]: https://github.com/interstellar/slingshot/blob/main/spacesuit/spec.md
[spacesuit_repo]: https://github.com/interstellar/slingshot/blob/main/spacesuit
[spacesuit_crate]: https://crates.io/crates/spacesuit
[criterion]: https://github.com/japaric/criterion.rs
[old_repo]: https://github.com/interstellar/spacesuit