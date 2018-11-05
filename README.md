# Spacesuit: Interstellar's implementation of cloaked transactions

This library provides a pure-Rust implementation of [Cloak][cloak], a confidential assets
protocol based on the [Bulletproofs][bp_website] zero-knowledge circuit proof system.

The implementation of the Cloak protocol for [Interstellar][interstellar] is called [Spacesuit][spacesuit_crate].
It uses [this implementation][bp_repo] of Bulletproofs circuit proofs in Rust.

## Documentation

Specs for the Cloak protocol can be [found here][cloak].

## WARNING

This code is still research-quality.  It is not (yet) suitable for deployment.
The development roadmap can be found in the [Milestones][milestones] section of the 
[Github repo][spacesuit_repo].

## Tests 

Run tests with `cargo test`.

## Benchmarks

This crate uses [criterion.rs][criterion] for benchmarks.  Run
benchmarks with `cargo bench`.

## About

This is a research project sponsored by [Interstellar][interstellar],
developed by Henry de Valence, Cathie Yun, and Oleg Andreev.

[bp_website]: https://crypto.stanford.edu/bulletproofs/
[bp_repo]: https://github.com/dalek-cryptography/bulletproofs/
[interstellar]: https://interstellar.com/
[cloak]: https://github.com/interstellar/spacesuit/blob/master/spec.md
[milestones]: https://github.com/interstellar/spacesuit/milestones
[spacesuit_repo]: https://github.com/interstellar/spacesuit
[spacesuit_crate]: https://crates.io/crates/spacesuit
[criterion]: https://github.com/japaric/criterion.rs