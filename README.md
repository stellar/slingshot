# Spacesuit: Interstellar's implementation of cloaked transactions

This library is a pure-Rust implementation of the [Cloak][cloak] protocol. We use the
[Bulletproofs][bp_website] zero-knowledge circuit proof system, as implemented in
Rust in [this library][bp_repo]. 

## Documentation

Specs for the Cloak protocol can be [found here][cloak].

## WARNING

This code is still research-quality.  It is not (yet) suitable for deployment. 

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