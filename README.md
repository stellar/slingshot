# Spacesuit: Interstellar's implementation of cloaked transactions

This library implements the [cloak][cloak] protocol, using the [Bulletproofs][bp_website]
zero-knowledge proof circuit protocol as implemented in rust in [this][bp_repo] library.

## WARNING

This code is still research-quality.  It is not (yet) suitable for
deployment. 

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