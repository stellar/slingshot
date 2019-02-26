# ZkVM implementation guide

The [ZkVM specification](zkvm-spec.md) covers the _verification rules_ for transactions that are already created,
but does not describe how to _create_ such transactions. This is the goal of this document.

## Prover and Verifier APIs

The [`Prover`](src/prover.rs) and [`Verifier`](src/verifier.rs) are two entry points to the ZkVM:

`Prover` is an API for _creating_ a transaction object `Tx` out of a stream of `Instruction`s:
`VM` executes the instructions, producing a serialized program bytecode, aggregated transaction signature
and a zero-knowledge R1CS proof for the [Cloak protocol](../../spacesuit/spec.md) and custom statements expressed by instructions.

`Verifier` is an API for _verifying_ a transaction object `Tx`: it parses the bytecode, executes it, verifies the aggregated transaction signature and the R1CS proof, producing a `VerifiedTx` as a result. Verification logic is described by the [ZkVM specification](zkvm-spec.md).

Note that `VM` execution is used twice: first, for _proving_, then for _verifying_. 

How does the `Prover` know how to sign transaction and make a proof? The prover’s input is not an opaque sequence of instruction codes, but _witness-bearing instructions_. That is, a `push` instruction on the prover’s side does not hold an opaque string of bytes, but an accurate _witness type_ that may contain secret data and necessary structure for creating the proofs and signatures.

## Witness types

TBD.



