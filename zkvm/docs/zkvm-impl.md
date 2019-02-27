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

**Witness** is a type necessary to create a zero-knowledge proof or a signature.

R1CS variables’ _witness_ is their secret _assignment_.

VM instructions expect different types of witness data depending on the kind of object they operate on.

### Commitments

For the verifier, Pedersen commitments are opaque 32-byte [compressed points](zkvm-spec.md#point). For the verifier, these are represented by a `Data::Commitment` variant that holds a `Commitment` structure which can be `::Closed` or `::Open`.

The `var` instruction in the prover’s VM expects an `::Open` commitment. An open commitment contains the secret value and its blinding factor explicitly, so they can be used to compute a R1CS proof.

### Predicates

`Predicate` type represents either an opaque predicate, or an entire tree where unused branches can be left opaque and visited branches are stored as-is. This structure can then produce correct input for the [`call`](zkvm-spec.md#call), [`left`](zkvm-spec.md#left) and [`right`](zkvm-spec.md#right) instructions.

### Variables

Variables are represented as indices into the commitments stored within the VM state. VM manages the "attached" state of the variables to permit replacing the commitments via [`reblind`](zkvm-spec.md#reblind). The secret assignments for the variables are stored within their commitments as [described above](#commitments).

### Expressions

Expressions store their witness data as an optional assignment `Option<ScalarWitness>`.
The verifier’s VM sees `None` and the prover’s VM sees `Some(...)`.

See also [scalar witness](#scalar-witness).

### Constraints

Constraints do not have explicit witness data. It can be computed on the fly by evaluating the boolean function that the constraint represents, taking the underlying [expressions’](#expressions) assignments as input.

### Signing keys

A [`signtx`](zkvm-spec.md#signtx) instruction expects a [predicate point](zkvm-spec.md#predicate) to be a [verification key](zkvm-spec.md#verification-key). In the `Prover` such key is represented as a `Data::Witness` type that holds `PredicateWitness::Key`. When the prover’s VM pops such item from the stack and remembers it, the `Prover` accumulates all such secret keys and creates a [transaction signature](zkvm-spec.md#transaction-signature) at the end of the execution.

TBD: describe the upcoming signer API that adds a layer of indirection between the witness keys and actual secrets — for HSM-compatibility and multi-party signing scenarios.

### Contracts

An [`input`](#input) instruction decodes a serialized contract. In the prover’s VM it pops an `Input` item from the stack that contains a previously created `Output` object with usual data items (with witnesses) and “frozen values”: values where quantity and flavors are represented by [open commitments](#commitments) instead of variables.

The VM extracts the `Output` object from the `Input` and converts it to a [Contract type](zkvm-spec.md#contract-type) by allocating variables for each commitment within frozen values, turning them into actual [Value](zkvm-spec.md#value-type) types.

### Scalar witness

Scalar witness represents either:

* a [scalar](zkvm-spec.md#scalar), or
* a [signed integer](../../spacesuit/spec.md#signed-integer)

Arithmetic operations on scalar witnesses _preserve integers until overflow_. If an addition/multiplication of two integers overflows the range of `±(2^64-1)`, the result is promoted to a scalar modulo Ristretto group order.

[Range proof](../../spacesuit/spec.md#range-proof) gadget in Cloak requires a witness to be an integer (and also checks that it is non-negative) and does not attempt to carve 64 bits out of a scalar.
For safety, integer overflows immediately promote the integer to a scalar: any higher-level protocol that wishes to operate on integer quantities must ensure that they never overflow.

