# ZkVM API

The [ZkVM specification](zkvm-spec.md) covers the _verification rules_ for transactions that are already created,
but does not describe how to _create_ such transactions. This is the goal of this document.

## Prover and Verifier APIs

The [`Prover`](../src/prover.rs) and [`Verifier`](../src/verifier.rs) are two entry points to the ZkVM:

`Prover` is an API for _creating_ a transaction object `Tx` out of a stream of `Instruction`s:
`VM` executes the instructions, producing a serialized program bytecode, aggregated transaction signature
and a zero-knowledge R1CS proof for the [Cloak protocol](../../spacesuit/spec.md) and custom statements expressed by instructions.

`Verifier` is an API for _verifying_ a transaction object `Tx`: it parses the bytecode, executes it, verifies the aggregated transaction signature and the R1CS proof, producing a `VerifiedTx` as a result. Verification logic is described by the [ZkVM specification](zkvm-spec.md).

Note that `VM` execution is used twice: first, for _proving_, then for _verifying_. 

How does the `Prover` know how to sign transaction and make a proof? The prover’s input is not an opaque sequence of instruction codes, but _witness-bearing instructions_. That is, a `push` instruction on the prover’s side does not hold an opaque string of bytes, but an accurate _witness type_ that may contain secret data and necessary structure for creating the proofs and signatures.

## Opaque and witness types

We call a type **opaque** if it provides only enough information for the _verification_ of a ZkVM transaction or some sub-protocol.

We call a type **witness** if it contains secret data and structure necessary for the _prover_ to create a zero-knowledge proof or a signature.

### Commitments

[Pedersen commitment](zkvm-spec.md#pedersen-commitment) is represented with an enum `Commitment`:

* `Commitment::Closed` is an _opaque type_ holding a compressed Ristretto [point](zkvm-spec.md#point) (represented by a 32-byte string).
* `Commitment::Open ` is a _witness type_ that holds a pair of a secret value ([scalar witness](#scalar-witness)) and a secret blinding factor. These are used to create a R1CS proof using the prover’s instance of the VM.

### Predicates

[Predicate](zkvm-spec.md#predicate) is a structure that encapsulates an opaque `VerificationKey` and an optional dynamically typed `PredicateWitness`. Witness may contain a private key directly, or metadata that helps creating a signature such as Multikey layout, derivation sequence number etc.

### Variables

Variables are represented as type-wrappers around Pedersen commitments.
The secret assignments for the variables are stored within the _commitment witnesses_ as [described above](#commitments).

### Expressions

Expressions store their witness data as an optional assignment `Option<ScalarWitness>`.
The verifier’s VM sees `None` and the prover’s VM sees `Some(...)`.

See also [scalar witness](#scalar-witness).

### Constraints

Constraints do not have explicit witness data. They can be computed on the fly by evaluating the boolean function that the constraint represents, taking the underlying [expressions’](#expressions) assignments as input.

### Signing keys

A [`signtx`](zkvm-spec.md#signtx) instruction expects a [predicate point](zkvm-spec.md#predicate) to be a [verification key](zkvm-spec.md#verification-key). In the `Prover` such key is represented as a `Data::Witness` type that holds `PredicateWitness::Key`. When the prover’s VM pops such item from the stack it remembers it. At the end of the VM execution, the prover queries the key storage for the corresponding secret keys and creates a [transaction signature](zkvm-spec.md#transaction-signature). Verifier uses the accumulated verification keys to verify the aggregated signature.

### Contracts

An [`input`](zkvm-spec.md#input) instruction decodes a serialized contract. In the prover’s VM it pops an `Input` item from the stack that contains a previously created `Output` object with usual data items (with witnesses) and “frozen values”: values where quantity and flavors are represented by [open commitments](#commitments) instead of variables.

The VM extracts the `Output` object from the `Input` and converts it to a [Contract type](zkvm-spec.md#contract-type) by allocating variables for each commitment within frozen values, turning them into actual [Value](zkvm-spec.md#value-type) types.

### Scalar witness

Scalar witness represents either:

* a [scalar](zkvm-spec.md#scalar), or
* a [signed integer](../../spacesuit/spec.md#signed-integer)

Arithmetic operations on scalar witnesses _preserve integers until overflow_. If an addition/multiplication of two integers overflows the range of `±(2^64-1)`, the result is promoted to a scalar modulo Ristretto group order.

[Range proof](../../spacesuit/spec.md#range-proof) gadget in Cloak requires a witness to be an integer (and also checks that it is non-negative) and does not attempt to carve 64 bits out of a scalar.
For safety, integer overflows immediately promote the integer to a scalar: any higher-level protocol that wishes to operate on integer quantities must ensure that they never overflow.

