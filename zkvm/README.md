# ZkVM

An evolution of TxVM with **cloaked assets** and **zero-knowledge smart contracts**.

* [ZkVM specification](docs/zkvm-spec.md) — transaction validation rules.
* [ZkVM API](docs/zkvm-api.md) — how to create transactions with ZkVM.

## Overview

ZkVM architecture uses four concepts:

1. Programs
2. Predicates
3. Constraints
4. Crypto operations

### Programs

ZkVM is a stack machine. Program is a string of bytecode representing ZkVM instructions. Instructions manipulate values, contracts and constraints stored on a single stack.

ZkVM _does not compile_ programs into a constraint system. Instead, the bytecode directly combines _variables_ and _constraints_ and adds them into constraint system.

### Predicates

Predicates protect the contracts’ contents (value and parameters) from unauthorized access or modification.

Predicates are represented with a single point which can be used either as a public key, as a commitment to a program, or as a commitment to a disjunction of other predicates. Predicate tree protocol is a variant of prior proposals [Taproot](https://lists.linuxfoundation.org/pipermail/bitcoin-dev/2018-January/015614.html) by Gregory Maxwell and [G'root](https://lists.linuxfoundation.org/pipermail/bitcoin-dev/2018-July/016249.html) by Anthony Towns.

Like programs, ZkVM does not compile the predicate tree into a constraint system: it exists on its own and VM provides instruction for traversing the tree and satisfying the predicates with signatures and program execution.

### Constraints

Constraint system is another component in ZkVM, in addition to the stack and transaction log. Various instructions may add custom constraints to the constraint system to enforce smart contract conditions in zero knowledge. The same constraint system also contains constraints for the Cloak protocol, that are added by the `cloak` instruction that re-distributes a collection of values.

At the end of the VM execution, the entire constraint system is verified with a single R1CS proof.

### Crypto operations

All instructions that perform relatively expensive scalar-point multiplications to implement various checks (traversal of a predicate tree, checking signatures, etc) defer these operations till the end of the VM execution. Then, all such checks are verified in a batch, significantly reducing the overall verification time.

## See also

* [Merlin transcripts](https://doc.dalek.rs/merlin/index.html)
* [Ristretto group](https://ristretto.group)
* [Bulletproofs R1CS](https://doc-internal.dalek.rs/develop/bulletproofs/notes/r1cs_proof/index.html)
* [Cloak](../spacesuit/spec.md)
