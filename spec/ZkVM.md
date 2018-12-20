# ZkVM

This is the specification for ZkVM, the zero-knowledge transaction virtual machine.

ZkVM defines a procedural representation for blockchain transactions and the rules for a virtual machine to interpret them and ensure their validity.

* [Overview](#overview)
    * [Motivation](#motivation)
    * [Concepts](#concepts)
* [Definitions](#definitions)
    * [Types](#types)
    * [Data types](#data-types)
    * [Linear types](#linear-types)
    * [Portable types](#portable-types)
    * [Portable types](#portable-types)
* [VM operation](#vm-operation)
    * [VM state](#vm-state)
    * [Encoding](#encoding)
* [Instructions](#instructions)
* [Discussion](#discussion)
    * [Relation to TxVM](#relation-to-txvm)
    * [Compatibility](#compatibility)







## Overview

### Motivation

[TxVM](https://chain.com/assets/txvm.pdf) introduced a novel representation for the blockchain transactions:
1. Each transaction is an executable program that produces effects to the blockchain state.
2. Values as first-class types subject to [linear logic](http://girard.perso.math.cnrs.fr/Synsem.pdf).
3. Contracts are first-class types that implement [object-capability model](https://en.wikipedia.org/wiki/Object-capability_model).

The resulting design enables scalable blockchain state machine (since the state is very small, and its updates are separated from transaction verification), expressive yet safe smart contracts via the sound abstractions provided by the VM, simpler validation rules and simpler transaction format.

TxVM, however, did not focus on privacy and in several places traded off simplicity for unlimited flexibility.

ZkVM is the entirely new design that inherits most important insights from the TxVM, makes the security and privacy its primary focus, and provides a more constrained customization framework, while making the expression of most important contracts even more straightforward.

### Concepts

The transaction program, together with a version number and time bounds,
is called the [transaction witness](#transaction-witness). It contains
all data and logic required to produce a unique
[transaction ID](#transaction-id). It also contains any necessary
proofs (such as signatures) that do not contribute to the transaction ID.

A [witness program](#witness-program) runs in the context of a
stack-based virtual machine. When the virtual machine executes the program,
it creates and manipulates data of various types:
[data types](#data-types) (e.g. [scalars](#scalar-type) and [points](#point-type))
and special [linear types](#linear-types) that include [values](#value-type) and
[contracts](#contract-type).

A _value_ is a specific amount of a specific asset that can be merged or split, issued or retired,
but not otherwise created or destroyed.

A _contract_ encapsulates a predicate (a public key or a program), plus its runtime state, and once created must be executed to completion or persisted in the global state for later execution.

Some ZkVM instructions (such as storing a contract for later
execution) propose alterations to the global blockchain state. These
proposals accumulate in the [transaction log](#transaction-log), a
data structure in the virtual machine that is the principal result of
executing a transaction. Hashing the transaction log gives the unique
[transaction ID](#transaction-id).

A ZkVM transaction is valid if and only if it runs to completion
without encountering failure conditions and without leaving any data
on the stack.

After a ZkVM program runs, the proposed state changes in the
transaction log are compared with the global state to determine the
transaction’s applicability to the [blockchain](Blockchain.md).










## Definitions


### Types

The items on the ZkVM stack are typed. The available types fall into two
broad categories: [data types](#data-types) and [linear types](#linear-types).


### Data types

Data types can be freely created, copied, and destroyed.

* [Scalars](#scalars)
* [Points](#points)
* [Strings](#strings)
* [Variables](#variables)
* [Constraints](#constraint)


### Linear types

Linear types are subject to special rules as to when and how they may be created
and destroyed, and may never be copied.

* [Contracts](#contracts)
* [Signed Values](#signed-values)
* [Values](#values)


### Portable types

The items of the following types can be _ported_ across transactions via [outputs](#outputs):

* [Plain data types](#data-types):
    * [Scalars](#scalars)
    * [Points](#points)
    * [Strings](#strings)
* [Values](#values)

The [Signed Value](#signed-values) is not portable because it is not proven to be non-negative.

The [Contract](#contracts) is not portable because it must be satisfied within the current transaction
or [output](#outputs) its contents itself.

The [Variable](#variables) and [Constraint](#constraint) types have no meaning outside the VM state
and its constraint system and therefore cannot be ported between transactions.


### Scalars

A _scalar_ is an integer modulo [Ristretto group](https://ristretto.group) order `2^252 + 27742317777372353535851937790883648493`.

Scalars are encoded as 32-byte arrays using little-endian notation.
Every scalar in the VM is guaranteed to be in a canonical (reduced) form.


### Points

A _point_ is an element in the [Ristretto group](https://ristretto.group).

Points are encoded as 32-byte arrays in _compressed Ristretto form_.
Each point in the VM is guaranteed to be a valid Ristretto point.


### Base points

ZkVM defines two base points: primary `B` and secondary `B2`.

```
B  = e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76
B2 = hash-to-ristretto255(SHA3-512(B))
```

Both base points are orthogonal (the discrete log between them is unknown)
and used in [commitments](#commitment), 
[verification keys](#verification-key) and [predicates](#predicate).

### Strings

A _string_ is a variable-length byte array used to represent signatures, proofs and programs.

Strings cannot be larger than the entire transaction program and cannot be longer than `2^32-1`.


### Contracts

A contract is a [predicate](#predicate) and a [payload](#payload) guarded by that predicate.

Contracts are created with the [`contract`](#contract) instruction and
destroyed by evaluating the predicate, leaving their stored items on the stack.

Contracts can be "frozen" with the [`output`](#output) instruction that
[encodes](#encoding) the predicate and the payload into the [output structure](#output-structure) which is
recorded in the [transaction log](#transaction-log).


### Payload

A list of [items](#types) stored in the [contract](#contracts) or [output](#outputs).

Payload of a [contract](#contracts) may contain arbitrary [types](#types),
but in the [output](#outputs) only the [portable types](#portable-types) are allowed.


### Predicate

A _predicate_ is a representation of a condition that unlocks the [contract](#contracts).

Predicate is encoded as a [point](#points) which can itself represent:

* a verification key,
* a set of verification keys,
* a disjunction of nested predicates,
* a [program](#program).

Each contract can be opened by either:

1. signing the [transaction ID](#transaction-id) with a key ([`signtx`](#signtx) instruction),
2. revealing the embedded program and evaluating it ([`call`](#call) instruction),
3. signing a _delegate program_ and evaluating it ([`delegate`](#delegate) instruction).

Predicates can be selected from a tree of alternatives via [`left`](#left) and [`right`](#right) instructions.


### Verification key

A _verification key_ (aka "public key") is a commitment to a _signing key_ (secret [scalar](#scalars))
using the primary [base point](#base-points).

```
P = x * B
```

where:

* `P` is a verification key,
* `x` is a signing key (secret scalar),
* `B` is the [primary base point](#base-points).

#### See also

* [Predicate](#predicate)
* [Signature](#signature)


### Program

A program is a string containing a sequence of ZkVM [instructions](#instructions).
Each instruction is an **opcode** optionally followed by **immediate data**.

The **opcode** is a one-byte unsigned integer.

The **immediate data** is 0 or more bytes, depending on the opcode.

See the [instruction set](#instructions) for definition of the immediate data for each opcode.


### Constraint system

The part of the [VM state](#vm-state) that implements
[Bulletprofs Rank-1 Constraint System](https://doc-internal.dalek.rs/develop/bulletproofs/notes/r1cs_proof/index.html).

Constraint system keeps track of [variables](#variables) and [constraints](#constraint).

### Variables

_Variable_ is a linear combination of high-level and low-level variables in the [constraint system](#constraint-system).

Variables can be added and multiplied, producing new variables (see [`zkadd`](#zkadd), [`zkneg`](#zkneg), [`zkmul`](#zkmul), [`scmul`](#scmul) and [`zkrange`](#zkrange) instructions).

Equality of two variables is checked by creating a [constraint](#constraint) using the [`zkeq`](#zkeq) instruction.

Examples of variables: [value quantities](#values) and [time bounds](#time-bounds).

Cleartext [scalars](#scalars) can be turned into a `Variable` type using the [`const`](#const) instruction.

#### See also

* [Constraint](#constrain)
* [Constraint system](#constraint-system)


### Constraint

_Constraint_ is a statement in the [constraint system](#constraint-system) that constrains
a linear combination of variables to zero.

Constraints are created using the [`zkeq`](#zkeq) instruction over two [variables](#variables).

Constraints can be combined using logical [`and`](#and) and [`or`](#or) instructions and added to the constraint
system using the [verify](#verify) instruction.

#### See also

* [Variable](#variable)
* [Constraint system](#constraint-system)


### Commitment

A _commitment_ is a Pedersen commitment to a secret [scalar](#scalars) represented by a [point](#points):

```
P = Com(v, f) = v*B + f*B2
```

where:

* `P` is a point representing commitment,
* `v` is a secret scalar value being committed to,
* `f` is a secret blinding factor (scalar),
* `B` and `B2` are [base points](#base-points).

Commitments can be used to allocate new [variables](#variables) using the [`var`](#var) instruction.

Commitments can be proven to use a pre-determined blinding factor using [`encrypt`](#encrypt) and 
[`decrypt`](#decrypt) instructions.


### Time bounds

Each transaction is explicitly bound to a range of _minimum_ and _maximum_ time.

Each bound is in _seconds_ since Jan 1st, 1970 (UTC), represented by an unsigned 64-bit integer.

Time bounds are available in the transaction as [variables](#variables) provided by the instructions
[`mintime`](#mintime) and [`maxtime`](#maxtime).


### Values

A value is a [linear type](#linear-types) representing a pair of *quantity* and *flavor*.

Both quantity and flavor are represented as [scalars](#scalars).
Quantity is guaranteed to be in a 64-bit range (`[0..2^64-1]`).

Values are created with [`issue`](#issue) and destroyed with [`retire`](#retire).

A value can be merged and split together with other values using a [`cloak`](#cloak) instruction.
Only values having the same flavor can be merged.

Values are secured by “locking them up” inside [contracts](#contracts).

Contracts can also require payments by creating outputs using _borrowed_ values.
[`borrow`](#borrow) instruction produces two items: a positive value and a negative [signed value](#signed-values),
which must be cleared using appropriate combination of positive values.


### Signed values

A signed value is an extension of the [value](#values) type where
quantity is guaranteed to be in a 65-bit range (`[-(2^64-1)..2^64-1]`).

The subtype [Value](#values) is most commonly used because it guarantees the non-negative quantity
(for instance, [`output`](#output) instruction only permits positive [values](#values)),
and the signed value is only used as an output of [`borrow`](#borrow) and as an input to [`cloak`](#cloak).


### Signature

Signature is a Schnorr proof of knowledge of a secret [scalar](#scalars) corresponding
to a [verification key](#verification-key).

Signature is encoded as a 64-byte [string](#strings).

The signature verification protocol is the following:

```
Prover                                              Verifier
------------------------------------------------------------
P := x*B
                 T("ZkVM.Signature")
                          T <- ("P", P)
                          T <- ("M", message)
r := random       
R := r*B   
                          T <- ("R", R)
                     e <- T
s := r + e*x
                                             s*G =?= R + e*P
```

where:

1. `T` is a [transcript](#transcript),
2. `P` is a [verification key](#verification-key),
3. `R` is a commitment to a random nonce `r`,
4. `e` is a Fiat-Shamir challenge scalar.


### Input structure

TBD: serialized contract snapshot + txid


### Output structure

TBD: contract snapshot


### Constraint system proof

A proof of satisfiability of a [constraint system](#constraint-system) built during the VM execution.

The proof is represented by a collection of [points](#points) and [scalars](#scalars)
encoded in a single [string](#strings).

The proof is provided to the [`finalize`](#finalize) instruction at which point the transaction is
fully formed and the proof can be verified.


### Transcript

TBD: protocol label, challenge scalar, labeled inputs.


### Transaction log

The *transaction log* contains entries that describe the effects of various instructions.

The transaction log is empty at the beginning of a ZkVM program. It is
append-only. Items are added to it upon execution of any of the
following instructions:

* [`finalize`](#finalize)
* [`input`](#input)
* [`issue`](#issue)
* [`data`](#data)
* [`nonce`](#nonce)
* [`output`](#output)
* [`retire`](#retire)

The details of the item added to the log differs for each
instruction. See the instruction’s description for more information.

The [`finalize`](#finalize) instruction prohibits further changes to the
transaction log. Every ZkVM program must execute `finalize` exactly
once.




## VM operation

### VM state

TBD: the header, the stack, program stack, txlog, CS, schnorr ops.


### Encoding

TBD: encoding of the txlog items and snapshots



## Instructions

TBD.



## Discussion

This section collects discussion of the rationale behind the design decisions in the ZkVM.

### Relation to TxVM

ZkVM has similar or almost identical properties as TxVM:

1. The format of the transaction is the _executable bytecode_.
2. The VM is a Forth-like _stack machine_.
3. Multi-asset issuable _values_ are first-class types subject to _linear logic_.
4. Contracts are first-class types implementing [object-capability model](https://en.wikipedia.org/wiki/Object-capability_model).
5. VM assumes small UTXO-based blockchain state and very simple validation rules outside the VM.
6. Each unspent transaction output (UTXO) is a _contract_ which holds arbitrary collection of data and values.
7. Optional _time-bounded nonces_ as a way to guarantee uniqueness when transaction has no link to previous transactions.
8. _Transaction log_ as an append-only list of effects of the transaction (inputs, outputs, nonces etc.)
9. Contracts use linear logic by imperatively producing the effects they require instead of observing and verifying their context.
10. Execution can be _delegated to a signed program_ which is provided at the moment of opening a contract.

At the same time, ZkVM improves on the following tradeoffs in TxVM:

1. _Runlimit_ and _jumps_: ZkVM does not permit recursion and loops and has more predictable cost model that does not require artificial cost metrics per instruction.
2. _Too abstract capabilities_ that do not find their application in the practical smart contracts, like having “wrapping” contracts or many kinds of hash functions.
3. Uniqueness of transaction IDs enforced via _anchors_ (embedded in values) is conceptually clean in TxVM, although not very ergonomic. In confidential transactions anchors become even less ergonomic in several respects, and issuance is simpler without anchors.
4. TxVM allows multiple time bounds and needs to intersect all of them, which comes at odds with zero-knowledge proofs about time bounds.
5. Creating outputs is less ergonomic and more complex than necessary (via a temporary contract).
6. TxVM allows nested contracts and needs multiple stacks and an argument stack. ZkVM uses one stack.


### Compatibility

Forward- and backward-compatible upgrades (“soft forks”) are possible
with [extension instructions](#ext), enabled by the
[extension flag](#versioning) and higher version numbers.

It is possible to write a compatible contract that uses features of a newer
transaction version while remaining usable by non-upgraded software
(that understands only older transaction versions) as long as
new-version code paths are protected by checks for the transaction
version. To facilitate that, a hypothetical ZkVM upgrade may introduce
an extension instruction “version assertion” that fails execution if
the version is below a given number (e.g. `4 versionverify`).




