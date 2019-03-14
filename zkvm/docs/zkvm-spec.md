# ZkVM specification

This is the specification for ZkVM, the zero-knowledge transaction virtual machine.

ZkVM defines a procedural representation for blockchain transactions and the rules for a virtual machine to interpret them and ensure their validity.

* [Overview](#overview)
    * [Motivation](#motivation)
    * [Concepts](#concepts)
* [Types](#types)
    * [Copyable types](#copyable-types)
    * [Linear types](#linear-types)
    * [Portable types](#portable-types)
    * [Data](#data-type)
    * [Contract](#contract-type)
    * [Variable](#variable-type)
    * [Expression](#expression-type)
    * [Constraint](#constraint-type)
    * [Value](#value-type)
    * [Wide value](#wide-value-type)
* [Definitions](#definitions)
    * [LE32](#le32)
    * [LE64](#le64)
    * [Scalar](#scalar)
    * [Point](#point)
    * [Base points](#base-points)
    * [Pedersen commitment](#pedersen-commitment)
    * [Verification key](#verification-key)
    * [Time bounds](#time-bounds)
    * [Contract ID](#contract-id)
    * [Anchor](#anchor)
    * [Transcript](#transcript)
    * [Predicate](#predicate)
    * [Predicate tree](#predicate-tree)
    * [Predicate disjunction](#predicate-disjunction)
    * [Program predicate](#program-predicate)
    * [Program](#program)
    * [Contract payload](#contract-payload)
    * [Output structure](#output-structure)
    * [UTXO](#utxo)
    * [Constraint system](#constraint-system)
    * [Constraint system proof](#constraint-system-proof)
    * [Transaction](#transaction)
    * [Transaction log](#transaction-log)
    * [Transaction ID](#transaction-id)
    * [Merkle binary tree](#merkle-binary-tree)
    * [Aggregated signature](#aggregated-signature)
    * [Transaction signature](#transaction-signature)
    * [Unblinding proof](#unblinding-proof)
* [VM operation](#vm-operation)
    * [VM state](#vm-state)
    * [VM execution](#vm-execution)
    * [Deferred point operations](#deferred-point-operations)
    * [Versioning](#versioning)
* [Instructions](#instructions)
    * [Stack instructions](#stack-instructions)
    * [Constraint system instructions](#constraint-system-instructions)
    * [Value instructions](#value-instructions)
    * [Contract instructions](#contract-instructions)
* [Transaction Encoding](#transaction-encoding)
* [Examples](#examples)
    * [Lock value example](#lock-value-example)
    * [Unlock value example](#unlock-value-example)
    * [Simple payment example](#simple-payment-example)
    * [Offer example](#offer-example)
    * [Offer with partial lift](#offer-with-partial-lift)
    * [Loan example](#loan-example)
    * [Loan with interest](#loan-with-interest)
    * [Payment channel example](#payment-channel-example)
    * [Payment routing example](#payment-routing-example)
* [Discussion](#discussion)
    * [Relation to TxVM](#relation-to-txvm)
    * [Compatibility](#compatibility)
    * [Static arguments](#static-arguments)
    * [Should cloak and borrow take variables and not commitments?](#should-cloak-and-borrow-take-variables-and-not-commitments)
    * [Why there is no `and` combinator in the predicate tree?](#why-there-is-no-and-combinator-in-the-predicate-tree)
    * [Why we need Wide value and `borrow`?](#why-we-need-wide-value-and-borrow)
    * [How to perform an inequality constraint?](#how-to-perform-an-inequality-constraint)
    * [How to perform a logical `not`?](#how-to-perform-a-logical-not)
    * [What ensures transaction uniqueness?](#what-ensures-transaction-uniqueness)
    * [Open questions](#open-questions)




## Overview

### Motivation

[TxVM](https://chain.com/assets/txvm.pdf) introduced a novel representation for the blockchain transactions:
1. Each transaction is an executable program that produces effects to the blockchain state.
2. Values as first-class types subject to [linear logic](http://girard.perso.math.cnrs.fr/Synsem.pdf).
3. Contracts are first-class types that implement [object-capability model](https://en.wikipedia.org/wiki/Object-capability_model).

The resulting design enables scalable blockchain state machine (since the state is very small, and its updates are separated from transaction verification), expressive yet safe smart contracts via the sound abstractions provided by the VM, simpler validation rules and simpler transaction format.

TxVM, however, did not focus on privacy and in several places traded off simplicity for unlimited flexibility.

ZkVM is the entirely new design that inherits most important insights from the TxVM, makes the security and privacy its primary focus, and provides a more constrained customization framework, while making the expression of the most common contracts even more straightforward.

### Concepts

A transaction is represented by a [transaction](#transaction) object that
contains a [program](#program) that runs in the context of a stack-based virtual machine.

When the virtual machine executes a program, it creates and manipulates data of various types:
[**copyable types**](#copyable-types) and [**linear types**](#linear-types), such as [values](#value-type) and
[contracts](#contract-type).

A [**value**](#value-type) is a specific _quantity_ of a certain _flavor_ that can be
merged or split, issued or retired, but not otherwise created or destroyed.

A [**contract**](#contract-type) encapsulates a list of data and value items
protected by a [predicate](#predicate) (a public key or a program) which must be satisfied
during the VM execution. The contract can be stored in and loaded from the global state
using [`output`](#output) and [`input`](#input) instructions.

Custom logic is represented via programmable [**constraints**](#constraint-type)
applied to [**variables**](#variable-type) and [**expressions**](#expression-type)
(linear combinations of variables). Variables represent quantities and flavors of values,
[time bounds](#time-bounds) and user-defined secret parameters. All constraints are arranged in
a single [constraint system](#constraint-system) which is proven to be satisfied after the VM
has finished execution.

Some ZkVM instructions write proposed updates to the blockchain state
to the [**transaction log**](#transaction-log), which represents the
principal result of executing a transaction.

Hashing the transaction log gives the unique [**transaction ID**](#transaction-id).

A ZkVM transaction is valid if and only if it runs to completion
without encountering failure conditions and without leaving any data
on the stack.

After a ZkVM program runs, the proposed state changes in the
transaction log are compared with the global state to determine the
transaction’s applicability to the blockchain.







## Types

The items on the ZkVM stack are typed. The available types fall into two 
categories: [copyable types](#copyable-types) and [linear types](#linear-types).

### Copyable types

Copyable types can be freely created, copied ([`dup`](#dup)), and destroyed ([`drop`](#drop)).

* [Data](#data-type)
* [Variable](#variable-type)
* [Expression](#expression-type)
* [Constraint](#constraint-type)


### Linear types

Linear types are subject to special rules as to when and how they may be created
and destroyed, and may never be copied.

* [Contract](#contract-type)
* [Wide value](#wide-value-type)
* [Value](#value-type)


### Portable types

Only the [data](#data-type) and [value](#value-type) types can be _ported_ across transactions via [outputs](#output-structure).

Notes:

* [Wide values](#wide-value-type) are not portable because they are not proven to be non-negative.
* [Contracts](#contract-type) are not portable because they must be satisfied within the current transaction
or [output](#output-structure) their contents themselves.
* [Variables](#variable-type), [expressions](#expression-type) and [constraints](#constraint-type) have no meaning outside the VM state
and its constraint system and therefore cannot be meaningfully ported between transactions.


### Data type

A _data type_ is a variable-length byte array used to represent signatures, proofs and programs.

Data cannot be larger than the entire transaction program and cannot be longer than `2^32-1` (see [LE32](#le32)).


### Contract type

A contract consists of a [predicate](#predicate) and a [payload](#contract-payload). The payload is guarded by the predicate.

Contracts are created with the [`contract`](#contract) instruction and
destroyed by evaluating the predicate, leaving their payload on the stack.

Contracts can be "frozen" with the [`output`](#output) instruction that places the predicate
and the payload into the [output structure](#output-structure) which is
recorded in the [transaction log](#transaction-log).

Each contract contains a hidden field [anchor](#anchor) that makes it globally unique for safe signing.


### Variable type

_Variable_ represents a secret [scalar](#scalar) value in the [constraint system](#constraint-system)
bound to its [Pedersen commitment](#pedersen-commitment).

A [point](#point) that represents a commitment to a secret scalar can be turned into a variable using the [`var`](#var) instruction.

A cleartext [scalar](#scalar) can be turned into a single-term [expression](#expression-type) using the [`const`](#const) instruction (which does not allocate a variable). Since we do not need to hide their values, a Variable is not needed to represent the cleartext constant.

Variables can be copied and dropped at will, but cannot be ported across transactions via [outputs](#output-structure).

[Value quantities and flavors](#value-type) are represented as variables.

Constraint system also contains _low-level variables_ that are not individually bound to [Pedersen commitments](#pedersen-commitment):
when these are exposed to the VM (for instance, from [`mul`](#mul)), they have the [expression type](#expression-type).


### Expression type

_Expression_ is a linear combination of constraint system variables with cleartext [scalar](#scalar) weights.

    expr = { (weight0, var0), (weight1, var1), ...  }

A [variable](#variable-type) can be converted to an expression using [`expr`](#expr):
the result is a linear combination with one term with weight 1:

    expr = { (1, var) }

Expressions can be [added](#add) and [multiplied](#mul), producing new expressions.

Expressions can be copied and dropped at will, but cannot be ported across transactions via [outputs](#output-structure).

### Constant expression

An [expression](#expression-type) that contains one term with the [scalar](#scalar) weight assigned to the R1CS `1` is considered
a _constant expression_:

    const_expr = { (weight, 1) }

Instructions [`add`](#add) and [`mul`](#mul) preserve constant expressions as an optimization in order to avoid
allocating unnecessary multipliers in the [constraint system](#constraint-system).


### Constraint type

_Constraint_ is a statement within the [constraint system](#constraint-system). Constraints are formed using [expressions](#expression-type)
and can be combined using logical operators [`and`](#and) and [`or`](#or).

There are three kinds of constraints:
1. **Linear constraint** is created using the [`eq`](#eq) instruction over two [expressions](#expression-type).
2. **Conjunction constraint** is created using the [`and`](#and) instruction over two constraints of any type.
3. **Disjunction constraint** is created using the [`or`](#or) instruction over two constraints of any type.

Constraints and can be copied and dropped at will.

Constraints only have an effect if added to the constraint system using the [`verify`](#verify) instruction.


### Value type

A value is a [linear type](#linear-types) representing a pair of *quantity* and *flavor* (see [quantity](../../spacesuit/spec.md#quantity) and [flavor](../../spacesuit/spec.md#flavor) in the [Cloak specification](../../spacesuit/spec.md)).
Both quantity and flavor are represented as [variables](#variable-type).
Quantity is guaranteed to be in a 64-bit range (`[0..2^64-1]`).

Values are created with [`issue`](#issue) and destroyed with [`retire`](#retire).
Values can be merged and split together with other values using a [`cloak`](#cloak) instruction.
Only values having the same flavor can be merged.

Values are secured by “locking them up” inside [contracts](#contract-type).

Contracts can also require payments by creating outputs using _borrowed_ values.
[`borrow`](#borrow) instruction produces two items: a non-negative value and a negated [wide value](#wide-value-type),
which must be cleared using appropriate combination of non-negative values.

Each non-negative value keeps the [Pedersen commitments](#pedersen-commitment)
for the quantity and flavor (in addition to the respective [variables](#variable-type)),
so that they can serialized in the [`output`](#output).


### Wide value type

_Wide value_ is an extension of the [value type](#value-type) where
quantity is guaranteed to be in a wider, 65-bit range `[-(2^64-1) .. 2^64-1]`.

The subtype [Value](#value-type) is most commonly used because it guarantees the non-negative quantity
(for instance, [`output`](#output) instruction only permits positive [values](#value-type)),
and the wide value is only used as an output of [`borrow`](#borrow) and as an input to [`cloak`](#cloak).





## Definitions

### LE32

A non-negative 32-bit integer encoded using little-endian convention.
Used to encode lengths of [data types](#data-type), sizes of [contract payloads](#contract-payload) and stack indices.

### LE64

A non-negative 64-bit integer encoded using little-endian convention.
Used to encode [value quantities](#value-type) and [timestamps](#time-bounds).


### Scalar

A _scalar_ is an integer modulo [Ristretto group](https://ristretto.group) order `|G| = 2^252 + 27742317777372353535851937790883648493`.

Scalars are encoded as 32-byte [data types](#data-type) using little-endian convention.

Every scalar in the VM is guaranteed to be in a canonical (reduced) form: an instruction that operates on a scalar
checks if the scalar is canonical.


### Point

A _point_ is an element in the [Ristretto group](https://ristretto.group).

Points are encoded as 32-byte [data types](#data-type) in _compressed Ristretto form_.

Each point in the VM is guaranteed to be a valid Ristretto point.


### Base points

ZkVM defines two base points: primary `B` and secondary `B2`.

```
B  = e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76
B2 = hash-to-ristretto255(SHA3-512(B))
```

Both base points are orthogonal (the discrete log between them is unknown)
and used in [Pedersen commitments](#pedersen-commitment), 
[verification keys](#verification-key) and [predicates](#predicate).


### Pedersen commitment

Pedersen commitment to a secret [scalar](#scalar)
is defined as a point with the following structure:

```
P = Com(v, f) = v·B + f·B2
```

where:

* `P` is a point representing commitment,
* `v` is a secret scalar value being committed to,
* `f` is a secret blinding factor (scalar),
* `B` and `B2` are [base points](#base-points).

Pedersen commitments can be used to allocate new [variables](#variable-type) using the [`var`](#var) instruction.

Pedersen commitments can be opened using the [`unblind`](#unblind) instruction.


### Verification key

A _verification key_ `P` is a commitment to a secret [scalar](#scalar) `x` (_signing key_)
using the primary [base point](#base-points) `B`: `P = x·B`.
Verification keys are used to construct [predicates](#predicate) and verify [signatures](#aggregated-signature).


### Time bounds

Each transaction is explicitly bound to a range of _minimum_ and _maximum_ time.
Each bound is in _seconds_ since Jan 1st, 1970 (UTC), represented by an unsigned 64-bit integer.
Time bounds are available in the transaction as [expressions](#expression-type) provided by the instructions
[`mintime`](#mintime) and [`maxtime`](#maxtime).


### Contract ID

_Contract ID_ is a 32-byte unique identifier of the [contract](#contract-type) and a commitment to its contents (see [Output](#output-structure)):

```
T = Transcript("ZkVM.contractid")
T.commit("contract", output_structure)
id = T.challenge_bytes("id")
```

Contract ID makes signatures safe against reused [verification keys](#verification-key) in [predicates](#predicate):
a signature covers the unique contract ID, therefore preventing its replay against another contract,
even if containing the same [payload](#contract-payload) and predicate.

Uniqueness is provided via the [anchor](#anchor).

### Anchor

_Anchor_ is a 32-byte unique string that provides uniqueness to the [contract ID](#contract-id).
Anchors can be created by the [`nonce`](#nonce) instruction or generated from unique contract IDs used earlier in the same transaction. These are tracked by the VM via [last anchor](#vm-state):

1. Nonce contract has its anchor computed from the nonce parameters (see [`nonce`](#nonce) instruction).
2. Claimed UTXO ([`input`](#input)) sets the VM’s [last anchor](#vm-state) to its _ratcheted_ [contract ID](#contract-id) (see [`input`](#input)).
3. Newly created contracts and outputs ([`contract`](#contract), [`output`](#contract)) consume the VM’s [last anchor](#vm-state) and replace it with its [contract ID](#contract-id).

VM fails if:

1. an [`issue`](#issue), [`output`](#output) or [`contract`](#contract) is invoked before the anchor is set,
2. by the end of the execution, no anchor was used (which means that [transaction ID](#transaction-id) is not unique).

Note 1: chaining the anchors this way gives flexibility to the signer:
if contract A creates contract B, the B's ID can be computed solely
from the contents of A, without the knowledge of the entire transaction.

Note 2: [`input`](#input) _ratchets_ the contract ID because this contract ID was already available as an anchor in the _previous transaction_ (where the output was created).


### Transcript

Transcript is an instance of the [Merlin](https://doc.dalek.rs/merlin/) construction,
which is itself based on [STROBE](https://strobe.sourceforge.io/) and [Keccak-f](https://keccak.team/keccak.html)
with 128-bit security parameter.

Transcript is used throughout ZkVM to generate challenge [scalars](#scalar) and commitments.

Transcripts have the following operations, each taking a label for domain separation:

1. **Initialize** transcript:
    ```    
    T := Transcript(label)
    ```
2. **Commit bytes** of arbitrary length:
    ```    
    T.commit(label, bytes)
    ```
3. **Challenge bytes**
    ```    
    T.challenge_bytes<size>(label) -> bytes
    ```
4. **Challenge scalar** is defined as generating 64 challenge bytes and reducing the 512-bit little-endian integer modulo Ristretto group order `|G|`:
    ```    
    T.challenge_scalar(label) -> scalar
    T.challenge_scalar(label) == T.challenge_bytes<64>(label) mod |G|
    ```

Labeled instances of the transcript can be precomputed
to reduce number of Keccak-f permutations to just one per challenge.


### Predicate

A _predicate_ is a representation of a condition that unlocks the [contract](#contract-type).
Predicate is encoded as a [point](#point) representing a node
of a [predicate tree](#predicate-tree).


### Predicate tree

A _predicate tree_ is a composition of [predicates](#predicate) and [programs](#program) that
provide a flexible way to open a [contract](#contract-type).

Each node in a predicate tree is formed with one of the following:

1. [Verification key](#verification-key): can be satisfied by signing a transaction using [`signtx`](#signtx) or signing and executing a program using [`delegate`](#delegate).
2. [Disjunction](#predicate-disjunction) of other predicates. Choice is made using [`left`](#left) and [`right`](#right) instructions.
3. [Program commitment](#program-predicate). The structure of the commitment prevents signing and requires user to reveal and evaluate the program using the [`call`](#call) instruction.


### Predicate disjunction

Disjunction of two predicates is implemented using a commitment `f` that
commits to _left_ and _right_ [predicates](#predicate) `L` and `R`
as a scalar factor on a [primary base point](#base-points) `B` added to the predicate `L`:

```
OR(L,R) = L + f(L, R)·B
```

Commitment scheme is defined using the [transcript](#transcript) protocol
by committing compressed 32-byte points `L` and `R` and squeezing a scalar
that is bound to both predicates:

```
T = Transcript("ZkVM.predicate")
T.commit("L", L)
T.commit("R", R)
f = T.challenge_scalar("f")
OR(L,R) = L + f·B
``` 

The choice between the branches is performed using [`left`](#left) and [`right`](#right) instructions.

Disjunction allows signing ([`signtx`](#signtx), [`delegate`](#delegate)) for the [key](#verification-key) `L` without
revealing the alternative predicate `R` using the adjusted secret scalar `dlog(L) + f(L,R)`.


### Program predicate

_Program predicate_ is a commitment to a [program](#program) made using
commitment scalar `h` on a [secondary base point](#base-points) `B2`:

```
PP(prog) = h(prog)·B2
```

Commitment scheme is defined using the [transcript](#transcript) protocol
by committing the program data and squeezing a scalar that is bound to it:

```
T = Transcript("ZkVM.predicate")
T.commit("prog", prog)
h = T.challenge_scalar("h")
PP(prog) = h·B2
```

Program predicate can be satisfied only via the [`call`](#call) instruction that takes a cleartext program string, verifies the commitment and evaluates the program. Use of the [secondary base point](#base-points) `B2` prevents using the predicate as a [verification key](#verification-key) and signing with `h` without executing the program.


### Program

A program is of type [data](#data-type) containing a sequence of ZkVM [instructions](#instructions).


### Contract payload

The contract payload is a list of [items](#types) stored in the [contract](#contract-type) or [output](#output-structure).

Payload of a [contract](#contract-type) may contain arbitrary [types](#types),
but in the [output](#output-structure) only the [portable types](#portable-types) are allowed.


### Output structure

Output is a serialized [contract](#contract-type):

```
      Output  =  Anchor || Predicate  ||  LE32(k)  ||  Item[0]  || ... ||  Item[k-1]
      Anchor  =  <32 bytes>
   Predicate  =  <32 bytes>
        Item  =  enum { Data, Value }
        Data  =  0x00  ||  LE32(len)  ||  <bytes>
       Value  =  0x01  ||  <32 bytes> ||  <32 bytes>
```

### UTXO

UTXO stands for Unspent Transaction [Output](#output-structure).
UTXO is uniquely identified by the [ID](#contract-id) of the contract represented by the output.

### Constraint system

The constraint system is the part of the [VM state](#vm-state) that implements
[Bulletproof's rank-1 constraint system](https://doc-internal.dalek.rs/develop/bulletproofs/notes/r1cs_proof/index.html).

It also keeps track of the [variables](#variable-type) and [constraints](#constraint-type),
and is used to verify the [constraint system proof](#constraint-system-proof).


### Constraint system proof

A proof of satisfiability of a [constraint system](#constraint-system) built during the VM execution.

The proof is provided to the VM at the beginning of execution and verified when the VM is [finished](#vm-execution).


### Transaction

Transaction is a structure that contains all data and logic
required to produce a unique [transaction ID](#transaction-id):

* Version (uint64)
* [Time bounds](#time-bounds) (pair of [LE64](#le64)s)
* [Program](#program) (variable-length [data](#data-type))
* [Transaction signature](#transaction-signature) (64 bytes)
* [Constraint system proof](#constraint-system-proof) (variable-length array of points and scalars)


### Transaction log

The *transaction log* contains entries that describe the effects of various instructions.

The transaction log is empty at the beginning of a ZkVM program. It is
append-only. Items are added to it upon execution of any of the
following instructions:

* [`input`](#input)
* [`output`](#output)
* [`issue`](#issue)
* [`retire`](#retire)
* [`nonce`](#nonce)
* [`log`](#log)
* [`import`](#import)
* [`export`](#export)

See the specification of each instruction for the details of which data is stored.

Note: transaction log items are only serialized when committed to a [transcript](#transcript)
during the [transaction ID](#transaction-id) computation.


### Transaction ID

Transaction ID is defined as a [merkle hash](#merkle-binary-tree) of a list consisting of 
a [header entry](#header-entry) followed by all the entries from the [transaction log](#transaction-log):

```
T = Transcript("ZkVM.txid")
txid = MerkleHash(T, {header} || txlog )
```

Entries are committed to the [transcript](#transcript) using the following schema.

#### Header entry

Header commits the transaction version and [time bounds](#time-bounds) using the [LE64](#le64) encoding.

```
T.commit("tx.version", LE64(version))
T.commit("tx.mintime", LE64(mintime))
T.commit("tx.maxtime", LE64(maxtime))
```

#### Input entry

Input entry is added using [`input`](#input) instruction.

```
T.commit("input", contract_id)
```

where `contract_id` is the [contract ID](#contract-id) of the claimed [UTXO](#utxo).

#### Output entry

Output entry is added using [`output`](#output) instruction.

```
T.commit("output", contract_id)
```

where `contract_id` is the [contract ID](#contract-id) of the newly created [UTXO](#utxo).

#### Issue entry

Issue entry is added using [`issue`](#issue) instruction.

```
T.commit("issue.q", qty_commitment)
T.commit("issue.f", flavor_commitment)
```

#### Retire entry

Retire entry is added using [`retire`](#retire) instruction.

```
T.commit("retire.q", qty_commitment)
T.commit("retire.f", flavor_commitment)
```

#### Nonce entry

Nonce entry is added using [`nonce`](#nonce) instruction.

```
T.commit("nonce.b", blockid)
T.commit("nonce.t", maxtime)
T.commit("nonce.n", nonce_anchor)
```

#### Data entry

Data entry is added using [`log`](#log) instruction.

```
T.commit("data", data)
```

#### Import entry

Import entry is added using [`import`](#import) instruction.

```
T.commit("import", proof)
```

#### Export entry

Export entry is added using [`export`](#export) instruction.

```
T.commit("export", metadata)
```



### Merkle binary tree

The construction of a merkle binary tree is based on the [RFC 6962 Section 2.1](https://tools.ietf.org/html/rfc6962#section-2.1)
with hash function replaced with a [transcript](#transcript).

Leafs and nodes in the tree use the same instance of a transcript provided by the upstream protocol:

```
T = Transcript(<label>)
```

The hash of an empty list is a 32-byte challenge string with the label `merkle.empty`:

```
MerkleHash(T, {}) = T.challenge_bytes("merkle.empty")
```

The hash of a list with one entry (also known as a leaf hash) is
computed by committing the entry to the transcript (defined by the item type),
and then generating 32-byte challenge string the label `merkle.leaf`:

```
MerkleHash(T, {item}) = {
    T.commit(<field1 name>, item.field1)
    T.commit(<field2 name>, item.field2)
    ...
    T.challenge_bytes("merkle.leaf")
}
```

For n > 1, let k be the largest power of two smaller than n (i.e., k < n ≤ 2k). The merkle hash of an n-element list is then defined recursively as:

```
MerkleHash(T, list) = {
    T.commit("L", MerkleHash(list[0..k]))
    T.commit("R", MerkleHash(list[k..n]))
    T.challenge_bytes("merkle.node")
}
```

Note that we do not require the length of the input list to be a power of two.
The resulting merkle binary tree may thus not be balanced; however,
its shape is uniquely determined by the number of leaves.


### Aggregated Signature

Aggregated Signature is a Schnorr proof of knowledge of a set of secret [scalars](#scalar)
corresponding
to some [verification keys](#verification-key) in a context of some _message_.

Aggregated Signature is encoded as a 64-byte [data](#data-type).

The protocol is the following:

1. Prover and verifier obtain a [transcript](#transcript) `T` that is assumed to be already bound to the _message_ being signed (see [`signtx`](#signtx) and [transaction signature](#transaction-signature)).
2. Commit the count `n` of verification keys as [LE32](#le32):
    ```
    T.commit("n", LE32(n))
    ```
3. Commit all verification keys `P[i]` one by one (in the order they were added during VM execution):
    ```
    T.commit("P", P[i])
    ```
4. For each key, generate a delinearizing scalar:
    ```
    x[i] = T.challenge_scalar("x")
    ```
5. Form an aggregated key without computing it right away:
    ```
    PA = x[0]·P[0] + ... + x[n-1]·P[n-1]
    ```
6. Prover creates a _secret nonce_: a randomly sampled [scalar](#scalar) `r`.
7. Prover commits to its nonce:
    ```
    R = r·B
    ```
8. Prover sends `R` to the verifier.
9. Prover and verifier write the nonce commitment `R` to the transcript:
    ```
    T.commit("R", R)
    ```
10. Prover and verifier compute a Fiat-Shamir challenge scalar `e` using the transcript:
    ```
    e = T.challenge_scalar("e")
    ```
11. Prover blinds the secrets `dlog(P[i])` using the nonce and the challenge:
    ```
    s = r + e·sum{x[i]·dlog(P[i])}
    ```
12. Prover sends `s` to the verifier.
13. Verifier checks the relation:
    ```
    s·B  ==  R + e·PA
         ==  R + (e·x[0])·P[0] + ... + (e·x[n-1])·P[n-1]
    ```

Note: if the signing is performed by independent mistrusting parties, it should use pre-commitments to the nonces.
The MPC protocol for safe aggregated signing is outside the scope of this specification because it does not affect the verification protocol.

### Transaction signature

Instruction [`signtx`](#signtx) unlocks a contract if its [predicate](#predicate)
correctly signs the [transaction ID](#transaction-id). The contract‘s predicate
is added to the array of deferred [verification keys](#verification-key) that
are later aggregated in a single key and a Schnorr [signature](#aggregated-signature) protocol
is executed for the [transaction ID](#transaction-id).

Aggregated signature verification protocol is based on the [MuSig](https://eprint.iacr.org/2018/068) scheme, but with
Fiat-Shamir transform defined through the use of the [transcript](#transcript) instead of a composition of hash function calls.

1. Instantiate the [transcript](#transcript) `TA` for transaction signature:
    ```
    T = Transcript("ZkVM.signtx")
    ```
2. Commit the [transaction ID](#transaction-id):
    ```
    T.commit("txid", txid)
    ```
3. Perform the [aggregated signature protocol](#aggregated-signature) using the transcript `T`.
4. Add the verifier's statement to the list of [deferred point operations](#deferred-point-operations).


### Unblinding proof

Unblinding proof shows the committed value `v` and proves
that the blinding factor in the [Pedersen commitment](#pedersen-commitment) is zero:

```
V == v·B + 0·B2
```

1. Prover shows `v`.
2. Verifier checks equality `V == v·B`.




## VM operation

### VM state

The ZkVM state consists of the static attributes and the state machine attributes.

1. [Transaction](#transaction):
    * `version`
    * `mintime` and `maxtime`
    * `program`
    * `tx_signature`
    * `cs_proof`
2. Extension flag (boolean)
3. Last [anchor](#anchor) or ∅ if unset
4. Data stack (array of [items](#types))
5. Program stack (array of [programs](#program) with their offsets)
6. Current [program](#program) with its offset
7. [Transaction log](#transaction-log) (array of logged items)
8. Transaction signature verification keys (array of [points](#point))
9. [Deferred point operations](#deferred-point-operations)
10. [Constraint system](#constraint-system)


### VM execution

The VM is initialized with the following state:

1. [Transaction](#transaction) as provided by the user.
2. Extension flag set to `true` or `false` according to the [transaction versioning](#versioning) rules for the transaction version.
3. Last anchor is set to ∅.
4. Data stack is empty.
5. Program stack is empty.
6. Current program set to the transaction program; with zero offset.
7. Transaction log is empty.
8. Array of signature verification keys is empty.
9. Array of deferred point operations is empty.
10. Constraint system: empty (time bounds are constants that appear only within linear combinations of actual variables), with [transcript](#transcript) initialized with label `ZkVM.r1cs`:
    ```
    r1cs_transcript = Transcript("ZkVM.r1cs")
    ```

Then, the VM executes the current program till completion:

1. Each instruction is read at the current program offset, including its immediate data (if any).
2. Program offset is advanced immediately after reading the instruction to the next instruction.
3. The instruction is executed per [specification below](#instructions). If the instruction fails, VM exits early with an error result.
4. If VM encounters [`call`](#call) or [`delegate`](#delegate) instruction, the new program with offset zero is set as the current program. The next iteration of the vm will start from the beginning of the new program.
5. If the offset is less than the current program’s length, a new instruction is read (go back to step 1).
6. Otherwise (reached the end of the current program):
   1. If the program stack is not empty, pop top item from the program stack and set it to the current program. Go to step 5.
   2. If the program stack is empty, the transaction is considered _finalized_ and VM successfully finishes execution.

If the execution finishes successfully, VM performs the finishing tasks:
1. Checks if the stack is empty; fails otherwise.
2. Checks if the [last anchor](#vm-state) is set; fails otherwise.
3. Computes [transaction ID](#transaction-id).
4. Computes a verification statement for [transaction signature](#transaction-signature).
5. Computes a verification statement for [constraint system proof](#constraint-system-proof).
6. Executes all [deferred point operations](#deferred-point-operations), including aggregated transaction signature and constraint system proof, using a single multi-scalar multiplication. Fails if the result is not an identity point.

If none of the above checks failed, the resulting [transaction log](#transaction-log) is _applied_
to the blockchain state as described in the blockchain specification (TBD).


### Deferred point operations

VM defers operations on [points](#point) till the end of the transaction in order
to batch them with the verification of [transaction signature](#transaction-signature) and
[constraint system proof](#constraint-system-proof).

Each deferred operation at index `i` represents a statement:
```
0  ==  sum{s[i,j]·P[i,j], for all j}  +  a[i]·B  +  b[i]·B2
```
where:
1. `{s[i,j],P[i,j]}` is an array of ([scalar](#scalar),[point](#point)) tuples,
2. `a[i]` is a [scalar](#scalar) weight of a [primary base point](#base-points) `B`,
3. `b[i]` is a [scalar](#scalar) weight of a [secondary base point](#base-points) `B2`.

All such statements are combined using the following method:

1. For each statement, a random [scalar](#scalar) `x[i]` is sampled.
2. Each weight `s[i,j]` is multiplied by `x[i]` for all weights per statement `i`:
    ```
    z[i,j] = x[i]·s[i,j]
    ```
3. All weights `a[i]` and `b[i]` are independently added up with `x[i]` factors:
    ```
    a = sum{a[i]·x[i]}
    b = sum{b[i]·x[i]}
    ```
4. A single multi-scalar multiplication is performed to verify the combined statement:
    ```
    0  ==  sum{z[i,j]·P[i,j], for all i,j}  +  a·B  +  b·B2
    ```


### Versioning

1. Each transaction has a version number. Each
   block (reference TBD) also has a version number.
2. Block version numbers must be monotonically non-decreasing: each
   block must have a version number equal to or greater than the
   version of the block before it.
3. The **current block version** is 1. The **current transaction
   version** is 1.

Extensions:

1. If the block version is equal to the **current block version**, no
   transaction in the block may have a version higher than the
   **current transaction version**.
2. If a transaction’s version is higher than the **current transaction
   version**, the ZkVM `extension` flag is set to `true`. Otherwise,
   the `extension` flag is set to `false`.




## Instructions

Each instruction is represented by a one-byte **opcode** optionally followed by **immediate data**.
Immediate data is denoted by a colon `:` after the instruction name.

Each instruction defines the format for immediate data. See the reference below for detailed specification.

Code | Instruction                | Stack diagram                              | Effects
-----|----------------------------|--------------------------------------------|----------------------------------
 |     [**Stack**](#stack-instructions)               |                        |
0x00 | [`push:n:x`](#push)        |                 ø → _data_                 |
0x01 | [`drop`](#drop)            |               _x_ → ø                      |
0x02 | [`dup:k`](#dup)            |     _x[k] … x[0]_ → _x[k] ... x[0] x[k]_   |
0x03 | [`roll:k`](#roll)          |     _x[k] … x[0]_ → _x[k-1] ... x[0] x[k]_ |
 |                                |                                            |
 |     [**Constraints**](#constraint-system-instructions)  |                   | 
0x04 | [`const`](#var)            |          _scalar_ → _expr_                 | 
0x05 | [`var`](#var)              |           _point_ → _var_                  | Adds an external variable to [CS](#constraint-system)
0x06 | [`alloc`](#alloc)          |                 ø → _expr_                 | Allocates a low-level variable in [CS](#constraint-system)
0x07 | [`mintime`](#mintime)      |                 ø → _expr_                 |
0x08 | [`maxtime`](#maxtime)      |                 ø → _expr_                 |
0x09 | [`expr`](#expr)            |             _var_ → _expr_                 | Allocates a variable in [CS](#constraint-system)
0x0a | [`neg`](#neg)              |           _expr1_ → _expr2_                |
0x0b | [`add`](#add)              |     _expr1 expr2_ → _expr3_                |
0x0c | [`mul`](#mul)              |     _expr1 expr2_ → _expr3_                | Potentially adds multiplier in [CS](#constraint-system)
0x0d | [`eq`](#eq)                |     _expr1 expr2_ → _constraint_           | 
0x0e | [`range:n`](#range)        |            _expr_ → _expr_                 | Modifies [CS](#constraint-system)
0x0f | [`and`](#and)              | _constr1 constr2_ → _constr3_              |
0x10 | [`or`](#or)                | _constr1 constr2_ → _constr3_              |
0x11 | [`verify`](#verify)        |      _constraint_ → ø                      | Modifies [CS](#constraint-system) 
0x12 | [`unblind`](#unblind)      |        _v V expr_ → _var_                  | Modifies [CS](#constraint-system), [Defers point ops](#deferred-point-operations)
 |                                |                                            |
 |     [**Values**](#value-instructions)              |                        |
0x13 | [`issue`](#issue)          |    _qty flv data pred_ → _contract_        | Modifies [CS](#constraint-system), [tx log](#transaction-log), [defers point ops](#deferred-point-operations)
0x14 | [`borrow`](#borrow)        |         _qty flv_ → _–V +V_                | Modifies [CS](#constraint-system)
0x15 | [`retire`](#retire)        |           _value_ → ø                      | Modifies [CS](#constraint-system), [tx log](#transaction-log)
0x16 | [`cloak:m:n`](#cloak)      | _widevalues commitments_ → _values_        | Modifies [CS](#constraint-system)
0x17 | [`import`](#import)        |   _proof qty flv_ → _value_                | Modifies [CS](#constraint-system), [tx log](#transaction-log), [defers point ops](#deferred-point-operations)
0x18 | [`export`](#export)        |       _value ???_ → ø                      | Modifies [CS](#constraint-system), [tx log](#transaction-log)
 |                                |                                            |
 |     [**Contracts**](#contract-instructions)        |                        |
0x19 | [`input`](#input)          |      _prevoutput_ → _contract_             | Modifies [tx log](#transaction-log)
0x1a | [`output:k`](#output)      |   _items... pred_ → ø                      | Modifies [tx log](#transaction-log)
0x1b | [`contract:k`](#contract)  |   _items... pred_ → _contract_             | 
0x1c | [`nonce`](#nonce)          |    _pred blockid_ → _contract_             | Modifies [tx log](#transaction-log)
0x1d | [`log`](#log)              |            _data_ → ø                      | Modifies [tx log](#transaction-log)
0x1e | [`signtx`](#signtx)        |        _contract_ → _results..._           | Modifies [deferred verification keys](#transaction-signature)
0x1f | [`call`](#call)            | _contract salt prog_ → _results..._        | [Defers point operations](#deferred-point-operations)
0x20 | [`left`](#left)            |    _contract A B_ → _contract’_            | [Defers point operations](#deferred-point-operations)
0x21 | [`right`](#right)          |    _contract A B_ → _contract’_            | [Defers point operations](#deferred-point-operations)
0x22 | [`delegate`](#delegate)    |_contract prog sig_ → _results..._          | [Defers point operations](#deferred-point-operations)
  —  | [`ext`](#ext)              |                 ø → ø                      | Fails if [extension flag](#vm-state) is not set.




### Stack instructions

#### push

**push:_n_:_x_** → _data_

Pushes a [data](#data-type) `x` containing `n` bytes. 
Immediate data `n` is encoded as [LE32](#le32)
followed by `x` encoded as a sequence of `n` bytes.


#### drop

_x_ **drop** → ø

Drops `x` from the stack.

Fails if `x` is not a [copyable type](#copyable-types).


#### dup

_x[k] … x[0]_ **dup:_k_** → _x[k] ... x[0] x[k]_

Copies k’th data item from the top of the stack.
Immediate data `k` is encoded as [LE32](#le32).

Fails if `x[k]` is not a [copyable type](#copyable-types).


#### roll

_x[k] x[k-1] ... x[0]_ **roll:_k_** → _x[k-1] ... x[0] x[k]_

Looks past `k` items from the top, and moves the next item to the top of the stack.
Immediate data `k` is encoded as [LE32](#le32).

Note: `roll:0` is a no-op, `roll:1` swaps the top two items.




### Constraint system instructions

#### const

_a_ **const** → _expr_

1. Pops a [scalar](#scalar) `a` from the stack.
2. Creates an [expression](#expression-type) `expr` with weight `a` assigned to an R1CS constant `1`.
3. Pushes `expr` to the stack.

Fails if `a` is not a valid [scalar](#scalar).

#### var

_P_ **var** → _v_

1. Pops a [point](#point) `P` from the stack.
2. Creates a [variable](#variable-type) `v` from a [Pedersen commitment](#pedersen-commitment) `P`.
3. Pushes `v` to the stack.

Fails if `P` is not a valid [point](#point).

#### alloc

**alloc** → _expr_

1. Allocates a low-level variable in the [constraint system](#constraint-system) and wraps it in the [expression](#expression-type) with weight 1.
2. Pushes the resulting expression to the stack.

This is different from [`var`](#var): the variable created by `alloc` is _not_ represented by an individual Pedersen commitment and therefore can be chosen freely when the transaction is constructed.


#### mintime

**mintime** → _expr_

Pushes an [expression](#expression-type) `expr` corresponding to the [minimum time bound](#time-bounds) of the transaction.

The one-term expression represents time bound as a weight on the R1CS constant `1` (see [`const`](#const)).

#### maxtime

**maxtime** → _expr_

Pushes an [expression](#expression-type) `expr` corresponding to the [maximum time bound](#time-bounds) of the transaction.

The one-term expression represents time bound as a weight on the R1CS constant `1` (see [`const`](#const)).

#### expr

_var_ **expr** → _ex_

1. Pops a [variable](#variable-type) `var`.
2. Allocates a high-level variable in the constraint system using its Pedersen commitment.
3. Pushes a single-term [expression](#expression-type) with weight=1 to the stack: `expr = { (1, var) }`.

Fails if `var` is not a [variable type](#variable-type).

#### neg

_ex1_ **neg** → _ex2_

1. Pops an [expression](#expression-type) `ex1`.
2. Negates the weights in the `ex1` producing new expression `ex2`.
3. Pushes `ex2` to the stack.

Fails if `ex1` is not an [expression type](#expression-type).

#### add

_ex1 ex2_ **add** → ex3_

1. Pops two [expressions](#expression-type) `ex2`, then `ex1`.
2. If both expressions are [constant expressions](#constant-expression):
    1. Creates a new [constant expression](#constant-expression) `ex3` with the weight equal to the sum of weights in `ex1` and `ex2`.
3. Otherwise, creates a new expression `ex3` by concatenating terms in `ex1` and `ex2`.
4. Pushes `ex3` to the stack.

Fails if `ex1` and `ex2` are not both [expression types](#expression-type).

#### mul

_ex1 ex2_ **mul** → _ex3_

Multiplies two [expressions](#expression-type) producing another [expression](#expression-type) representing the result of multiplication.

This performs a _guaranteed optimization_: if one of the expressions `ex1` or `ex2` contains
only one term and this term is for the variable representing the R1CS constant `1`
(in other words, the statement is a cleartext constant),
then the other expression is multiplied by that constant in-place without allocating a multiplier in the [constraint system](#constraint-system).

This optimization is _guaranteed_ because it affects the state of the constraint system:
not performing it would make the existing proofs invalid.

1. Pops two [expressions](#expression-type) `ex2`, then `ex1`.
2. If either `ex1` or `ex2` is a [constant expression](#constant-expression):
    1. The other expression is multiplied in place by the scalar from that expression.
    2. The resulting expression is pushed to the stack.
3. Otherwise:
    1. Creates a multiplier in the constraint system.
    2. Constrains the left wire to `ex1`, and the right wire to `ex2`.
    3. Creates an [expression](#expression-type) `ex3` with the output wire in its single term.
    4. Pushes `ex3` to the stack.

Fails if `ex1` and `ex2` are not both [expression types](#expression-type).

Note: if both `ex1` and `ex2` are [constant expressions](#constant-expression),
the result does not depend on which one treated as a constant,
and the resulting expression is also a constant expression.

#### eq

_ex1 ex2_ **eq** → _constraint_

1. Pops two [expressions](#expression-type) `ex2`, then `ex1`.
2. Creates a [constraint](#constraint-type) that represents statement `ex1 - ex2 = 0`.
3. Pushes the constraint to the stack.

Fails if `ex1` and `ex2` are not both [expression types](#expression-type).

#### range

_expr_ **range:_n_** → _expr_

1. Pops an [expression](#expression-type) `expr`.
2. Adds an `n`-bit range proof for `expr` to the [constraint system](#constraint-system) (see [Cloak protocol](../../spacesuit/spec.md) for the range proof definition).
3. Pushes `expr` back to the stack.

Immediate data `n` is encoded as one byte.

Fails if `expr` is not an [expression type](#expression-type) or if `n` is not in range [0, 64].

#### and

_c1 c2_ **and** → _c3_

1. Pops [constraints](#constraint-type) `c2`, then `c1`.
2. Creates a _conjunction constraint_ `c3` containing `c1` and `c2`.
3. Pushes `c3` to the stack.

No changes to the [constraint system](#constraint-system) are made until [`verify`](#verify) is executed.

Fails if `c1` and `c2` are not [constraints](#constraint-type).

#### or

_constraint1 constraint2_ **or** → _constraint3_

1. Pops [constraints](#constraint-type) `c2`, then `c1`.
2. Creates a _disjunction constraint_ `c3` containing `c1` and `c2`.
3. Pushes `c3` to the stack.

No changes to the [constraint system](#constraint-system) are made until [`verify`](#verify) is executed.

Fails if `c1` and `c2` are not [constraints](#constraint-type).

#### verify

_constr_ **verify** → ø

1. Pops [constraint](#constraint-type) `constr`.
2. Transforms the constraint `constr` recursively using the following rules:
    1. Replace conjunction of two _linear constraints_ `a` and `b` with a linear constraint `c` by combining both constraints with a random challenge `z`:
        ```
        z = transcript.challenge_scalar(b"ZkVM.verify.and-challenge");
        c = a + z·b
        ```
    2. Replace disjunction of two _linear constraints_ `a` and `b` by constrainting an output `o` of a newly allocated multiplier `{r,l,o}` to zero, while adding constraints `r == a` and `l == b` to the constraint system.
        ```
        r == a # added to CS
        l == b # added to CS
        o == 0 # replaces OR(a,b)
        ```
    3. Conjunctions and disjunctions of non-linear constraints are transformed via rules (1) and (2) using depth-first recursion.
3. The resulting single linear constraint is added to the constraint system.

Fails if `constr` is not a [constraint](#constraint-type).


#### unblind

_v V expr_ **unblind** → _var_

1. Pops [expression](#expression-type) `expr`.
2. Pops [point](#point) `V`.
3. Pops [scalar](#scalar) `v`.
4. Creates a new [variable](#variable-type) `var` with commitment `V`.
5. Verifies the [unblinding proof](#unblinding-proof) for the commitment `V` and scalar `v`, [deferring all point operations](#deferred-point-operations)).
6. Adds an equality [constraint](#constraint-type) `expr == var` to the [constraint system](#constraint-system).
7. Pushes `var` to the stack.

Fails if: 
* `v` is not a valid [scalar](#scalar), or
* `V` is not a valid [point](#point), or
* `expr` is not an [expression](#expression-type).



### Value instructions

#### issue

_qty flv metadata pred_ **issue** → _contract_

1. Pops [point](#point) `pred`.
2. Pops [data](#data-type) `metadata`.
3. Pops [variable](#variable-type) `flv` and commits it to the constraint system.
4. Pops [variable](#variable-type) `qty` and commits it to the constraint system.
5. Creates a [value](#value-type) with variables `qty` and `flv` for quantity and flavor, respectively. 
6. Computes the _flavor_ scalar defined by the [predicate](#predicate) `pred` using the following [transcript-based](#transcript) protocol:
    ```
    T = Transcript("ZkVM.issue")
    T.commit("predicate", pred)
    T.commit("metadata", metadata)
    flavor = T.challenge_scalar("flavor")
    ```
6. Checks that the `flv` has unblinded commitment to `flavor`
   by [deferring the point operation](#deferred-point-operations):
    ```
    flv == flavor·B
    ```
7. Adds a 64-bit range proof for the `qty` to the [constraint system](#constraint-system)
   (see [Cloak protocol](../../spacesuit/spec.md) for the range proof definition).
8. Adds an [issue entry](#issue-entry) to the [transaction log](#transaction-log).
9. Creates a [contract](#contract-type) with the value as the only [payload](#contract-payload),
   protected by the predicate `pred`, consuming [VM’s last anchor](#vm-state)
   and replacing it with this contract’s [ID](#contract-id).

The value is now issued into the contract that must be unlocked
using one of the contract instructions: [`signtx`](#signtx), [`delegate`](#delegate) or [`call`](#call).

Fails if:
* `pred` is not a valid [point](#point),
* `flv` or `qty` are not [variable types](#variable-type),
* VM’s [last anchor](#vm-state) is not set.


#### borrow

_qty flv_ **borrow** → _–V +V_

1. Pops [variable](#variable-type) `flv` and commits it to the constraint system.
2. Pops [variable](#variable-type) `qty` and commits it to the constraint system.
3. Creates a [value](#value-type) `+V` with variables `qty` and `flv` for quantity and flavor, respectively.
4. Adds a 64-bit range proof for `qty` variable to the [constraint system](#constraint-system) (see [Cloak protocol](../../spacesuit/spec.md) for the range proof definition).
5. Creates [wide value](#wide-value-type) `–V`, allocating a low-level variable `qty2` for the negated quantity and reusing the flavor variable `flv`.
6. Adds a constraint `qty2 == -qty` to the constraint system.
7. Pushes `–V`, then `+V` to the stack.

The wide value `–V` is not a [portable type](#portable-types), and can only be consumed by a [`cloak`](#cloak) instruction
(where it is merged with appropriate positive quantity of the same flavor).

Fails if `qty` and `flv` are not [variable types](#variable-type).


#### retire

_value_ **retire** → ø

1. Pops a [value](#value-type) from the stack.
2. Adds a _retirement_ entry to the [transaction log](#transaction-log).

Fails if the value is not a [non-negative value type](#value-type).

#### cloak

_widevalues commitments_ **cloak:_m_:_n_** → _values_

Merges and splits `m` [wide values](#wide-value-type) into `n` [values](#value-type).

1. Pops `2·n` [points](#point) as pairs of _flavor_ and _quantity_ for each output value, flavor is popped first in each pair.
2. Pops `m` [wide values](#wide-value-type) as input values.
3. Creates constraints and 64-bit range proofs for quantities per [Cloak protocol](../../spacesuit/spec.md).
4. Pushes `n` [values](#value-type) to the stack, placing them in the same order as their corresponding commitments.

Immediate data `m` and `n` are encoded as two [LE32](#le32)s.


#### import

_proof qty flv_ **import** → _value_

1. Pops [variable](#variable-type) `flv` and commits it to the constraint system.
2. Pops [variable](#variable-type) `qty` and commits it to the constraint system.
3. Pops [data](#data-type) `proof`.
4. Creates a [value](#value-type) with variables `qty` and `flv` for quantity and flavor, respectively. 
5. Computes the _flavor_ scalar defined by the [predicate](#predicate) `pred` using the following [transcript-based](#transcript) protocol:
    ```
    T = Transcript("ZkVM.import")
    T.commit("extflavor", proof.external_flavor_id)
    T.commit("extaccount", proof.pegging_account_id)
    flavor = T.challenge_scalar("flavor")
    ```
6. Checks that the `flv` has unblinded commitment to `flavor` by [deferring the point operation](#deferred-point-operations):
    ```
    flv == flavor·B
    ```
7. Checks that the `qty` has unblinded commitment to `quantity` by [deferring the point operation](#deferred-point-operations):
    ```
    qty == proof.quantity·B
    ```
8. Adds an [import entry](#import-entry) with `proof` to the [transaction log](#transaction-log).
9. Pushes the imported value to the stack.

Note: the `proof` data contains necessary metadata to check if the value is pegged on the external blockchain.
It is verified when the transaction is applied to the blockchain state.

TBD: definition of the proof data (quantity, asset id, pegging account, identifier of the pegging transaction)

Fails if:
* `flv` or `qty` are not [variable types](#variable-type),
* `proof` is not a [data type](#data-type).



#### export

_metadata value_ **export** → ø

1. Pops [value](#value-type).
2. Pops [data](#data-type) `metadata`.
3. Computes the local flavor based on the pegging metadata:
    ```
    T = Transcript("ZkVM.import")
    T.commit("extflavor", metadata.external_flavor_id)
    T.commit("extaccount", metadata.pegging_account_id)
    flavor = T.challenge_scalar("flavor")
    ```
4. Adds two constraints to the constraint system using cleartext quantity and flavor in the metadata:
    ```
    value.qty == metadata.qty
    value.flv == flavor
    ```
5. Adds an [export entry](#export-entry) with `metadata` to the [transaction log](#transaction-log).

TBD: definition of the metadata data (quantity, asset id, pegging account, target address/accountid)

Fails if:
* `value` is not a [non-negative value type](#value-type),
* `metadata` is not a [data type](#data-type).



### Contract instructions


#### input

_prevoutput_ **input** → _contract_

1. Pops a [data](#data-type) `prevoutput` representing the [unspent output structure](#output-structure) from the stack.
2. Constructs a [contract](#contract-type) based on the `prevoutput` data and pushes it to the stack.
3. Adds [input entry](#input-entry) to the [transaction log](#transaction-log).
4. Sets the [VM’s last anchor](#vm-state) to the ratcheted [contract ID](#contract-id):
    ```
    T = Transcript("ZkVM.ratchet-anchor")
    T.commit("old", contract_id)
    new_anchor = T.challenge_bytes("new")
    ```

Fails if the `prevoutput` is not a [data type](#data-type) with exact encoding of an [output structure](#output-structure).


#### output

_items... predicate_ **output:_k_** → ø

1. Pops [`predicate`](#predicate) from the stack.
2. Pops `k` items from the stack.
3. Creates a contract with the `k` items as a payload, the predicate `pred`, and anchor set to the [VM’s last anchor](#vm-state).
4. Adds an [output entry](#output-entry) to the [transaction log](#transaction-log).
5. Updates the [VM’s last anchor](#vm-state) with the [contract ID](#contract-id) of the new contract.

Immediate data `k` is encoded as [LE32](#le32).

Fails if VM’s [last anchor](#vm-state) is not set.


#### contract

_items... pred_ **contract:_k_** → _contract_

1. Pops [predicate](#predicate) `pred` from the stack.
2. Pops `k` items from the stack.
3. Creates a contract with the `k` items as a payload, the predicate `pred`, and anchor set to the [VM’s last anchor](#vm-state).
4. Pushes the contract onto the stack.
5. Update the [VM’s last anchor](#vm-state) with the [contract ID](#contract-id) of the new contract.

Immediate data `k` is encoded as [LE32](#le32).

Fails if VM’s [last anchor](#vm-state) is missing.

#### nonce

_pred blockid_ **nonce** → _contract_

1. Pops [32-byte string](#data-type) `blockid` from the stack.
2. Pops [predicate](#predicate) `pred` from the stack.
3. Computes the nonce [anchor](#anchor) value:
    ```
    T = Transcript("ZkVM.nonce")
    T.commit("blockid", blockid)
    T.commit("predicate", pred)
    T.commit("maxtime", LE64(tx.maxtime))
    nonce_anchor = T.challenge_bytes("anchor")
    ```
4. Pushes a new [contract](#contract-type) with:
    * an empty [payload](#contract-payload)
    * predicate set to `pred`
    * anchor set to `nonce_anchor`.
5. Sets the [VM’s last anchor](#vm-state) to [contract ID](#contract-id) of that contract.
6. Adds [nonce entry](#nonce-entry) to the [transaction log](#transaction-log) with the `blockid`, transaction [maxtime](#time-bounds) and `nonce_anchor`.

Fails if:
* `blockid` is a not a 32-byte [data string](#data-type).
* `pred` is not a valid [point](#point).

**Discussion**

A nonce serves two purposes:

1. It provides a unique anchor for an issuing transaction if other anchors are not available (i.e., from other values already on the stack);
2. It binds the entire transaction to a particular blockchain, protecting not only against cross-blockchain replays, but also potential blockchain forks. This is a necessary feature for stateless signing devices that rely on blockchain proofs.

Blockchain state machine performs the following checks:

1. The `blockid` is checked against the IDs of “recent” blocks when the transaction is applied to the blockchain. It must match a recent block, or the initial block of the blockchain.
2. The `nonce_anchor` is checked for uniqueness against “recent” nonce anchors.

To perform these checks, validators must keep a set of recent nonces and a set of recent block headers available. For scalability and to reduce resource demands on the network, these sets must be limited in size. So verifiers can and should impose reasonable limits on the value of exp (which is the time by which the transaction must be included in a block or become invalid).

To support long-living pre-signed transactions, the protocol allows a nonce to use the blockchain’s initial block ID regardless of the `refscount` limit specified in the block headers.


#### log

_data_ **log** → ø

1. Pops `data` from the stack.
2. Adds [data entry](#data-entry) with it to the [transaction log](#transaction-log).

Fails if the item is not a [data type](#data-type).


#### signtx

_contract_ **signtx** → _results..._

1. Pops the [contract](#contract-type) from the stack.
2. Adds the contract’s [predicate](#predicate) as a [verification key](#verification-key)
   to the list of deferred keys for [aggregated transaction signature](#transaction-signature)
   check at the end of the VM execution.
3. Places the [payload](#contract-payload) on the stack (last item on top), discarding the contract.

Note: the instruction never fails as the only check (signature verification)
is deferred until the end of VM execution.


#### call

_contract(P) salt prog_ **call** → _results..._

1. Pops the [data](#data-type) `prog`, its associated [data](#data-type) `salt`, and a [contract](#contract-type) `contract`.
2. Reads the [predicate](#predicate) `P` from the contract and its salt.
3. Forms a statement for [program predicate](#program-predicate) of `prog` being equal to `P`:
    ```
    0 == -P + h(prog)·B2
    ```
4. Adds the statement to the [deferred point operations](#deferred-point-operations).
5. Places the [payload](#contract-payload) on the stack (last item on top), discarding the contract.
6. Set the `prog` as current.

Fails if either of the top two item is not a [data](#data-type) or
the third-from-the-top is not a [contract](#contract-type).


#### left

_contract(P) L R_ **left** → _contract(L)_

1. Pops the right [predicate](#predicate) `R`, then the left [predicate](#predicate) `L` and a [contract](#contract-type) `contract`.
2. Reads the [predicate](#predicate) `P` from the contract.
3. Forms a statement for [predicate disjunction](#predicate-disjunction) of `L` and `R` being equal to `P`:
    ```
    0 == -P + L + f(L, R)·B
    ```
4. Adds the statement to the [deferred point operations](#deferred-point-operations).
5. Replaces the contract’s predicate with `L` and pushes the contract back onto the stack.

Fails if the top two items are not valid [points](#point),
or if the third from the top item is not a [contract](#contract-type).


#### right

_contract(P) L R_ **right** → _contract(R)_

1. Pops the right [predicate](#predicate) `R`, then the left [predicate](#predicate) `L` and a [contract](#contract-type) `contract`.
2. Reads the [predicate](#predicate) `P` from the contract.
3. Forms a statement of [predicate disjunction](#predicate-disjunction) of `L` and `R` being equal to `P`:
    ```
    0 == -P + L + f(L, R)·B
    ```
4. Adds the statement to the deferred point operations.
5. Replaces the contract’s predicate with `R` and pushes the contract back onto the stack.

Fails if the top two items are not valid [points](#point),
or if the third from the top item is not a [contract](#contract-type).


#### delegate

_contract prog sig_ **delegate** → _results..._

1. Pop [data](#data-type) `sig`, [data](#data-type) `prog` and the [contract](#contract-type) from the stack.

2. Place the [contract payload](#contract-payload) on the stack (last item on top), discarding the contract.

3. Instantiate the [transcript](#transcript):
    ```
    T = Transcript("ZkVM.delegate")
    ```
4. Commit the program `prog` to the transcript:
    ```
    T.commit("prog", prog)
    ```
5. Extract nonce commitment `R` and scalar `s` from a 64-byte data `sig`:
    ```
    R = sig[ 0..32]
    s = sig[32..64]
    ```
6. Perform the [signature protocol](#aggregated-signature) using the transcript `T`, public key `contract.predicate` and the values `R` and `s`:
    ```
    (s = dlog(R) + e·dlog(P))
    s·B  ==  R + e·P
    ```
7. Add the statement to the list of [deferred point operations](#deferred-point-operations).
8. Set the `prog` as current.

Fails if:
1. the `sig` is not a 64-byte long [data](#data-type),
2. or `prog` is not a [data type](#data-type),
3. or `contract` is not a [contract type](#contract-type).


#### ext

ø **ext** → ø

All unassigned instruction codes are interpreted as no-ops. This are reserved for use in the future versions of the VM.

See [Versioning](#versioning).

## Transaction Encoding

A [Transaction](#transaction) is serialized as follows:

```
        SerializedTx = TxHeader || LE32(len(Program)) || Program || Signature || Proof
        TxHeader = LE64(version) || LE64(mintime) || LE64(maxtime)
        Program = <len(Program) bytes>
        Signature = <64 bytes>
        Proof = <14·32 + len(InnerProductProof) bytes>
```

## Examples

### Lock value example

Locks value with a public key.

```
... (<value>) <pubkey> output:1
```

### Unlock value example

Unlocks a simple contract that locked a single value with a public key.
The unlock is performed by claiming the [input](#input) and [signing](#signtx) the transaction.

```
<serialized_input> input signtx ...
```

### Simple payment example

Unlocks three values from the existing [inputs](#input),
recombines them into a payment to address `A` (pubkey) and a change `C`:

```
<input1> input signtx
<input2> input signtx
<input3> input signtx
<FC> <QC> <FA> <QA> cloak:3:2  # flavor and quantity commitments for A and C
<A> output:1
<C> output:1
```

### Multisig

Multi-signature predicate can be constructed in three ways:

1. For N-of-N schemes, a set of independent public keys can be merged using a [MuSig](https://eprint.iacr.org/2018/068) scheme as described in [transaction signature](#transaction-signature). This allows non-interactive key generation, and only a simple interactive signing protocol.
2. For threshold schemes (M-of-N, M ≠ N), a single public key can be constructed using a variant of a Feldman-VSS scheme, but this requires interactive key generation.
3. Small-size threshold schemes can be instantiated non-interactively using a [predicate tree](#predicate-tree). Most commonly, 2-of-3 "escrow" scheme can be implemented as 2 keys aggregated as the main branch for the "happy path" (escrow party not involved), while the other two combinations aggregated in the nested branches.

Note that all three approaches minimize computational costs and metadata leaks, unlike Bitcoin, Stellar and TxVM where all keys are enumerated and checked independently.


### Offer example

Offer is a cleartext contract that can be _cancelled_ by the owner or _lifted_ by an arbitrary _taker_.

Offer locks the value being sold and stores the price as a pair of commitments: for the flavor and quantity.

The _cancellation_ clause is simply a [predicate](#predicate) formed by the maker’s public key.

The _lift_ clause when chosen by the taker, [borrows](#borrow) the payment amount according to the embedded price,
makes an [output](#output) with the positive payment value and leaves to the taker a negative payment and the unlocked value.
The taker than merges the negative payment and the value together with their actual payment using the [cloak](#cloak) instruction,
and create an output for the lifted value.

```
contract Offer(value, price, maker) {
    OR(
        maker,
        {
            let (payment, negative_payment) = borrow(price.qty, price.flavor)
            output(payment, maker)
            return (negative_payment, value)
        }
    )
}
```

Lift clause bytecode:

```
<priceqty> <priceflavor> borrow <makerpubkey> output:1
```

To make it discoverable, each transaction that creates an offer output also creates a [data entry](#data-entry)
describing the value quantity and flavor, and the price quantity and flavor in cleartext format.
This way the offer contract does not need to perform any additional computation or waste space for cleartext scalars.

Bytecode creating the offer:

```
<value> <offer predicate> output:1 "Offer: 1 BTC for 3745 USD" data
```

The programmatic API for creating, indexing and interacting with offers ties all parts together.

### Offer with partial lift

TBD: 

Sketch:
price = rational X/Y, total value = V, payment: P, change: C;  
constraint: `(V - C)*X == Y*P`.
contract unlocks V, `borrow`s and `unblind`s C, outputs C into the same contract,
borrows P per provided scalar amount, outputs P into recipient's address.
Returns V, -C and -P to the user. User merges V+(-C) and outputs V-C to its address, provides P into the cloak.

What about zero remainder or dust? Contract can have two branches: partial or full lift,
and partial lift has minimum remainder to prevent dust.




### Loan example

TBD.

### Loan with interest

TBD.


### Payment channel example

Payment channel is a contract that permits a number of parties to exchange value within a given range back-and-forth
without publication of each transaction on a blockchain. Instead, only net distribution of balances is _settled_ when the channel is _closed_.

Assumptions for this example:

1. There are 2 parties in a channel.
2. The channel uses values of one _flavor_ chosen when the channel is created.

Overview:

1. Both parties commit X quantity of funds to a shared contract protected by a simple 2-of-2 multisig predicate. This allows each party to net-send or net-receive up to X units.
2. Parties can close the channel mutually at any time, signing off a transaction that distributes the latest balances. They can even choose the target addresses arbitrarily. E.g. if one party needs to make an on-chain payment, they can have their balance split in two outputs: _payment_ and _change_ immediately when closing a channel, without having to make an additional transaction.
3. Parties can _independently close_ the channel at any time using a _pre-signed authorization predicate_, that encodes a distribution of balances with the hard-coded pay-out outputs.
4. Each payment has a corresponding pre-signed authorization reflecting a new distribution.
5. To prevent publication of a transaction using a _stale_ authorization predicate:
    1. The predicate locks funds in a temporary "holding" contract for a duration of a "contest period" (agreed upon by both parties at the creation of a channel).
    2. Any newer predicate can immediately spend that time-locked contract into a new "holding" contract with an updated distribution of funds.
    3. Users watch the blockchain updates for attempts to use a stale authorization, and counter-act them with the latest version.
6. If the channel was force-closed and not (anymore) contested, after a "contest period" is passed, the "holding" contract can be opened by either party, which sends the funds to the pre-determined outputs.

In ZkVM such predicate is implemented with a _signed program_ ([`delegate`](#delegate)) that plays dual role:

1. It allows any party to _initiate_ a force-close.
2. It allows any party to _dispute_ a stale force-close (overriding it with a more fresh force-close).

To _initiate_ a force-close, the program `P1` does:

1. Take the exptime as an argument provided by the user (encrypted via Pedersen commitment).
2. Check that `tx.maxtime + D == exptime` (built-in contest period).
   Transaction maxtime is chosen by the initiator of the tx close to the current time.
3. Put the exptime and the value into the output under predicate `P2` (built-in predicate committing to a program producing final outputs and checking exptime).

To construct such program `P1`, users first agree on the final distribution of balances via the program `P2`.

The final-distribution program `P2`:
1. Checks that `tx.mintime >= exptime` (can be done via `range:24(tx.mintime - exptime)` which gives 6-month resolution for the expiration time)
2. Creates `borrow`/`output` combinations for each party with hard-coded predicate for each output.
3. Leaves the payload value and negatives from `borrow` on the stack to be consumed by the `cloak` instruction.

To _dispute_ a stale force-close, the program `P1` has an additional feature:
it contains a sequence number that's incremented for each new authorization predicate `P1`, at each payment.
The program `P1`, therefore:

1. Expect two items on the stack coming from a contract: `seq` scalar and `val` value (on top of `seq`). Below these, there is `exptime` commitment.
2. Check `range:24(new_seq - seq - 1)` to make sure `new_seq > seq`. If there are more than 16.7 million payments (capped by a 24-bit rangeproof), several contest transactions can be chained together with a distance of 16.7 million payments between each other to reach the latest one. At the tx rate of 1 tx/sec, this implies 6 months worth of channel life per intermediate force-close transaction.
3. Check the expiration time `tx.maxtime + D == exptime` (D is built into the predicate).
4. Lock the value and `exptime` in a new output with a built-in predicate `P2`.

If `P1` is used to initiate force-close on a contract that does not have a sequence number (initial contract),
the user simply provides a zero scalar on the stack under the contract.

Confidentiality properties:

1. When the channel is normally closed, it is not even revealed whether it was a payment channel at all. The channel contract looks like an ordinary output indistinguishable from others.
2. When the channel is force-closed, it does not reveal the number of payments (sequence number) that went through it, nor the contest period which could be used to fingerprint participants with different settings.

The overhead in the force-close case is 48 multipliers (two 24-bit rangeproofs) — a 37.5% performance overhead on top of 2 outputs which the channel has to create even in a normal-close case. There is no range proof for the re-locked value between `P1` and `P2`, as it's already known to be in range and it does no go through the `cloak`.


### Payment routing example

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

For instance, to implement a SHA-256 function, an unsued extension instruction
could be assigned `verifysha256` name and check if top two strings on the stack
are preimage and image of the SHA-256 function respectively. The VM would fail if
the check failed, while the non-upgraded software could choose to treat the instruction as no-op
(e.g. by ignoring the upgraded transaction version).

It is possible to write a compatible contract that uses features of a newer
transaction version while remaining usable by non-upgraded software
(that understands only older transaction versions) as long as
new-version code paths are protected by checks for the transaction
version. To facilitate that, a hypothetical ZkVM upgrade may introduce
an extension instruction “version assertion” that fails execution if
the version is below a given number (e.g. `4 versionverify`).


### Static arguments

Some instructions ([`output`](#output), [`roll`](#roll) etc) have size or index
parameters specified as _immediate data_ (part of the instruction code),
which makes it impossible to compute such argument on the fly.

This allows for a simpler type system (no integers, only scalars),
while limiting programs to have pre-determined structure.

In general, there are no jumps or cleartext conditionals apart from a specialized [predicate tree](#predicate-tree).
Note, however, that with the use of [delegation](#delegate),
program structure can be determined right before the use.


### Should cloak and borrow take variables and not commitments?

1. it makes sense to reuse variable created by `blind`
2. txbuilder can keep the secrets assigned to variable instances, so it may be more convenient than remembering preimages for commitments.


### Why there is no `and` combinator in the predicate tree?

The payload of a contract must be provided to the selected branch. If both predicates must be evaluated and both are programs, then which one takes the payload? To avoid ambiguity, AND can be implemented inside a program that can explicitly decide in which order and which parts of payload to process: maybe check some conditions and then delegate the whole payload to a predicate, or split the payload in two parts and apply different predicates to each part. There's [`contract`](#contract) instruction for that delegation.


### Why we need Wide value and `borrow`?

Imagine your contract is "pay $X to address A in order to unlock £Y".

You can write this contract as "give me the value V, i'll check if V == $X, and lock it with address A, then unlock my payload £Y". Then you don't need any negative values or "borrowing".

However, this is not flexible: what if $X comes from another contract that takes Z£ and part of Z is supposed to be paid by £Y? You have a circular dependency which you can only resolve if you have excess of £ from somewhere to resolve both contracts and then given these funds back.

Also, it's not private enough: the contract now not only reveals its logic, but also requires you to link the whole tx graph where the $X is coming from.

Now let’s see how [`borrow`](#borrow) simplifies things: it allows you to make $X out of thin air, "borrowing" it from void for the duration of the transaction.

`borrow` gives you a positive $X as requested, but it also needs to require you to repay $X from some other source before tx is finalized. This is represented by creating a *negative –$X* as a less powerful type Wide Value.

Wide values are less powerful (they are super-types of Values) because they are not _portable_. You cannot just stash such value away in some output. You have to actually repay it using the `cloak` instruction.


### How to perform an inequality constraint?

First, note that inequality constraint only makes sense for integers, not for scalars.
This is because integers are ordered and scalars wrap around modulo group order.
Therefore, any two [variables](#variable-type) or [expressions](#expression-type) that must be compared,
must theselves be proven to be in range using the [`range`](#range) instruction (directly or indirectly).

Then, the inequality constraint is created by forming an expression of the form `expr ≥ 0` (using instructions [`neg`](#neg) and [`add`](#add)) and using a [`range`](#range) instruction to place a range check on `expr`.

Constraint | Range check
-----------|------------------
`a ≥ b`    | `range:64(a - b)`
`a ≤ b`    | `range:64(b - a)`
`a > b`    | `range:64(a - b - 1)`
`a < b`    | `range:64(b - a - 1)`



### How to perform a logical `not`?

Logical instructions [`or`](#or) and [`and`](#and) work by combining constraints of form `expr == 0`, that is, a comparison with zero. Logical `not` then is a check that a secret variable is _not zero_.

One way to do that is to break the scalar in 253 bits (using 253 multipliers) and add a disjunction "at least one of these bits is 1" (using additional 252 multipliers), spending total 505 multipliers (this is 8x more expensive than a regular 64-bit rangeproof).

On the other hand, using `not` may not be a good way to express contracts because of a dramatic increase in complexity: a contract that says `not(B)` effectively inverts a small set of inadmissible inputs, producing a big set of addmissible inputs.

We need to investigate whether there are use-cases that cannot be safely or efficiently expressed with only [`and`](#and) and [`or`](#or) combinators.


### What ensures transaction uniqueness?

In ZkVM:

* [Transaction ID](#transaction-id) is globally unique,
* [UTXO](#utxo) is globally unique,
* [Nonce](#nonce) is globally unique,
* [Contract](#contract-type) is globally unique,
* [Value](#value-type) is **not** unique.

In contrast, in TxVM:

* [Transaction ID](#transaction-id) is globally unique,
* [UTXO](#utxo) is **not** unique,
* [Nonce](#nonce) is globally unique,
* [Contract](#contract-type) is globally unique,
* [Value](#value-type) is globally unique.

TxVM ensures transaction uniqueness this way:

* Each value has a unique “anchor” (32-byte payload)
* When values are split/merged, anchor is one-way hashed to produce new anchor(s).
* `finalize` instruction consumes a zero-quantity value, effectively consuming a unique anchor.
* Anchors are originally produced via `nonce` instruction that uses blockchain state to prevent reuse of nonces.
* Issuance of new assets consumes a zero-quantity value, moving the anchor from it to the new value.

**Pro:**

UTXO is fully determined before transaction is finalized. So e.g. a child transaction can be formed before the current transaction is completed and its ID is known. This might be handy in some cases.

**Meh:**

It seems like transaction ID is defined quite simply as a hash of the log, but it also must consume an anchor (since UTXOs alone are not guaranteed to be unique, and one can make a transaction without spending any UTXOs). So transaction ID computation still has some level of special handling.

**Con:**

Recipient of payment cannot fully specify the contract snapshot because they do not know sender’s anchors. This is not a problem in cleartext TxVM, but a problem in ZkVM where values have to participate in the Cloak protocol.

Storing anchor inside a value turned out to be handy, but is not very ergonomic. For instance, a contract cannot simply “claim” an arbitrary value and produce a negative counterpart, w/o having _some_ value to “fork off” an anchor from.

Another potential issue: UTXOs are not guaranteed to be always unique. E.g. if a contract does not modify its value and other content, it can re-save itself to the same UTXO ID. It can even toggle between different states, returning to the previously spent ID. This can cause issues in some applications that forget that UTXO ID in special circumstances can be resurrected.


ZkVM ensures transaction uniqueness this way:

* Values do not have anchors.
* We still have `nonce` instruction with the same semantics
* `issue` does not consume zero value
* `finalize` does not consume zero value
* `claim/borrow` can produce an arbitrary value and its negative at any point
* Each UTXO ID is defined as `Hash(contract)`, that is contents of the contract are unique due to a contract’s anchor.
* Transaction ID is a hash of the finalized log.
* Newly created contracts consume the "last anchor" tracked by VM and set it to their contract ID.
* When VM finishes, it checks that "last anchor" is present, which means that the log contains either an [input](#input-entry) or a [nonce](#nonce-entry).
* Inputs and outputs are represented in the log as contract IDs which the blockchain state machine should remove/insert accordingly.

**Pros:**

The values are simply pedersen commitments (Q,A) (quantity, flavor), without any extra payload.
This makes handling them much simpler: we can issue, finalize and even “claim” a value in a straightforward manner.

**Con:**

UTXO IDs are not generally known without fuller view on transaction flow. This could be not a big deal, as we cannot really plan for the next transaction until this one is fully formed and published. Also, in a joint proof scenario, it’s even less reliable to plan the next payment until the multi-party protocol is completed, therefore waiting for transaction ID to be determined becomes a requirement.

That said, for contracts created from another contract, the contract ID is determined locally by the parent contract’s ID.

### Do we need qty/flavor introspection ops?

Previously, we thought we needed them to reblind a received value. (In this now-scrapped protocol, we would encrypt a value to a public key in one transaction and decrypt it in another one.) Now, we will use El-Gamal encryptions and codify encrypted values or data in specific types. That means we do not need to operate on individual values or commitments.
Also, instead of placing bounds on some received value, we now normally use `borrow`. While constraints on values are still relevant, the `borrow` approach means we do not need to inspect a `Value` object. Instead, we can simply constrain raw commitments or variables and then `borrow` a value with such a commitment. 
Thus, neither of these use cases requires `qty` and `flavor`.

### Open questions
None at the moment.