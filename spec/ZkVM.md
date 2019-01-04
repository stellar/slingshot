# ZkVM

This is the specification for ZkVM, the zero-knowledge transaction virtual machine.

ZkVM defines a procedural representation for blockchain transactions and the rules for a virtual machine to interpret them and ensure their validity.

* [Overview](#overview)
    * [Motivation](#motivation)
    * [Concepts](#concepts)
* [Types](#types)
    * [Data types](#data-types)
    * [Linear types](#linear-types)
    * [Portable types](#portable-types)
    * [Scalar](#scalar-type)
    * [Point](#point-type)
    * [String](#string-type)
    * [Contract](#contract-type)
    * [Variable](#variable-type)
    * [Constraint](#constraint-type)
    * [Value](#value-type)
    * [Signed value](#signed-value)
* [Definitions](#definitions)
    * [LE32](#le32)
    * [LE64](#le64)
    * [Base points](#base-points)
    * [Pedersen commitment](#pedersen-commitment)
    * [Verification key](#verification-key)
    * [Time bounds](#time-bounds)
    * [Transcript](#transcript)
    * [Predicate](#predicate)
    * [Predicate tree](#predicate-tree)
    * [Predicate disjunction](#predicate-disjunction)
    * [Program predicate](#program-predicate)
    * [Program](#program)
    * [Contract payload](#contract-payload)
    * [Input structure](#input-structure)
    * [UTXO](#utxo)
    * [Output structure](#output-structure)
    * [Constraint system](#constraint-system)
    * [Constraint system proof](#constraint-system-proof)
    * [Transaction witness](#transaction-witness)
    * [Transaction log](#transaction-log)
    * [Transaction ID](#transaction-id)
    * [Merkle binary tree](#merkle-binary-tree)
    * [Signature](#signature)
    * [Aggregated transaction signature](#aggregated-transaction-signature)
    * [Blinding protocol](#blinding-protocol)
* [VM operation](#vm-operation)
    * [VM state](#vm-state)
    * [VM execution](#vm-execution)
    * [Deferred point operations](#deferred-point-operations)
    * [Versioning](#versioning)
* [Instructions](#instructions)
    * [Data instructions](#data-instructions)
    * [Scalar instructions](#scalar-instructions)
    * [Constraint system instructions](#constraint-system-instructions)
    * [Value instructions](#value-instructions)
    * [Contract instructions](#contract-instructions)
    * [Stack instructions](#stack-instructions)
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

A transaction is represented by a [transaction witness](#transaction-witness) that
contains a [program](#program) that runs in the context of a stack-based virtual machine.

When the virtual machine executes a program, it creates and manipulates data of various types:
[**plain data types**](#data-types) and [**linear types**](#linear-types), such as [values](#value-type) and
[contracts](#contract-type).

A [**value**](#value-type) is a specific _quantity_ of a certain _flavor_ that can be
merged or split, issued or retired, but not otherwise created or destroyed.

A [**contract**] encapsulates a predicate (a public key or a program),
plus its runtime state, and once created must be executed to completion
or persisted in the global state for later execution.

Custom logic is represented via programmable [**constraints**](#constraint-type)
applied to [**variables**](#variable-type). Variables represent quantities and flavors of values,
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
transaction’s applicability to the [blockchain](Blockchain.md).







## Types

The items on the ZkVM stack are typed. The available types fall into two
broad categories: [data types](#data-types) and [linear types](#linear-types).

### Data types

Data types can be freely created, copied, and destroyed.

* [Scalar](#scalar-type)
* [Point](#point-type)
* [String](#string-type)
* [Variable](#variable-type)
* [Constraint](#constraint-type)


### Linear types

Linear types are subject to special rules as to when and how they may be created
and destroyed, and may never be copied.

* [Contract](#contract-type)
* [Signed Value](#signed-value-type)
* [Value](#value-type)


### Portable types

The items of the following types can be _ported_ across transactions via [outputs](#output-structure):

* [Scalar](#scalar-type)
* [Point](#point-type)
* [String](#string-type)
* [Value](#value-type)

The [Signed Value](#signed-value-type) is not portable because it is not proven to be non-negative.

The [Contract](#contract-type) is not portable because it must be satisfied within the current transaction
or [output](#output-structure) its contents itself.

The [Variable](#variable-type) and [Constraint](#constraint-type) types have no meaning outside the VM state
and its constraint system and therefore cannot be ported between transactions.


### Scalar type

A _scalar_ is an integer modulo [Ristretto group](https://ristretto.group) order `|G| = 2^252 + 27742317777372353535851937790883648493`.

Scalars are encoded as 32-byte arrays using little-endian convention.
Every scalar in the VM is guaranteed to be in a canonical (reduced) form.


### Point type

A _point_ is an element in the [Ristretto group](https://ristretto.group).

Points are encoded as 32-byte arrays in _compressed Ristretto form_.
Each point in the VM is guaranteed to be a valid Ristretto point.


### String type

A _string_ is a variable-length byte array used to represent signatures, proofs and programs.

Strings cannot be larger than the entire transaction program and cannot be longer than `2^32-1`.


### Contract type

A contract is a [predicate](#predicate) and a [payload](#contract-payload) guarded by that predicate.

Contracts are created with the [`contract`](#contract) instruction and
destroyed by evaluating the predicate, leaving their stored items on the stack.

Contracts can be "frozen" with the [`output`](#output) instruction that places the predicate
and the payload into the [output structure](#output-structure) which is
recorded in the [transaction log](#transaction-log).


### Variable type

_Variable_ represents a secret [scalar](#scalar-type) value in the [constraint system](#constraint-system).

A variable can be in one of two states: **detached** and **attached**.

**Detached variable** is represented by a reference to a [Pedersen commitment](#pedersen-commitment) which can be [decrypted](#decrypt)
before the variable is added to the [constraint system](#constraint-system).
All copies of a detached variable share the same commitment, so that once one of them is decrypted
to use another commitment, all other copies reflect the new commitment.

**Attached variable** a linear combination of underlying variables within a [constraint system](#constraint-system).
Once the variable is attached to a constraint system, it cannot be detached.

Variables can be [added](#zkadd) and [multiplied](#zkmul), producing new variables.
Variables can also be [encrypted](#encrypt) into a [Pedersen commitment](#pedersen-commitment) with a predetermined
blinding factor. All these operations transform each involved variable into the **attached** state.

Cleartext [scalars](#scalar-type) can be turned into variables using the [`const`](#const) instruction,
[points](#point-type) that represent commitments can be turned into variables using the [`var`](#var) instruction.

Variables can be copied and dropped at will, but cannot be ported across transactions via [outputs](#output-structure).

Examples of variables: [value quantities](#value-type) and [time bounds](#time-bounds).



### Constraint type

_Constraint_ is a statement in the [constraint system](#constraint-system) that constrains one
or more linear combination of [variables](#variable-type) to zero.

Constraints are created using the [`zkeq`](#zkeq) instruction over two [variables](#variable-type).

Constraints can be combined using logical [`and`](#and) and [`or`](#or) instructions,
and can also be copied and dropped at will.

Constraints only have an effect if added to the constraint system using the [`verify`](#verify) instruction.


### Value type

A value is a [linear type](#linear-types) representing a pair of *quantity* and *flavor*.
Both quantity and flavor are represented as [scalars](#scalar-type).
Quantity is guaranteed to be in a 64-bit range (`[0..2^64-1]`).

Values are created with [`issue`](#issue) and destroyed with [`retire`](#retire).
Values can be merged and split together with other values using a [`cloak`](#cloak) instruction.
Only values having the same flavor can be merged.

Values are secured by “locking them up” inside [contracts](#contract-type).

Contracts can also require payments by creating outputs using _borrowed_ values.
[`borrow`](#borrow) instruction produces two items: a non-negative value and a negated [signed value](#signed-value-type),
which must be cleared using appropriate combination of non-negative values.

Each non-negative value keeps the [Pedersen commitments](#pedersen-commitment)
for the quantity and flavor (in addition to the respective [variables](#variable-type)),
so that they can serialized in the [`output`](#output).


### Signed value type

A signed value is an extension of the [value](#value-type) type where
quantity is guaranteed to be in a 65-bit range (`[-(2^64-1)..2^64-1]`).

The subtype [Value](#value-type) is most commonly used because it guarantees the non-negative quantity
(for instance, [`output`](#output) instruction only permits positive [values](#value-type)),
and the signed value is only used as an output of [`borrow`](#borrow) and as an input to [`cloak`](#cloak).





## Definitions

### LE32

A non-negative 32-bit integer encoded using little-endian convention.
Primarily used to encode sizes of data structures ([strings](#string-type), lists etc).

### LE64

A non-negative 64-bit integer encoded using little-endian convention.
Primarily used to encode [value quantities](#value) and [timestamps](#time-bounds).


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

Pedersen commitment to a secret [scalar](#scalar-type)
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

Pedersen commitments can be proven to use a pre-determined blinding factor using [`blind`](#blind) and 
[`reblind`](#reblind) instructions.


### Verification key

A _verification key_ `P` is a commitment to a secret [scalar](#scalar-type) `x` (_signing key_)
using the primary [base point](#base-points) `B`: `P = x·B`.
Verification keys are used to construct [predicates](#predicate) and verify [signatures](#signature).


### Time bounds

Each transaction is explicitly bound to a range of _minimum_ and _maximum_ time.
Each bound is in _seconds_ since Jan 1st, 1970 (UTC), represented by an unsigned 64-bit integer.
Time bounds are available in the transaction as [variables](#variable-type) provided by the instructions
[`mintime`](#mintime) and [`maxtime`](#maxtime).



### Transcript

Transcript is an instance of the [Merlin](https://doc.dalek.rs/merlin/) construction,
which is itself based on [STROBE](https://strobe.sourceforge.io/) and [Keccak-f](https://keccak.team/keccak.html)
with 128-bit security parameter.

Transcript is used throughout ZkVM to generate challenge [scalars](#scalar-type) and commitments.

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
Predicate is encoded as a [point](#point-type) representing a node
of a [predicate tree](#predicate-tree).


### Predicate tree

A _predicate tree_ is a composition of [predicates](#predicate) and [programs](#program) that
provides flexible way to open a [contract](#contract-type).

Each node in a predicate tree is formed with one of the following:

1. [Verification key](#verification-key): can be satisfied by signing a transaction using [`signtx`](#signtx) or signing and executing a program using [`delegate`](#delegate).
2. [Disjunction](#predicate-disjunction) of other predicates. Choice is made using [`left`](#left) and [`right`](#right) instructions.
3. [Program commitment](#program-predicate). The structure of the commitment prevents signing and requires user to reveal and evaluate the program using [`call`](#call) instruction.


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
by committing the program string and squeezing a scalar that is bound to it:

```
T = Transcript("ZkVM.predicate")
T.commit("prog", prog)
h = T.challenge_scalar("h")
PP(prog) = h·B2
```

Program predicate can be satisfied only via the [`call`](#call) instruction that takes a cleartext program string, verifies the commitment and evaluates the program. Use of the [secondary base point](#base-points) `B2` prevents using the predicate as a [verification key](#verification-key)) and signing with `h` without executing it.


### Program

A program is a string containing a sequence of ZkVM [instructions](#instructions).


### Contract payload

A list of [items](#types) stored in the [contract](#contract-type) or [output](#output-structure).

Payload of a [contract](#contract-type) may contain arbitrary [types](#types),
but in the [output](#output-structure) only the [portable types](#portable-types) are allowed.


### Input structure

Input structure represents an unspent output (UTXO) from a previous transaction.

Input is serialized as [output](#output-structure) with extra 32 bytes containing
this output’s [transaction ID](#transaction-id).

```
       Input  =  PreviousOutput || PreviousTxID
PreviousTxID  =  <32 bytes>

```

### UTXO

UTXO is an _unspent transaction output_ identified by a 32-byte hash computed using [transcript](#transcript):

```
T = Transcript("ZkVM.utxo")
T.commit("txid", previous_txid)
T.commit("output", previous_output)
utxo = T.challenge_bytes("id")
```

In the above, `previous_txid` is the [transaction ID](#transaction-id) of the transaction where the output was created,
and `previous_output` is the [output](#output-structure), serialized.


### Output structure

Output represents a _snapshot_ of a [contract](#contract-type)
and can only contain [portable types](#portable-types).

```
       Input  =  LE32(k)  ||  Item[0]  || ... ||  Item[k-1]  ||  Predicate
   Predicate  =  <32 bytes>
        Item  =  enum { Scalar, Point, String, Value }
      Scalar  =  0x00  ||  <32 bytes>
       Point  =  0x01  ||  <32 bytes>
      String  =  0x02  ||  LE32(len)  ||  <bytes>
       Value  =  0x03  ||  <32 bytes> ||  <32 bytes>
```

Note: the [plain data](#data-types) items are encoded as VM instructions that produce the corresponding item.


### Constraint system

The part of the [VM state](#vm-state) that implements
[Bulletprofs rank-1 constraint system](https://doc-internal.dalek.rs/develop/bulletproofs/notes/r1cs_proof/index.html).

Constraint system keeps track of [variables](#variable-type) and [constraints](#constraint-type)
and is used to verify the [constraint system proof](#constraint-system-proof).


### Constraint system proof

A proof of satisfiability of a [constraint system](#constraint-system) built during the VM execution.

The proof is provided to the VM at the beggining of execution and verified when the VM is [finished](#vm-execution).


### Transaction witness

Transaction witness is a structure that contains all data and logic
required to produce a unique [transaction ID](#transaction-id):

* Version (uint64)
* [Time bounds](#time-bounds) (pair of uint64)
* [Program](#program) (variable-length string)
* [Transaction signature](#signature) (64 bytes)
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
* [`data`](#data)
* [`import`](#import)
* [`export`](#export)

See the specification of each instruction for the details of which data is stored.

Note: transaction log items are only serialized when committed to a [transcript](#transcript)
during the [transaction ID](#transaction-id) computation.


### Transaction ID

Transaction ID is defined as a [merkle hash](#merkle-binary-tree) of a list consisting of 
a _header entry_ (transaction version and [time bounds](#time-bounds)),
followed by all the entries from the [transaction log](#transaction-log):

```
T = Transcript("ZkVM.txid")
txid = MerkleHash(T, {header} || txlog )
```

Entries are committed to the [transcript](#transcript) using the following schema.

#### Header entry

```
T.commit("tx.version", LE64(version))
T.commit("tx.mintime", LE64(mintime))
T.commit("tx.maxtime", LE64(maxtime))
```

#### Input entry

Input entry is added using [`input`](#input) instruction.

```
T.commit("input", utxo_id)
```

where `utxo_id` is the ID of the corresponding [UTXO](#utxo).

#### Output entry

Output entry is added using [`output`](#output) instruction.

```
T.commit("output", output_structure)
```

where `output_structure` is a serialized [output](#output-structure).

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
T.commit("nonce.p", predicate)
T.commit("nonce.t", maxtime)
```

#### Data entry

A [data type](#data-types) ([scalar](#scalar-type), [point](#point-type) or [string](#string-type)) is encoded
as a single-instruction program that produces an item of the corresponding type (see [output structure](#output-structure)).

Data entry is added using [`data`](#data) instruction.

```
T.commit("data", prog)
```

#### Import entry

Import entry is added using [`import`](#import) instruction.

TBD.

#### Export entry

Export entry is added using [`export`](#export) instruction.

TBD.



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


### Signature

Signature is a Schnorr proof of knowledge of a secret [scalar](#scalar-type) corresponding
to a [verification key](#verification-key) in a context of some _message_.

Signature is encoded as a 64-byte [string](#string-type).

The protocol is the following:

1. Prover and verifier obtain a [transcript](#transcript) `T` defined by the context in which the signature is used (see [`signtx`](#signtx), [`delegate`](#delegate)). The transcript is assumed to be already bound to the _message_ and the [verification key](#verification-key) `P`.
2. Prover creates a _secret nonce_: a randomly sampled [scalar](#scalar-type) `r`.
3. Prover commits to nonce:
    ```
    R = r·B
    ```
4. Prover sends `R` to the verifier.
5. Prover and verifier write the nonce commitment `R` to the transcript:
    ```
    T.commit("R", R)
    ```
6. Prover and verifier compute a Fiat-Shamir challenge scalar `e` using the transcript:
    ```
    e = T.challenge_scalar("e")
    ```
7. Prover computes a signature scalar `s` using the nonce, the challenge and the secret key `dlog(P)`:
    ```
    s = r + e·dlog(P)
    ```
8. Prover sends `s` to the verifier.
9. Verifier checks the relation:
    ```
    s·B == R + e·P
    ```

### Aggregated transaction signature

Instruction [`signtx`](#signtx) unlocks a contract if its [predicate](#predicate)
correctly signs the [transaction ID](#transaction-id). The contract‘s predicate
is added to the array of deferred [verification keys](#verification-key) that
are later aggregated in a single key and a Schnorr [signature](#signature) protocol
is executed for the [transaction ID](#transaction-id).

Aggregation protocol is based on the [MuSig](https://eprint.iacr.org/2018/068) scheme, but with
Fiat-Shamir transform defined through the use of the [transcript](#transcript) instead of a composition of hash function calls.

1. Instantiate the [transcript](#transcript) `TA` for transaction signature:
    ```
    T = Transcript("ZkVM.signtx")
    ```
2. Commit the [transaction ID](#transaction-id):
    ```
    T.commit("txid", txid)
    ```
3. Commit the count `n` of deferred keys as [LE32](#le32):
    ```
    T.commit("n", LE32(n))
    ```
4. Commit all deferred keys `P[i]` in order, one by one:
    ```
    T.commit("P", P[i])
    ```
5. For each key, generate a randomizing scalar:
    ```
    x[i] = T.challenge_scalar("x")
    ```
6. Form an aggregated key without computing it right away:
    ```
    PA = x[0]·P[0] + ... + x[n-1]·P[n-1]
    ```
7. Perform the [signature protocol](#signature) using the transcript `T`, randomized secret keys `x[i]·dlog(P[i])`, and unrolling `PA` in the final statement:
    ```
    s[i] = r[i] + e·x[i]·dlog(P[i])
      s  = sum{s[i]}

    s·B  ==  R + e·PA
         ==  R + (e·x[0])·P[0] + ... + (e·x[n-1])·P[n-1]
    ```
8. Add the statement to the list of [deferred point operations](#deferred-point-operations).




### Blinding protocol

Blinding protocol consists of three proofs about blinding factors:

1. [Blinding proof](#blinding-proof): a proof that a blinding factor is formed with a pre-determined key which can be removed using [reblind](#reblind-proof) operation. Implemented by the [`blind`](#blind) instruction.
2. [Reblinding proof](#reblinding-proof): a proof that a blinding factor is replaced with another one without affecting the committed value. Implemented by the [`reblind`](#reblind) instruction.
3. [Unblinding proof](#unblinding-proof): demonstrates the committed value and proves that the blinding factor is zero. Implemented by the [`unblind`](#reblind) instruction.

#### Blinding proof

TBD. Prove `V = v*B + q*P` where `Q=q*B2` is random and `P=p*B2` is agreed on.

```
proof = Q || R_q || s_q || R_v || R_w || R_p || s_p || s_w (8x32 = 256 bytes)

W + Q == p^{-1}·V
    W == p^{-1}·v·B
   B2 == p^{-1}·P
    Q == q·B2        (separate proof)

V = v·B + p·q·B2
```


#### Reblinding proof

TBD. Prove `V2-V1 = f*B2 - p*Q` where `Q=q*B2` proof is copied from blinding tx, `P=p*B2` is agreed on, and `f` is the new factor.

```
proof = Q || R_q || s_q || R_f || R_v || s_p || s_f (7x32 = 224 bytes)

    F == p^{-1}·f·B2
F - R == p^{-1}·(V2-V1)
    Q == q·B2        (separate proof, copied from tx encrypted)

V1 = v·B + (x + p·q)·B2
V2 = v·B + (x + f)·B2
```


#### Unblinding proof

TBD. Prove `V = v*B` where `v` is provided in cleartext.




TBD: the protocol below is obsolete and will be replaced.


A zero-knowledge protocol that proves that a [Pedersen commitment](#pedersen-commitment) contains a 
pre-committed blinding factor. This protocol allows proving to the network that a payment is accessible
to the recipient (since the blinding factor is already known to the recipient), while allowing
the sender to compute the amount on the fly.

TBD: need to enable derivation, so that the blinding factor can be safely reused with randomization.

The setup:

1. Recipient chooses a random blinding factor `f`.
2. 

The protocol is the following:

1. Prover and verifier obtain a [transcript](#transcript) `T` defined by the context in which the proof is applied (see [`encrypt`](#encrypt)).
2. Prover creates a _secret nonce_ `r`, randomly sampled [scalar](#scalar-type) `r`.
3. Prover commits to nonce:
    ```
    R = r·B
    ```
4. Prover sends `R` to the verifier.
5. Prover and verifier write the nonce commitment `R` to the transcript:
    ```
    T.commit("R", R)
    ```
6. Prover and verifier compute a Fiat-Shamir challenge scalar `e` using the transcript:
    ```
    e = T.challenge_scalar("e")
    ```
7. Prover computes a signature scalar `s` using the nonce, the challenge and the secret key `dlog(P)`:
    ```
    s = r + e·dlog(P)
    ```
8. Prover sends `s` to the verifier.
9. Verifier checks the relation:
    ```
    s·B == R + e·P
    ```




## VM operation

### VM state

The ZkVM state consists of the static attributes and the state machine attributes.

1. [Transaction witness](#transaction-witness):
    * `version`
    * `mintime` and `maxtime`
    * `program`
    * `tx_signature`
    * `cs_proof`
2. Extension flag (boolean)
3. Uniqueness flag (boolean)
4. Data stack (array of [items](#types))
5. Program stack (array of [programs](#program) with their offsets)
6. Current [program](#program) with its offset
7. [Transaction log](#transaction-log) (array of logged items)
8. Transaction signature verification keys (array of [points](#point-type))
9. [Deferred point operations](#deferred-point-operations)
10. High-level variables: a list of `enum{ detached(point), attached(index) }`
11. [Constraint system](#constraint-system)


### VM execution

The VM is initialized with the following state:

1. A [transaction witness](#transaction-witness) as provided by the user.
2. Extension flag set to `true` or `false` according to the [transaction versioning](#versioning) rules for the witness version.
3. Uniqueness flag is set to `false`.
4. Data stack is empty.
5. Program stack is empty.
6. Current program set to the transaction witness program; with zero offset.
7. Transaction log is empty.
8. Array of signature verification keys is empty.
9. Array of deferred point operations is empty.
10. High-level variables: attached variables for [mintime and maxtime](#time-bounds).
10. Constraint system: empty (time bounds are constants that appear only within linear combinations of actual variables).

Then, the VM executes the current program till completion:

1. Each instruction is read at the current program offset, including its immediate data (if any).
2. Program offset is advanced immediately after reading the instruction to the next instruction.
3. The instruction is executed per [specification below](#instructions). If the instruction fails, VM exits early with an error result.
4. If VM encounters [`call`](#call) or [`delegate`](#delegate) instruction, the current program and the offset are saved in the program stack, and the new program with offset zero is set as the current program. 
5. If the offset is less than the current program’s length, a new instruction is read (go back to step 1).
6. Otherwise (reached the end of the current program):
   1. If the program stack is not empty, pop top item from the program stack and set it to the current program. Go to step 5.
   2. If the program stack is empty, the transaction is considered _finalized_ and VM successfully finishes execution.

If the execution finishes successfully, VM performs the finishing tasks:
1. Checks if the stack is empty; fails otherwise.
2. Checks if the uniqueness flag is set to `true`; fails otherwise.
3. Computes [transaction ID](#transaction-id).
4. Computes a verification statement for [aggregated transaction signature](#aggregated-transaction-signature).
5. Computes a verification statement for [constraint system proof](#constraint-system-proof).
6. Executes all [deferred point operations](#deferred-point-operations), including aggregated transaction signature and constraint system proof, using a single multi-scalar multiplication. Fails if the result is not an identity point.

If none of the above checks failed, the resulting [transaction log](#transaction-log) is _applied_
to the blockchain state as described in [the blockchain specification](Blockchain.md#apply-transaction-log).


### Deferred point operations

VM defers operations on [points](#point-type) till the end of the transaction in order
to batch them with the verification of [transaction signature](#signature) and
[constraint system proof](#constraint-system-proof).

Each deferred operation at index `i` represents a statement:
```
0  ==  sum{s[i,j]·P[i,j], for all j}  +  a[i]·B  +  b[i]·B2
```
where:
1. `{s[i,j],P[i,j]}` is an array of ([scalar](#scalar-type),[point](#point-type)) tuples,
2. `a[i]` is a [scalar](#scalar-type) weight of a [primary base point](#base-points) `B`,
3. `b[i]` is a [scalar](#scalar-type) weight of a [secondary base point](#base-points) `B2`.

All such statements are combined using the following method:

1. For each statement, a random [scalar](#scalar-type) `x[i]` is sampled.
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
   [block](Blockchain.md#block-header) also has a version number.
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
 |     [**Data**](#data-instructions)                 |                        |
0x00 | [`scalar:x`](#scalar)      |                 ø → _scalar_               | 
0x01 | [`point:x`](#point)        |                 ø → _point_                | 
0x02 | [`string:n:x`](#string)    |                 ø → _string_               | 
 |                                |                                            |
 |     [**Scalars**](#scalar-instructions)            |                        | 
0x?? | [`neg`](#neg)              |               _a_ → _\|G\|–a_              | 
0x?? | [`add`](#add)              |             _a b_ → _a+b mod \|G\|_        | 
0x?? | [`mul`](#mul)              |             _a b_ → _a·b mod \|G\|_        | 
0x?? | [`eq`](#eq)                |             _a b_ → ø                      | Fails if _a_ ≠ _b_.
0x?? | [`range:n`](#range)        |               _a_ → _a_                    | Fails if _a_ is not in range [0..2^64-1]
 |                                |                                            |
 |     [**Constraints**](#constraint-system-instructions)  |                   | 
0x?? | [`var`](#var)              |           _point_ → _var_                  | Adds an external variable to [CS](#constraint-system)
0x?? | [`const`](#var)            |          _scalar_ → _var_                  | 
0x?? | [`mintime`](#mintime)      |                 ø → _var_                  |
0x?? | [`maxtime`](#maxtime)      |                 ø → _var_                  |
0x?? | [`zkneg`](#zkneg)          |            _var1_ → _var2_                 |
0x?? | [`zkadd`](#zkadd)          |       _var1 var2_ → _var3_                 |
0x?? | [`zkmul`](#zkmul)          |       _var1 var2_ → _var3_                 | Adds multiplier in [CS](#constraint-system)
0x?? | [`scmul`](#scmul)          |          _var1 x_ → _var2_                 | 
0x?? | [`zkeq`](#zkeq)            |       _var1 var2_ → _constraint_           | 
0x?? | [`zkrange:n`](#zkrange)    |             _var_ → _var_                  | Modifies [CS](#constraint-system)
0x?? | [`and`](#and)              | _constr1 constr2_ → _constr3_              |
0x?? | [`or`](#or)                | _constr1 constr2_ → _constr3_              |
0x?? | [`verify`](#verify)        |      _constraint_ → ø                      | Modifies [CS](#constraint-system) 
0x?? | [`blind`](#blind)          |   _var Q V proof_ → _V_                    | [Defers point operations](#deferred-point-operations)
0x?? | [`reblind`](#reblind)      |              _??_ → _V_                    | [Defers point operations](#deferred-point-operations)
0x?? | [`unblind`](#unblind)      |    _var V scalar_ → _V_                    | [Defers point operations](#deferred-point-operations)
 |                                |                                            |
 |     [**Values**](#value-instructions)              |                        |
0x?? | [`issue`](#issue)          |       _qtyc pred_ → _contract_             | Modifies [CS](#constraint-system), [tx log](#transaction-log)
0x?? | [`borrow`](#borrow)        |    _qtyc flavorc_ → _–V +V_                | Modifies [CS](#constraint-system)
0x?? | [`retire`](#retire)        |           _value_ → ø                      | Modifies [CS](#constraint-system), [tx log](#transaction-log)
0x?? | [`qty`](#qty)              |     _signedvalue_ → _signedvalue qtyvar_   |
0x?? | [`flavor`](#flavor)        |     _signedvalue_ → _signedvalue flavorvar_|
0x?? | [`cloak:m:n`](#cloak)      | _signedvalues commitments_ → _values_      | Modifies [CS](#constraint-system)
0x?? | [`import`](#import)        |             _???_ → _value_                | Modifies [CS](#constraint-system), [tx log](#transaction-log)
0x?? | [`export`](#export)        |       _value ???_ → ø                      | Modifies [CS](#constraint-system), [tx log](#transaction-log)
 |                                |                                            |
 |     [**Contracts**](#contract-instructions)        |                        |
0x?? | [`input`](#input)          |           _input_ → _contract_             | Modifies [tx log](#transaction-log)
0x?? | [`output:k`](#output)      | _items... predicate_ → ø                   | Modifies [tx log](#transaction-log)
0x?? | [`contract:k`](#contract)  | _items... predicate_ → _contract_          | 
0x?? | [`nonce`](#nonce)          |          _predicate_ → _contract_          | Modifies [tx log](#transaction-log)
0x?? | [`data`](#data)            |               _item_ → ø                   | Modifies [tx log](#transaction-log)
0x?? | [`signtx`](#signtx)        |           _contract_ → _results..._        | Modifies [deferred verification keys](#signature)
0x?? | [`call`](#call)            |      _contract prog_ → _results..._        | [Defers point operations](#deferred-point-operations)
0x?? | [`left`](#left)            |       _contract A B_ → _contract’_         | [Defers point operations](#deferred-point-operations)
0x?? | [`right`](#right)          |       _contract A B_ → _contract’_         | [Defers point operations](#deferred-point-operations)
0x?? | [`delegate`](#delegate)    |  _contract prog sig_ → _results..._        | [Defers point operations](#deferred-point-operations)
 |                                |                                            |
 |     [**Stack**](#stack-instructions)               |                        |
0x?? | [`dup`](#dup)              |               _x_ → _x x_                  |
0x?? | [`drop`](#drop)            |               _x_ → ø                      |
0x?? | [`peek:k`](#peek)          |     _x[k] … x[0]_ → _x[k] ... x[0] x[k]_   |
0x?? | [`roll:k`](#roll)          |     _x[k] … x[0]_ → _x[k-1] ... x[0] x[k]_ |
0x?? | [`bury:k`](#bury)          |     _x[k] … x[0]_ → _x[0] x[k] ... x[1]_   |



### Data instructions

#### scalar

**scalar:_x_** → _scalar_

Pushes a [scalar](#scalar-type) `x` to the stack. `x` is a 32-byte immediate data.

Fails if the scalar is not canonically encoded (reduced modulo Ristretto group order).

#### point

**point:_x_** → _point_

Pushes a [point](#point-type) `x` to the stack. `x` is a 32-byte immediate data.

Fails if the point is not a valid compressed Ristretto point.

#### string

**string:_n_:_x_** → _string_

Pushes a [string](#string-type) `x` containing `n` bytes. 
Immediate data `n` is encoded as [LE32](#le32)
followed by `x` encoded as a sequence of `n` bytes.





### Scalar instructions

#### neg

_a_ **neg** → _(|G|–a)_

Negates the [scalar](#scalar-type) `a` modulo Ristretto group order `|G|`.

Fails if item `a` is not a [scalar type](#scalar-type).

#### add

_a b_ **add** → _(a+b mod |G|)_

Adds [scalars](#scalar-type) `a` and `b` modulo Ristretto group order `|G|`.

Fails if either `a` or `b` is not a [scalar type](#scalar-type).

#### mul

_a b_ **mul** → _(a·b mod |G|)_

Multiplies [scalars](#scalar-type) `a` and `b` modulo Ristretto group order `|G|`.

Fails if either `a` or `b` is not a [scalar type](#scalar-type).

#### eq

_a b_ **eq** → ø

Checks that [scalars](#scalar-type) are equal. Fails execution if they are not.

Fails if either `a` or `b` is not a [scalar type](#scalar-type).

#### range

_a_ **range:_n_** → _a_

Checks that a [scalar](#scalar-type) `a` is in `n`-bit range. Immediate data `n` is 1 byte and must be in [1,64] range.

Fails if:
* `a` is not a [scalar type](#scalar-type), or
* `n` is not in range [1,64], or
* any bit of `a[n..]` bits is set.



### Constraint system instructions

#### var

_P_ **var** → _v_

1. Pops a [point](#point-type) `P` from the stack.
2. Creates a _detached_ [variable](#variable-type) `v` from a [Pedersen commitment](#pedersen-commitment) `P`.
3. Pushes `v` to the stack.

Fails if `P` is not a [point type](#point-type).

#### const

_a_ **const** → _v_

1. Pops a [scalar](#scalar-type) `a` from the stack.
2. Creates an _attached_ [variable](#variable-type) `v` with weight `a` assigned to an R1CS constant `1`.
3. Pushes `v` to the stack.

Fails if `a` is not a [scalar type](#scalar-type).

#### mintime

**mintime** → _v_

Pushes an _attached_ [variable](#variable-type) `v` corresponding to the [minimum time bound](#time-bounds) of the transaction.

The variable represents time bound as a weight on the R1CS constant `1` (see [`cost`](#const)).

#### maxtime

**maxtime** → _v_

Pushes an _attached_ [variable](#variable-type) `v` corresponding to the [maximum time bound](#time-bounds) of the transaction.

The variable represents time bound as a weight on the R1CS constant `1` (see [`cost`](#const)).

#### zkneg

_var1_ **zkneg** → _var2_

1. Pops a [variable](#variable-type) `var1`.
2. If the variable is detached, attaches it to the constraint system.
3. Negates the weights in the linear combination represented by `var1` producing new variable `var2`.
4. Pushes `var2` to the stack.

Fails if `var1` is not a [variable type](#variable-type).

#### zkadd

_var1 var2_ **zkadd** → _var3_

1. Pops two [variables](#variable-type) `var2`, then `var1`.
2. If any of the variables is detached, attaches that variable to the constraint system.
3. Adds two linear combinations represented by `var1` and `var2`, producing a new linear combination `var3`.
4. Pushes `var3` to the stack.

Fails if `var1` or `var2` is not a [variable type](#variable-type).

#### zkmul

_var1 var2_ **zkmul** → _var3_

1. Pops two [variables](#variable-type) `var2`, then `var1`.
2. If any of the variables is detached, attaches that variable to the constraint system.
3. Creates a multiplier in the constraint system. Constraints the left wire to `var1`, right wire to `var2`, creates a [variable](#variable-type) `var3` representing an output wire.
4. Pushes `var3` to the stack.

Fails if `var1` or `var2` is not a [variable type](#variable-type).

#### scmul

_var1 x_ **scmul** → _var2_

1. Pops [scalar](#scalar-type) `x` and [variable](#variable-type) `var1` from the stack.
2. Multiplies all weights in `var1` by `x`.
3. Pushes updated `var2` to the stack.

Fails if `x` is not a [scalar type](#scalar-type) or if `var2` is not a [variable type](#variable-type).

#### zkeq

_var1 var2_ **zkeq** → _constraint_

1. Pops two [variables](#variable-type) `var2`, then `var1`.
2. If any of the variables is detached, attaches that variable to the constraint system.
3. Creates a [constraint](#constraint-type) that represents statement `var1 - var2 = 0`.
4. Pushes constraint to the stack.

Fails if `var1` or `var2` is not a [variable type](#variable-type).

#### zkrange

_v_ **zkrange:_n_** → _v_

1. Pops a [variable](#variable-type) `v`.
2. If `v` is detached, attaches it to the constraint system.
3. Adds an `n`-bit range proof for `v` to the [constraint system](#constraint-system) (see [Cloak protocol](https://github.com/interstellar/spacesuit/blob/master/spec.md) for the range proof definition).
4. Pushes `v` back to the stack.

Immediate data `n` is encoded as one byte.

Fails if `v` is not a [variable type](#variable-type) or if `n` is not in range [1, 64].

#### and

_constraint1 constraint2_ **and** → _constraint3_

TBD: step-by-step spec.
Combines two constraints using logical conjunction: both constraints must be satisfied.

No changes to the [constraint system](#constraint-system) are made until [`verify`](#verify) is executed.

#### or

_constraint1 constraint2_ **or** → _constraint3_

TBD: step-by-step spec.
Combines two constraints using logical disjunction: either of two constraints must be satisfied.

No changes to the [constraint system](#constraint-system) are made until [`verify`](#verify) is executed.

#### verify

_constraint_ **verify** → ø

TBD: step-by-step spec.
Flattens the constraint and adds it to the [constraint system](#constraint-system).

For each disjunction, a multiplier is allocated.

For each conjunction, appropriate challenges are generated after the R1CS is complete, but before it is checked.

#### blind

_var P V proof_ **blind** → _V_

Verifies that the [Pedersen commitment](#pedersen-commitment) `V` is blinded with a factor committed using `P` and an ephemeral key specified in the proof.

```
proof = Q || R_q || s_q || R_v || R_w || R_p || s_p || s_w (8x32 = 256 bytes)

W + Q == p^{-1}·V
    W == p^{-1}·v·B
   B2 == p^{-1}·P
    Q == q·B2        (separate proof)

V = v·B + p·q·B2
```

TBD: rewrite the below description:

1. Pops a [string](#string-type) `proof`, and [points](#point-type) `V`, `F` and `X` from the stack.
2. Forms two statements to verify:
    ```
    X == x·B2
    F == x·V - x·v·B
    ```
3. Parses 2 points and 2 scalars from the 128-byte `proof` string:
    ```
    RX = proof[0..32]
    RF = proof[32..64]
    sx = proof[64..96]
    sv = proof[96..128]
    ```
4. Instantiates the [transcript](#transcript):
    ```
    T = Transcript("ZkVM.encrypt")
    ```
5. Performs the verification of the [blinding protocol](#blinding-protocol) using the transcript `T`, secrets `x = X/B2` and `f = F/X`:
    ```
    RX + e·X  ==  sx·B2
    RF + e·F  ==  sx·V - sv·B
    ```
6. Adds the statement to the list of [deferred point operations](#deferred-point-operations).
7. Pushes point `V` back to the stack.

Fails if `proof` is not a 128-byte [string](#string-type) or if `X`, `F` and `V` are not all [point](#point-type).

Usage 1: check if blinding factor is zero (therefore, the contract can allow interaction to anyone - like a partially fillable order book).

Usage 2: commit a secret value, but allow counterparty compute the value dynamically with a pre-agreed blinding factor (e.g. in a contract “collateralized loan with interest”).

Usage 3: embed blinding factor into the constraint system (since F is a valid unblinded commitment) and add constraints alongside other scalars.

#### reblind

_var V2 proof_ **reblind** → _var_

Verifies that the [Pedersen commitment](#pedersen-commitment) `V` (in the detached variable `v`) is reblinded into commitment `V2` with a factor committed using `P` and an ephemeral key specified in the proof.

```
proof = Q || R_q || s_q || R_f || R_v || s_p || s_f (7x32 = 224 bytes)

    F == p^{-1}·f·B2
F - R == p^{-1}·(V2-V1)
    Q == q·B2        (separate proof, copied from tx encrypted)

V1 = v·B + (x + p·q)·B2
V2 = v·B + (x + f)·B2
```

1. Pops [string](#string-type) `proof`, [point](#point-type) `V2` and [variable](#variable-type) `v`,  from the stack.
2. Checks that the variable is detached, fails otherwise.
3. Replaces variable commitment with V2.
4. TBD: Runs the proof using the current commitment as V1, defers point operations.
5. Pushes the variable back to the stack.

#### unblind

_var V scalar_ **unblind** → _V_

TBD: 



### Value instructions

#### issue

_qtyc pred_ **issue** → _contract_

1. Pops [points](#point-type) `pred`, then `qtyc` from the stack.
2. Creates a value with quantity represented by a [Pedersen commitment](#pedersen-commitment) _qtyc_ and flavor defined by the [predicate](#predicate) `pred` using the following [transcript-based](#transcript) protocol:
    ```
    T = Transcript("ZkVM.issue")
    T.commit("predicate", pred)
    flavor = T.challenge_scalar("flavor")
    F = flavor·B  (non-blinded Pedersen commitment)
    ```
3. Adds a 64-bit range proof for the quantity variable to the [constraint system](#constraint-system) (see [Cloak protocol](https://github.com/interstellar/spacesuit/blob/master/spec.md) for the range proof definition). 
4. Adds an [issue entry](#issue-entry) to the [transaction log](#transaction-log).
5. Creates a [contract](#contract-type) with the value as the only [payload](#contract-payload), with the predicate `pred`.

The value is now issued into the contract that must be unlocked
using one of the contract instructions: [`signtx`](#signx), [`delegate`](#delegate) or [`call`](#call).

TBD: customization tag, maybe hidden via commitment? Cleartext tag is useless because it can be embedded in a predicate.

Fails if either `qtyc` or `pred` are not [point types](#point-type).


#### borrow

_qtyc flavorc_ **borrow** → _–V +V_

1. Pops [points](#point-type) `flavorc`, then `qtyc` from the stack.
2. Creates [value](#value-type) `+V`, allocating high-level variables for quantity `q1` and flavor `f` in the [constraint system](#constraint-system).
3. Adds a 64-bit range proof for the quantity variable to the [constraint system](#constraint-system) (see [Cloak protocol](https://github.com/interstellar/spacesuit/blob/master/spec.md) for the range proof definition).
4. Creates [signed value](#signed-value-type) `–V`, allocating low-level variable `q2` for its negated quantity and reusing variable for the flavor `f`. Note: the signed value does not have its own Pedersen commitment.
5. Adds a constraint `q2 == -q1` to the constraint system. 
6. Pushes `–V`, then `+V` to the stack.

The signed value `–V` is not a [portable type](#portable-types), and can only be consumed by a [`cloak`](#cloak) instruction
(where it is merged with appropriate positive quantity of the same flavor).

Fails if either `qtyc` or `flavorc` are not [point types](#point-type).


#### retire

_value_ **retire** → ø

1. Pops a [value](#value) from the stack.
2. Adds a _retirement_ entry to the [transaction log](#transaction-log).

Fails if the value is not of unsigned (positive) [value type](#value-type).

#### qty

_signedvalue_ **qty** → _signedvalue qtyvar_

Copies a [variable](#variable-type) representing quantity of a [signed value](#signed-value-type) and pushes it to the stack.


#### flavor

_signedvalue_ **flavor** → _signedvalue flavorvar_

Copies a [variable](#variable-type) representing flavor of a [signed value](#signed-value-type) and pushes it to the stack.


#### cloak

_signedvalues commitments_ **cloak:_m_:_n_** → _values_

Merges and splits `m` [signed values](#signed-value-type) into `n` [values](#values).

1. Pops `2·n` [points](#point-type) as pairs of flavor and quantity for each output value, quantity is popped first.
2. Pops `m` [signed values](#signed-value-type) as input values.
3. Creates constraints and 64-bit range proofs for quantities per [Cloak protocol](https://github.com/interstellar/spacesuit/blob/master/spec.md).
4. Pushes `n` [values](#values) to the stack in the same order as their commitments.

Immediate data `m` and `n` are encoded as two [LE32](#le32)s.


#### import

_..._ **import** → _value_

TBD: Creates [value](#value) from the external blockchain.

The imported flavor is defined using [transcript](#transcript) protocol:

```
T = Transcript("ZkVM.import")
T.commit("extasset", external_asset_id)
T.commit("extaccount", pegging_account_id)
flavor = T.challenge_scalar("flavor")
```


#### export

_value ..._ **export** → ø

TBD: Retires imported [value](#value) with annotation for export.



### Contract instructions


#### input

_input_ **input** → _contract_

1. Pops an [input string](#input-structure) from the stack.
2. Constructs a [contract](#contract-type) based on the `input` data and pushes it to the stack.
3. Adds [input entry](#input-entry) to the [transaction log](#transaction-log).

Fails if the `input` is not a [string type](#string-type) with exact encoding of an [input structure](#input-structure).

#### output

_items... predicate_ **output:_k_** → ø

1. Pops [`predicate`](#predicate) from the stack.
2. Pops `k` items from the stack.
3. Adds an [output entry](#output-entry) to the [transaction log](#transaction-log).

Immediate data `k` is encoded as [LE32](#le32).


#### contract

_items... pred_ **contract:_k_** → _contract_

1. Pops [predicate](#predicate) `pred` from the stack.
2. Pops `k` items from the stack.
3. Creates a contract with the `k` items as a payload and the predicate.
4. Pushes the contract onto the stack.

Immediate data `k` is encoded as [LE32](#le32).


#### nonce

_predicate_ **nonce** → _contract_

1. Pops [predicate](#predicate) from the stack.
2. Pushes a new [contract](#contract-type) with an empty [payload](#contract-payload) and this predicate to the stack.
3. Adds [nonce entry](#nonce-entry) to the [transaction log](#transaction-log) with the predicate and transaction [maxtime](#time-bounds).

Fails if `predicate` is not a [point type](#point-type).


#### data

_item_ **data** → ø

1. Pops `item` from the stack.
2. Adds [data entry](#data-entry) with it to the [transaction log](#transaction-log).

Fails if the item is not a [data type](#data-types).


#### signtx

_contract_ **signtx** → _results..._

1. Pops the [contract](#contract-type) from the stack.
2. Adds the contract’s [predicate](#predicate) as a [verification key](#verification-key)
   to the list of deferred keys for [aggregated transaction signature](#aggregated-transaction-signature)
   check at the end of the VM execution.
3. Places the [payload](#contract-payload) on the stack (last item on top), discarding the contract.

Note: the instruction never fails as the only check (signature verification)
is deferred until the end of VM execution.


#### call

_contract(P) prog_ **call** → _results..._

1. Pops the [string](#string-type) `prog` and a [contract](#contract-type) `contract`.
2. Reads the [predicate](#predicate) `P` from the contract.
3. Forms a statement for [program predicate](#program-predicate) of `prog` being equal to `P`:
    ```
    0 == -P + h(prog)·B2
    ```
4. Adds the statement to the deferred point operations.
5. Places the [payload](#contract-payload) on the stack (last item on top), discarding the contract.
6. Saves the current program in the program stack, sets the `prog` as current and [runs it](#vm-execution).

Fails if the top item is not a [string](#string-type) or
the second-from-the-top is not a [contract](#contract-type).


#### left

_contract(P) L R_ **left** → _contract(L)_

1. Pops the right [predicate](#predicate) `R`, then the left [predicate](#predicate) `L`.
2. Reads the [predicate](#predicate) `P` from the contract.
3. Forms a statement for [predicate disjunction](#predicate-disjunction) of `L` and `R` being equal to `P`:
    ```
    0 == -P + L + f(L, R)·B
    ```
4. Adds the statement to the deferred point operations.
5. Replaces the contract’s predicate with `L` and leaves the contract on stack.

Fails if the top two items are not [points](#point-type),
or if the third from the top item is not a [contract](#contract-type).


#### right

_contract(P) L R_ **left** → _contract(R)_

1. Pops the right [predicate](#predicate) `R`, then the left [predicate](#predicate) `L`.
2. Reads the [predicate](#predicate) `P` from the contract.
3. Forms a statement of [predicate disjunction](#predicate-disjunction) of `L` and `R` being equal to `P`:
    ```
    0 == -P + L + f(L, R)·B
    ```
4. Adds the statement to the deferred point operations.
5. Replaces the contract’s predicate with `R` and leaves the contract on stack.

Fails if the top two items are not [points](#point-type),
or if the third from the top item is not a [contract](#contract-type).


#### delegate

_contract prog sig_ **delegate** → _results..._

1. Pops [strings](#string-type) `sig`, [string](#string-type) `prog` and the [contract](#contract-type) from the stack.
2. Instantiates the [transcript](#transcript):
    ```
    T = Transcript("ZkVM.delegate")
    ```
3. Commits the contract’s [predicate](#predicate) to the transcript:
    ```
    P = contract.predicate
    T.commit("P", P)
    ```
4. Commits the program `prog` to the transcript:
    ```
    T.commit("prog", prog)
    ```
5. Extracts nonce commitment `R` and scalar `s` from a 64-byte string `sig`:
    ```
    R = sig[ 0..32]
    s = sig[32..64]
    ```
6. Performs the [signature protocol](#signature) using the transcript `T`, secret key `dlog(contract.predicate)` and the values `R` and `s`:
    ```
    (s = dlog(r) + e·dlog(P))
    s·B  ==  R + e·P
    ```
7. Adds the statement to the list of [deferred point operations](#deferred-point-operations).
8. Saves the current program in the program stack, sets the `prog` as current and [runs it](#vm-execution).

Fails if:
1. the `sig` is not a 64-byte long [string](#string-type),
2. or `prog` is not a string,
3. or `contract` is not a [contract type](#contract-type).



### Stack instructions

#### dup

_x_ **dup** → _x x_

Pushes a copy of `x` to the stack.

Fails if `x` is not a [data type](#data-types).

#### drop

_x_ **drop** → ø

Drops `x` from the stack.

Fails if `x` is not a [data type](#data-types).

#### peek

_x[k] … x[0]_ **peek:_k_** → _x[k] ... x[0] x[k]_

Copies k’th data item from the top of the stack.
Immediate data `k` is encoded as [LE32](#le32).

Fails if `x[k]` is not a [data type](#data-types).

Note: `peek:0` is equivalent to `dup`.

#### roll

_x[k] x[k-1] ... x[0]_ **roll:_k_** → _x[k-1] ... x[0] x[k]_

Looks past `k` items from the top, and moves the next item to the top of the stack.
Immediate data `k` is encoded as [LE32](#le32).

Note: `roll:0` is a no-op, `roll:1` swaps the top two items.

#### bury

_x[k] ... x[1] x[0]_ **bury:_k_** → _x[0] x[k] ... x[1]_

Moves the top item past the `k` items below it.
Immediate data `k` is encoded as [LE32](#le32).

Note: `bury:0` is a no-op, `bury:1` swaps the top two items.









## Examples

### Lock value example

Locks value with a public key.

```
... (<value>) <pubkey> output:1
```

### Unlock value example

Unlocks a simple contract that locked a single value with a public key.
The unlock is performed by claiming the [input](#input-structure) and [signing](#signtx) the transaction.

```
<serialized_input> input signtx ...
```

### Simple payment example

Unlocks three values from the existing [inputs](#input-structure),
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

1. For N-of-N schemes, a set of independent public keys can be merged using a [MuSig](https://eprint.iacr.org/2018/068) scheme as described in [aggregated transaction signature](#aggregated-transaction-signature). This allows non-interactive key generation, and only a simple interactive signing protocol.
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

TBD.

### Loan example

TBD.

### Loan with interest

TBD.

### Payment channel example

TBD.

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


### Why there is no AND combinator in predicate tree?

The payload of a contract must be provided to the selected branch. If both predicates must be evaluated and both are programs, then which one takes the payload? To avoid ambiguity, AND can be implemented inside a program that can explicitly decide in which order and which parts of payload to process: maybe check some conditions and then delegate the whole payload to a predicate, or split the payload in two parts and apply different predicates to each part. There's [`contract`](#contract) instruction for that delegation.

