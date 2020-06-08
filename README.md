# Project Slingshot

_Accelerating trajectory into interstellar space._

Slingshot is a new blockchain architecture under active development,
with a strong focus on scalability, privacy and safety.

The Slingshot project consists of the following components:

### [Demo](demo)

Demo node where one can create transactions and inspect the blockchain.

* visit a public instance: [zkvm-demo.stellar.org](https://zkvm-demo.stellar.org).
* run on your own machine: [see instructions](demo/README.md).

### [ZkVM](zkvm)

ZkVM is a transaction format with **cloaked assets** and **zero-knowledge smart contracts**.

* [README](zkvm/README.md)
* [ZkVM whitepaper](zkvm/docs/zkvm-design.md)
* [ZkVM specification](zkvm/docs/zkvm-spec.md)
* [ZkVM API guide](zkvm/docs/zkvm-api.md)

### [Blockchain](blockchain)

Abstract blockchain state machine for the ZkVM transactions.

* [README](zkvm/README.md)
* [Blockchain specification](zkvm/docs/zkvm-blockchain.md)
* [Stubnet specification](zkvm/docs/zkvm-stubnet.md)

### [Spacesuit](spacesuit)

Interstellar’s implementation of _Cloak_, a confidential assets protocol
based on the [Bulletproofs](https://doc.dalek.rs/bulletproofs/index.html) zero-knowledge circuit proof system.

* [Spacesuit README](spacesuit/README.md)
* [Cloak specification](spacesuit/spec.md)

### [Starsig](starsig)

A pure Rust implementation of the Schnorr signature scheme based on [ristretto255](https://ristretto.group).

* [Starsig specification](starsig/docs/spec.md)

### [Musig](musig)

A pure Rust implementation of the [Simple Schnorr Multi-Signatures](https://eprint.iacr.org/2018/068) by Maxwell, Poelstra, Seurin and Wuille.

* [Musig specification](musig/docs/musig-spec.md)

### [Keytree](keytree)

A _key blinding scheme_ for deriving hierarchies of public keys for [Ristretto](https://ristretto.group)-based signatures.

* [Keytree specification](keytree/keytree.md)

### [Merkle](merkle)

A Merkle tree API for computing Merkle roots, making and verifying Merkle proofs.
Used for ZkVM transaction IDs, Taproot implementation and Utreexo commitments.

Based on [RFC 6962 Section 2.1](https://tools.ietf.org/html/rfc6962#section-2.1) and implemented using [Merlin](https://merlin.cool).

### [Accounts](accounts)

API for managing accounts and receivers. This is a building block for various payment protocols.

### [P2P](p2p)

Small p2p networking library that implements peer management logic with pluggable application logic.
Implements symmetric DH handshake with forward secrecy.

### [Reader/Writer](readerwriter)

Simple encoding/decoding and reading/writing traits and utilities for blockchain data structures.


![](https://user-images.githubusercontent.com/698/57546709-2d696c00-7312-11e9-8430-51ed9b51e6c8.png)
