# Starsig: schnorr signatures on Ristretto

Implementation of a simple Schnorr signature protocol
implemented with [Ristretto](https://ristretto.group) and [Merlin transcripts](https://merlin.cool).

* [Specification](docs/spec.md)

## Features

* Simple message-based API.
* Flexible [transcript](https://merlin.cool)-based API.
* Single signature verification.
* Batch signature verification.
* Compatible with [Musig](../musig) API.
* Compatible with [Keytree](../keytree) key derivation API.
* VRF (aka “HMAC verifiable by a public key”) is in development.

## Authors

* [Oleg Andreev](https://github.com/oleganza)
* [Cathie Yun](https://github.com/cathieyun)
