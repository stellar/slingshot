# Starsig specification

This is a technical specification for single-message Schnorr signature protocol
implemented with [Ristretto](https://ristretto.group) and [Merlin transcripts](https://merlin.cool).

* [Scalar](#scalar)
* [Point](#point)
* [Base point](#base-point)
* [Verification key](#verification-key)
* [Signature](#signature)
* [Transcript](#transcript)
* [Signature protocol](#signature-protocol)

### Scalar

A _scalar_ is an integer modulo [Ristretto group](https://ristretto.group) order 
`|G| = 2^252 + 27742317777372353535851937790883648493`.

Scalars are encoded as 32-byte strings using little-endian convention.

Every scalar is required to be in a canonical (reduced) form.

### Point

A _point_ is an element in the [Ristretto group](https://ristretto.group).

Points are encoded as _compressed Ristretto points_ (32-byte strings).


### Base point

Ristretto base point in compressed form:

```
B = e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76
```

### Verification key

A [point](#point) representing a key against which a [signature](#signature) is verified.

Verification key is computed by multiplying the [base point](#base-point) `B` by the secret [scalar](#scalar) `x`.

```
P = x·B
```

Verification key is encoded as a 32-byte string using Ristretto compression.


### Signature

A pair of a [point](#point) `R` and [scalar](#scalar) `s` that proves the knowledge of the secret key for a given message and a [verification key](#verification-key). Signature is _bound_ to the message and the verification key, but they are not the part of the signature data.

```
(R,s)
```

Signature is encoded as a 64-byte string using Ristretto compression for `R` and little-endian notation for 256-bit integer `s`.


### Transcript

Transcript is an instance of the [Merlin](https://merlin.cool) construction,
which is itself based on [STROBE](https://strobe.sourceforge.io/) and [Keccak-f](https://keccak.team/keccak.html)
with 128-bit security parameter.

Transcript is used in the signature protocols to perform Fiat-Shamir technique.

Transcripts have the following operations, each taking a label for domain separation:

1. **Initialize** transcript:
    ```
    T := Transcript(label)
    ```
2. **Append bytes** of arbitrary length prefixed with a label:
    ```
    T.append(label, bytes)
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


### Signature protocol

Single-message signature is a Schnorr proof of knowledge of a secret [scalar](#scalar) `x`
corresponding to some [verification key](#verification-key) in a context of some _message_.

The protocol is the following:

1. Prover and verifier obtain a [transcript](#transcript) `T` that is assumed to be already bound to the _message_ being signed.
2. Prover and verifier both commit the verification key `X` (computed by the prover as `X = x·B`):
    ```
    T.append("dom-sep", "starsig v1")
    T.append("X", X)
    ```
3. Prover creates a _secret nonce_: a randomly sampled [scalar](#scalar) `r`.
4. Prover commits to its nonce:
    ```
    R = r·B
    ```
5. Prover sends `R` to the verifier.
6. Prover and verifier write the nonce commitment `R` to the transcript:
    ```
    T.append("R", R)
    ```
7. Prover and verifier compute a Fiat-Shamir challenge scalar `c` using the transcript:
    ```
    c = T.challenge_scalar("c")
    ```
8. Prover blinds the secret scalar `x` using the nonce and the challenge:
    ```
    s = r + c·x
    ```
9. Prover sends `s` to the verifier.
10. Verifier checks the relation:
    ```
    s·B  ==  R + c·X
    ```
