# Key tree

This is a _key blinding scheme_ for deriving hierarchies of public keys.

The most important feature of this scheme is that a set of _public_ keys can be derived from a _public_ key,
without the use of private keys. This allows a piece of software generate unique receiving addresses
without having the private key material available. E.g. an online merchant may keep only public keys on the server and generate invoices with unique keys without compromising security of the private keys.

## Definitions

### Scalar

A _scalar_ is an integer modulo [Ristretto group](https://ristretto.group) order `|G| = 2^252 + 27742317777372353535851937790883648493`.

Scalars are encoded as 32-byte strings using little-endian convention.

Every scalar is required to be in a canonical (reduced) form.

### Point

A _point_ is an element in the [Ristretto group](https://ristretto.group).

Points are encoded as 32-byte [data types](#data-type) in _compressed Ristretto form_.


### Base point

Ristretto base point in compressed form:

```
B = e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76
```

### Derivation key

Uniformely random secret 32-byte string used to derive blinding factors.

### Xprv

Stands for _extended private key_: consists of a secret [scalar](#scalar) and a [derivation key](#derivation-key).

```rust
struct Xprv {
  scalar: Scalar,
  dk: [u8; 32]
}
```

### Xpub

Stands for _extended public key_: consists of a [point](#point) and a [derivation key](#derivation-key).

```rust
struct Xpub {
  scalar: CompressedRistretto,
  dk: [u8; 32]
}
```

## Operations

### Generate key

1. Take RNG
2. Generate random 64-byte string, reduce mod |G| into secret scalar.
3. Generate random 32-byte string into derivation key.
4. Package in [xprv](#xprv).

### Convert xprv to xpub

Multiply base point by xprv's scalar.

```
Xpub {
	point: xprv.scalar·B,
	dk: xprv.dk
}
```

### Derive an intermediate key

1. Create Merlin `t = Transcript::new("Keytree.intermediate")`.
2. Commit [xpub](#xpub) to transcript (if xprv is provided, compute xpub from xprv):
	```
	t.commit_bytes("xpub", xpub)
	```
3. Provide the transcript to the user to commit an arbitrary selector data (could be structured):
	```
	t.commit_bytes(label, data)
	```
4. Squeeze a blinding factor `f`:
	```
	f = t.challenge_scalar("f")
	```
5. Squeeze a new derivation key `dk2` (32 bytes):
	```
	dk2 = t.challenge_bytes("dk")
	```
5. For `xprv` (if provided):
	```
	child = Xprv { scalar: parent.scalar + f, dk: dk2 }
	```
6. For `xpub`:
	```
	child = Xpub { point: parent.point + f·B, dk: dk2 }
	```

### Derive a leaf key

Similar to the intermediate derivation, but for safety is domain-separated so the same index produces unrelated public key.

1. Create Merlin `t = Transcript::new("Keytree.leaf")`.
2. Commit [xpub](#xpub) to transcript (if xprv is provided, compute xpub from xprv):
	```
	t.commit_bytes("xpub", xpub)
	```
3. Provide the transcript to the user to commit an arbitrary selector data (could be structured):
	```
	t.commit_bytes(label, data)
	```
4. Squeeze a blinding factor `f`:
	```
	f = t.challenge_scalar("f")
	```
5. For `xprv` (if provided) returns a blinded scalar:
	```
	child = parent.scalar + f
	```
6. For `xpub` returns a blinded public key:
	```
	child = parent.point + f·B
	```



