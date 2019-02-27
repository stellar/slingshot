# Key tree

This is a _key blinding scheme_ for deriving hierarchies of public keys.

The most important feature of this scheme is that a set of _public_ keys can be derived from a _public_ key,
without the use of private keys. This allows a piece of software to generate unique receiving addresses
without having the private key material available (e.g., an online merchant may keep only public keys on the server and generate invoices with unique keys without compromising security of the private keys).

## Definitions

### Scalar

A _scalar_ is an integer modulo [Ristretto group](https://ristretto.group) order `|G| = 2^252 + 27742317777372353535851937790883648493`.

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

### Derivation key

Uniformly random secret 32-byte string used to derive blinding factors.

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
  point: CompressedRistretto,
  dk: [u8; 32]
}
```

Xpub is _semi-private_: it must be shared only with parties that are allowed to link together payments
that belong to the same root key. For instance, an online checkout software needs an Xpub
to generate individual public keys per invoice.

If you need to share an individual public key, use [leaf key derivation](#derive-a-leaf-key).

## Operations

### Generate key

1. Acquire a secure random number generator.
2. Generate a random 64-byte string, reduce it modulo Ristretto group order into a secret `scalar`.
3. Generate a random 32-byte string as a _derivation key_ `dk`.
4. Package the scalar and a derivation key in a [Xprv](#xprv) structure:
	```
	xprv = Xprv { scalar, dk }
	```
5. Return the resulting extended private key `xprv`.

### Convert Xprv to Xpub

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
	t.commit_bytes("pt", xpub.point)
	t.commit_bytes("dk", xpub.dk)
	```
3. Provide the transcript to the user to commit an arbitrary derivation path or index:
	```
	t.commit_bytes(label, data) 
	```
	E.g. `t.commit_u64("account", account_id)` for an account within a hierarchy of keys.
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
	t.commit_bytes("pt", xpub.point)
	t.commit_bytes("dk", xpub.dk)
	```
3. Provide the transcript to the user to commit an arbitrary selector data (could be structured):
	```
	t.commit_bytes(label, data)
	```
	E.g. `t.commit_u64("invoice", invoice_index)` for a receiving address.
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


## Test vectors

TBD.

