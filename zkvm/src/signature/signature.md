# Signatures: Engineering design doc

This is a signature scheme for signing messages. In the first iteration of this design, we are considering a case where we want to sign a single message with one public key. This public key can be created from a single party's public and private key pair, or it can be from the aggregation of multiple public keys. 

In future iterations, we can consider signing with public keys that are nested aggregations of public keys, and signing multiple messages in a way that is safe against Russell's attack.

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

### Multikey

Multikey creates transcript, commits pubkeys to transcript, and keeps transcript. Then allows functions to clone/fork the transcript to make per-key factors.
TODO: expand

### Signature

TODO

## Operations

### Key Aggregation

TODO

### Signing

TODO

### Verifying

TODO

## Protocol for party state transitions

We create a different struct for each party step in the protocol, to represent the state and state transition. This allows us to use the Rust type system to enforce correct state transitions, so we have a guarantee that the protocol was followed in the correct order.

Party state transitions overview:
```
Party{}
  ↓
.new(transcript, privkey, multikey, Vec<pubkey>) → NoncePrecommitment([u8; 32])
  ↓
PartyAwaitingPrecommitments{transcript, privkey, multikey, nonce, noncecommitment, Vec<Counterparty>}
  ↓
.receive_precommitments(self, Vec<precommitment>) → NonceCommitment(RistrettoPoint)
  ↓
PartyAwaitingCommitments{transcript, privkey, multikey, nonce, Vec<CounterpartyPrecommitted>}
  ↓
.receive_commitments(self, Vec<commitment>) → Share(Scalar)
  ↓
PartyAwaitingShares{multikey, c, R, Vec, CounterpartyCommitted>} 
  ↓
.receive_shares(self, Vec<share>) → Signature{s, R}

```

Note:
For now, we will have message redundancy - meaning, each party will receive and verify its own messages as well as its counterparties' messages. This makes the protocol slightly simpler, but does incur a performance overhead. (Future work: potentially remove this redundancy).

Also, for now we will assume that all of the messages passed into each party state arrive in the same order (each party's message is in the same index). This allows us to skip the step of ordering them / assigning indexes. (Future work: allow for unordered inputs, have the parties sort them.)

### Party

Fields: none

Function: `new(...)`

Input: 
- transcript: `&Transcript` - the message to be signed should have been fed to the transcript beforehand. (Future work: pass in a mutable borrow of a transcript instead of just a borrow.)
- privkey: `Scalar`
- multikey: `Multikey`
- pubkeys: `Vec<VerificationKey>` - all the public keys that went into the multikey. The list is assumed to be in the same order as the upcoming lists of `NoncePrecommitment`s, `NonceCommitment`s, and `Share`s.

Operation:
- use the transcript to generate a random factor (the nonce)
- use the nonce to create a nonce commitment and precommitment
- clone the transcript
- create a vector of `Counterparty`s using the pubkeys.

Output: 
- the next state in the protocol: `PartyAwaitingPrecommitments` 
- the nonce precommitment: `NoncePrecommitment`

### PartyAwaitingPrecommitments

Fields: 
- transcript: `Transcript`
- multikey: `Multikey`
- privkey: `Scalar`
- nonce: `Scalar`
- nonce_commitment: `RistrettoPoint`
- counterparties: `Vec<Counterparty>`

Function: `receive_precommitments(...)`

Input: 
- `self`
- nonce_precommitments: `Vec<NoncePrecommitment>`

Operation:
- call `precommit_nonce` on each of `self.counterparties`, with the received `nonce_precommitments`. This will return `CounterpartyPrecommitted`s.

Output:
- the next state in the protocol: `PartyAwaitingCommitments`
- the nonce commitment: `NonceCommitment`

### PartyAwaitingCommitments

Fields:
- transcript: `Transcript`
- multikey: `Multikey`
- privkey: `Scalar`
- nonce: `Scalar`
- counterparties: `Vec<CounterpartyPrecommitted>`

Function: `receive_commitments(...)`

Input:
- `self`
- nonce_commitments: `Vec<NonceCommitment>`

Operation:
- call `commit_nonce()` on each of `self.counterparties`, with the received `nonce_commitments`. This checks that the stored precommitments match the received commitments. If it succeeds, it will return `CounterpartyCommitted`s.
- make `nonce_sum` = sum(`nonce_commitments`)
- make `c` = challenge scalar after feeding `multikey.aggregated_key()` and `nonce_sum` into the transcript
- make `a_i` = `multikey.factor_for_key(self.privkey)`
- make `s_i` = `r_i + c * a_i * x_i`, where `x_i` = self.privkey and `r_i` = self.nonce

Output: 
- the next state in the protocol: `PartyAwaitingShares`
- the signature share: `Share`

### PartyAwaitingShares

Fields:
- multikey: `Multikey`
- counterparties: `Vec<CounterpartyCommitted>`
- challenge: `Scalar` // c
- nonce_sum: `RistrettoPoint` // R

Function: `receive_shares(...)`

Input: 
- `self`
- shares: `Vec<Share>`

Operation:
- call `sign()` on each of `self.counterparties`, with the received `shares`. This checks that the shares are valid, using the information in the `CounterpartyCommitted`. (Calling `receive_trusted_shares(...)` skips this step.)
- make `s` = `sum(shares)`

Output
- the signature: `Signature { self.nonce_sum, s }`

## Protocol for counterparty state transitions
Counterparties are states stored internally by a party, that represent the messages received by from its counterparties. 
// TODO: add more description

Counterparty state transitions overview:
```
Counterparty{pubkey: Verificationkey}
  ↓
.precommit_nonce(H: NoncePrecommitment) // simply adds precommitment
  ↓
CounterpartyPrecommitted{H, pubkey}
  ↓
.commit_nonce(R: NonceCommitment) // verifies hash(R) == H
  ↓
CounterpartyCommitted{R, pubkey}
/* R_total := sum{R_i}, commit to transcript, compute and send out siglet */
  ↓
.sign(s: Share) // verifies s_i*G == R_i + c * factor * pubkey_i
  ↓
  s

/* s_total = sum{s_i} */
```

