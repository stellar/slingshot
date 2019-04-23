# Signatures: Engineering design doc

This is a signature scheme for signing messages. 
This design doc describes the protocol for signing a single message with one public key 
(where the public key can be created from a single party's private key, 
or from the aggregation of multiple public keys),
and for signing multiple messages with multiple public keys.
The public key aggregation and multi-message signing protocols are implemented from the paper,
["Simple Schnorr Multi-Signatures with Applications to Bitcoin"](https://eprint.iacr.org/2018/068.pdf).

In future work, we can consider signing with public keys that are nested aggregations of public keys.

## Definitions

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

### MusigContext

This is a public trait with functions:
- `commit(&self, &mut transcript)`: takes a mutable transcript, and commits the internal context to the transcript.
- `challenge(&self, index, &mut transcript) -> Scalar`: takes the index of a public key
and a mutable transcript, and returns the suitable challenge for that public key from the transcript. 
- `len(&self) -> usize`: returns the number of pubkeys associated with the context.
- `key(&self, index: usize)`: returns the key at `index`.

### Multikey 

Implements MusigContext

Fields:
- prf: `Option<Transcript>`. All of the pubkeys that the multikey are created from are committed to this transcript. It is `None` if the multikey only consists of one public key.
- aggregated_key: `VerificationKey`
- public_keys: `Vec<VerificationKey>`

Functions: 
- `Multikey::new(...) -> Result<Self, MusigError>`: detailed more in [key aggregation](#key-aggregation) section. 

- `Multikey::commit(&self, &mut transcript)`: Commits `self.aggregated_key` to the input `transcript` with label "X".

- `Multikey::challenge(&self, &verification_key, &mut transcript) -> Scalar`: 
  Computes challenge `c_i = a_i * c`, where `a_i = H_agg(<L>, i)` and `c = H_sig(X, R, m)`.
  
  For calculating `a_i`, the function expects that `commit()` has already been called on the multikey, 
  so that `<L>` (the list of pubkeys that go into the aggregated pubkey) has already been committed into `self.transcript`. Therefore, to calculate `a_i`, this function simply clones `self.transcript`, 
  commits the index of the party (`i`) into the transcript with label "i", 
  and then gets the challenge scalar `a_i` from the transcript with label "a_i".

  For calculating `c`, the function expects that the message `m`, the nonce commitment sum `R`, 
  and the aggregated key `X` have already been committed to the input `transcript`.
  It then gets the challenge scalar `c` from the transcript with label "c".

  Returns `c_i = a_i * c`.

- `Multikey::aggregated_key(&self) -> VerificationKey`: returns the aggregated key stored in the multikey, `self.aggregated_key`.  

- `Multikey::len(&self) -> usize`: returns the length of `self.public_keys`.

- `Multikey::key(&self, index) -> VerificationKey`: returns the pubkey at `index` of `self.public_keys`

### Multimessage

Implements MusigContext

Fields:
- pairs: `Vec<(VerificationKey, &[u8])>`

Functions:
- `Multimessage::new(Vec<(VerificationKey, &[u8])>) -> Self`: creates a new Multimessage instance using the input.

- `Multimessage::commit(&self, &mut transcript)`: 
  It commits to the number of pairs, with label "Musig.Multimessage". 
  It then commits each of the pairs in `self.pairs`, by iterating through `self.pairs` and 
  committing the `VerificationKey` with label "X" and the message with label "m".

- `Multimessage::challenge(&self, i, &mut transcript) -> Scalar`: 
  Computes challenge `c_i = H(R, <S>, i)`, where `i` is the index of the public key 
  that it is getting a challenge for. The function expects that the nonce commitment sum `R`, 
  and the pairs `<S>`, have already been committed to the input `transcript`.

  It forks the input transcript by cloning it. It commits `i` to the forked transcript with label "i".
  It then gets and returns the challenge scalar `c_i` from the forked transcript with label "c".

- `Multimessage::len(&self) -> usize`: returns the length of `self.pairs`.

- `Multimessage:key(&self, index) -> VerificationKey`: returns the key at that index in `self.pairs`.


### Signature

A signature is comprised of a scalar `s`, and a RistrettoPoint `R`. 
In the simple Schnorr signature case, `s` represents the Schnorr signature scalar and `R` represents the nonce commitment. 
In the Musig signature case, `s` represents the sum of the Schnorr signature scalars of each party, or `s = sum_i (s_i)`. 
`R` represents the sum of the nonce commitments of each party, or `R = sum_i (R_i)`. 

Functions:
- `Signature::sign_single(...) -> Signature`
- `Signature::sign_multi(...) -> Result<Signature, MusigError>`
For more detail, see the [signing](#signing) section.

- `Signature::verify(...) -> DeferredVerification`
- `Signature::verify_multi(...) -> DeferredVerification`
For more detail, see the [verification](#verifying) section.

## Operations

### Key Aggregation

Key aggregation happens in the `Multikey::new(...)` function. 

Input:
- pubkeys: `Vec<VerificationKey>`. This is a list of compressed public keys that will be aggregated, 
  as long as they can be decompressed successfully.

Operation:
- Create a new transcript using the tag "Musig.aggregated-key". 
- Commit to the length of the pubkeys with the tag "n".
- Commit all the pubkeys to the transcript with the tag "X".
The transcript state corresponds to the commitment `<L>` in the Musig paper: `<L> = H(X_1 || X_2 || ... || X_n)`.
- Create `aggregated_key = sum_i ( a_i * X_i )`. 
Iterate over the pubkeys, compute the factor `a_i = H(<L>, X_i)`, and add `a_i * X_i` to the aggregated key.

Output:
- a new `Multikey`, with the transcript and aggregated key detailed above.

### Signing

There are several paths to signing:
1. Make a Schnorr signature with one public key (derived from one private key).
    Function: `Signature::sign_single(...)`

    Input: 
    - transcript: `&mut Transcript` - a transcript to which the message to be signed has already been committed.
    - privkey: `Scalar`

    Operation:
    - Clone the transcript state, mix it with the privkey and system-provided RNG to generate the nonce `r`. 
    This makes the nonce uniquely bound to a message and private key, and also makes it non-deterministic to prevent "rowhammer" attacks.
    - Use the nonce to create a nonce commitment `R = r * G`
    - Make `c = H(X, R, m)`. Because `m` has already been fed into the transcript externally, 
    we do this by committing `X = privkey * G` to the transcript with label "X", 
    committing `R` to the transcript with label "R", and getting the challenge scalar `c` with label "c".
    - Make `s = r + c * x` where `x = privkey`

    Output:
    - Signature { `s`, `R` }

2. Make a Schnorr signature with one aggregated key (`Multikey`), derived from multiple public keys 
   owned my multiple signing parties (signers).
    - Create a `Multikey`. For more information, see the [key aggregation](#key-aggregation) section.

    Each signer gets initialized, and makes and shares its nonce precommitment.
    - Call `Signer::new(transcript, position, x_i, multikey)`.
    - Get back `SignerAwaitingPrecommitments` and a `NoncePrecommitment`.
    - Share your `NoncePrecommitment`, and receive other signers' `NoncePrecommitment`s. 

    Each signer receives and stores other signers' precommitments, and shares its nonce commitment.
    - Call `receive_precommitments(precommitments)` on your `SignerAwaitingPrecommitments` state, 
    inputting a vector of all signers' precommitments.
    - Get back `SignerAwaitingCommitments` and a `NonceCommitment`.
    - Share your `NonceCommitment`, and receive other signers' `NonceCommitment`s.

    Each signer receives and validates other signers' commitments, and shares its signature share.
    - Call `receive_commitments(commitments)` on your `SignerAwaitingCommitments` state, 
    inputting a vector of all signers' commitments.
    - Get back `SignerAwaitingShares` and a `Share`.
    - Share your `Share`, and receive other signers' `Share`s.

    Each signer receives and validates other signers' signature shares, and returns a signature.
    - Call `receive_shares(share)` on your `SignerAwaitingShares`.
    - Get back `Signature`. You are done!

    For more information on each of these states and steps, see the [protocol for signer state transitions](#protocol-for-signer-state-transitions).

3. Make a Schnorr signature with multiple public keys and multiple messages, in a way that is safe from Russell's attack.
    - Create a `Multimessage` context by calling `Multimessage::new(...)`. 
      See the [multimessage](#multimessage) section for more details.

    For each signer that is taking part in the signing:
    - Call `Signer::new(transcript, privkey, multimessage)`.
    - All following steps are the same as in protocol #2.

### Verifying

There are several paths to verifying: 
1. Normal Schnorr signature verification (covers cases #1 and #2 in the [signing section](#signing)).
    Function: `Signature::verify(...)`

    Input: 
    - `&self`
    - transcript: `&mut Transcript` - a transcript to which the signed message has already been committed.
    - X: `VerificationKey`

    Operation:
    - Make `c = H(X, R, m)`. Since the transcript already has the message `m` committed to it, 
    the function only needs to commit `X` with label "X" and `R` with label "R", 
    and then get the challenge scalar `c` with label "c".
    - Make the `DeferredVerification` operation that checks if `s * G == R + c * P`. 
    `G` is the [base point](#base-point).

    Output:
    - `DeferredVerification` of the point operations to compute to check for validity.

2. Multi-message Schnorr signature verification (covers case #3 in [signing section](#signing)).
    Function: `Signature::verify_multi(...)`

    Input: 
    - `&self`
    - transcript: `&mut Transcript` - a transcript to which the signed message has already been committed.
    - messages: `Vec<(VerificationKey, &[u8])>` 

    Operation:
    - Make a `Multimessage` instance from `messages`, and call `commit()` on it to commit its state 
    to the transcript. 
    - Commit `self.R` to the transcript with label "R".
    - Use `multimessage.challenge(pubkey, &mut transcript)` to get the per-pubkey challenge `c_i` for each party.
    - Make the `DeferredVerification` operation that checks the linear combination: `s * G = R + sum{c_i * X_i}`.

    Output:
    - `DeferredVerification` of the point operations to compute to check for validity.

## Protocol for signer state transitions

We create a different struct for each signer step in the MPC protocol, to represent the state and state transition. 
This allows us to use the Rust type system to enforce correct state transitions, 
so we have a guarantee that the protocol was followed in the correct order.

Signer state transitions overview:
```
Signer{}
  ↓
.new(transcript, privkey, context) → NoncePrecommitment([u8; 32])
  ↓
SignerAwaitingPrecommitments{transcript, privkey, context, nonce, noncecommitment, Vec<Counterparty>}
  ↓
.receive_precommitments(self, Vec<precommitment>) → NonceCommitment(RistrettoPoint)
  ↓
SignerAwaitingCommitments{transcript, privkey, context, nonce, Vec<CounterpartyPrecommitted>}
  ↓
.receive_commitments(self, Vec<commitment>) → Share(Scalar)
  ↓
SignerAwaitingShares{context, c, R, Vec, CounterpartyCommitted>} 
  ↓
.receive_shares(self, Vec<share>) → Signature{s, R}

```

Note:
For now, we will have message redundancy - meaning, each signer will receive and verify its own messages 
as well as its counterparties' messages. This makes the protocol slightly simpler, but does incur a performance overhead. 
(Future work: potentially remove this redundancy).

Also, for now we will assume that all of the messages passed into each signer state arrive in the same order 
(each signer's message is in the same index). This allows us to skip the step of ordering them manually.
(Future work: allow for unordered inputs, have the signers sort them.)

### Signer

Fields: none

Function: `new<'t, C: MusigContext>(...)`

Input: 
- transcript: `&'t mut Transcript` - a transcript to which the message to be signed has already been committed.
- position: usize,
- x_i: `Scalar`
- context: `C`

Operation:
- Use the transcript to generate a random factor (the nonce), by committing to the privkey and passing in a `thread_rng`.
- Use the nonce to create a nonce commitment and precommitment (`r_i` and `R_i`).
- Clone the transcript.
- Create a vector of `Counterparty`s by calling `Counterparty::new(...)` with the each of the positions and pubkeys in the context. 

Output:

- The next state in the protocol: `SignerAwaitingPrecommitments` 
- The nonce precommitment: `NoncePrecommitment`

### SignerAwaitingPrecommitments<'t, C: MusigContext> 

Fields: 
- transcript: `Transcript`
- context: `C`
- x_i: `Scalar`
- r_i: `Scalar`
- R_i: `RistrettoPoint`
- counterparties: `Vec<Counterparty>`

Function: `receive_precommitments(...)`

Input: 
- `self`
- nonce_precommitments: `Vec<NoncePrecommitment>`

Operation:
- Call `precommit_nonce(...)` on each of `self.counterparties`, with the received `nonce_precommitments`. 
This will return `CounterpartyPrecommitted`s.

Output:
- the next state in the protocol: `SignerAwaitingCommitments`
- the nonce commitment: `self.R_i`

### SignerAwaitingCommitments<'t, C: MusigContext>

Fields:
- transcript: `Transcript`
- context: `C`
- position: `usize`
- x_i: `Scalar`
- r_i: `Scalar`
- counterparties: `Vec<CounterpartyPrecommitted>`

Function: `receive_commitments(...)`

Input:
- `mut self`
- nonce_commitments: `Vec<NonceCommitment>`

Operation:
- Call `verify_nonce(...)` on each of `self.counterparties`, with the received `nonce_commitments`. 
This checks that the stored precommitments match the received commitments. 
If it succeeds, it will return `CounterpartyCommitted`s.
- Commit the context to `self.transcript` by calling `MusigContext::challenge(...)`.
- Make `nonce_sum` = sum(`nonce_commitments`).
- Commit `nonce_sum` to `self.transcript` with label "R".
- Make `c_i` = `context.challenge(self.position, &mut transcript)`.
- Make `s_i` = `r_i + c_i * x_i`.

Output: 
- The next state in the protocol: `SignerAwaitingShares`
- The signature share: `s_i`

### SignerAwaitingShares<C: MusigContext>

Fields:
- transcript: `Transcript`
- context: `C`
- R: `RistrettoPoint`
- counterparties: `Vec<CounterpartyCommitted>`

Function: `receive_shares(...)`

Input: 
- `self`
- shares: `Vec<Share>`

Operation:
- Call `verify_share(...)` on each of `self.counterparties`, with the received `shares`. 
This checks that the shares are valid, using the information in the `CounterpartyCommitted`. 
(Calling `receive_trusted_shares(...)` skips this step.)
- Make `s` = `sum(shares)`

Output
- `Result<Signature, MusigError>`. It returns `Some(Signature)` if the share verifications succeed,
or a `MusigError` with the failing share index, if a share fails to verify correctly.

Function: `receive_trusted_shares(...)`
This function behaves in the same way as `receive_shares(...)`, except that it does not check
the validity of the shares that it receives before summing the shares and returning the signature.
Thus, it returns `Signature` instead of a `Result`, since it can not fail.

## Protocol for counterparty state transitions
Counterparties are states stored internally by a signer, that represent the messages received from its counterparties. 

Counterparty state transitions overview:
```
Counterparty{position, pubkey}
  ↓
.precommit_nonce(precommitment)
  ↓
CounterpartyPrecommitted{precommitment, position, pubkey}
  ↓
.commit_nonce(commitment)
  ↓
CounterpartyCommitted{commitment, position, pubkey}
  ↓
.verify_share(share, context, transcript)
  ↓
 s_i

s_total = sum{s_i}
R_total = sum{R_i}
Signature = {s: s_total, R: R_total}
```

### Counterparty

Fields: 
- position: `usize`
- pubkey: `VerificationKey`

Function: `new(...)`

Input: 
- position: `usize`
- pubkey: `VerificationKey`

Operation:
- Create a new `Counterparty` instance with the inputs

Output: 
- The new `Counterparty` instance



Function: `precommit_nonce(...)`

Input:
- `self`
- precommitment: `NoncePrecommitment`

Operation:
- Create a new `CounterpartyPrecommitted` instance with the input precommitment.
- Future work: receive pubkey (or index) together with the precommitmentin this function, 
and match against stored counterparties to make sure the pubkey corresponds. 
This will allow us to receive messages out of order, and do sorting on the party's end.

Output:
- `CounterpartyPrecommitted`

### CounterpartyPrecommitted

Fields:
- `self`
- precommitment: `NoncePrecommitment`
- position: `usize`
- pubkey: `VerificationKey`

Function: `verify_nonce(...)`

Input: 
- `self`
- commitment: `NonceCommitment`

Operation:
- Verify that `self.precommitment = commitment.precommit()`.
- If verification succeeds, create a new `CounterpartyCommitted` the input commitment.
- Else, return `Err(VMError::MusigShareError)`.

Output:
- `Result<CounterpartyCommitted, MusigShareError>`.

### CounterpartyCommitted

Fields:
- commitment: `NonceCommitment`
- position: `usize`
- X_i: `VerificationKey`

Function: `verify_share<C: MusigContext>(...)`

Input:
- `self`
- share: `Scalar`
- context: `C`
- transcript: `&mut transcript`

Operation:
- Verify that `s_i * G == R_i + c_i * X_i`.
  `s_i` = share, `G` = [base point](#base-point), `R_i` = self.commitment,
  `c_i` = `context.challenge(self.pubkey, &mut transcript)`, `X_i` = self.pubkey.
- If verification succeeds, return `Ok(share)`
- Else, return `Err(VMError::MusigShareError)`

Output:
- `Result<Scalar, VMError>`


## Modifications from the paper

### Using Merlin transcripts for hashing and randomness

The paper uses multiple hashing algorithms (`H_agg` and `H_sig` in the multikey Musig protocol, and `H` in the multimessage protocol). We instead use Merlin transcripts, by feeding the expected hash input to the transcript, and getting a challenge from the transcript instead of a hash output. The benefits of using transcripts is detailed in this [blog post about Merlin transcripts](https://medium.com/@hdevalence/merlin-flexible-composable-transcripts-for-zero-knowledge-proofs-28d9fda22d9a).

### Changing challenge definition for Multikey case

In order to have a consistent multi-party signer protocol between the Multikey and Multimessage cases, we changed the definition of the hash function `H_agg` in the Multikey case from `c_i = H_agg(<L>, X_i)` to `c_i = H_agg(<L>, i)`. This way, the `.challenge(...)` functions in the Multikey and Multimessage cases are dependent on the public key's index `i`, instead of the public key itself. The safety of the protocol is not changed, since the hash function `H_agg` also takes `<L>`, the encoding of the multiset of the the public keys, as an input, so the hash output is bound to a specific public key in the list both when it takes in `i` and `X_i`.
