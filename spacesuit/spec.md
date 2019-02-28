# Cloak

_Cloak_ is a protocol for confidential assets based on the [Bulletproofs](https://crypto.stanford.edu/bulletproofs/) zero-knowledge proof system. _Cloaked transactions_ exchange values of different “asset types” (which we call [flavors](#flavor)).

* [Requirements](#requirements)
* [Future directions](#future-directions)
* [Definitions](#definitions)
    * [Scalar](#scalar)
    * [Signed integer](#signed-integer)
    * [Value](#value)
    * [Quantity](#quantity)
    * [Flavor](#flavor)
    * [Gadget](#gadget)
    * [Transaction](#transaction)
    * [K-scalar shuffle](#k-scalar-shuffle)
    * [K-value shuffle](#k-value-shuffle)
    * [Pad](#pad)
    * [Mix](#mix)
    * [K-mix](#k-mix)
    * [K-merge](#k-merge)
    * [K-split](#k-split)
    * [Range proof](#range-proof)
* [Converting boolean expressions](#converting-boolean-expressions)
* [Computing assignments](#computing-assignments)


## Requirements

#### Soundness

The protocol guarantees to the verifier that each transaction is balanced _per flavor_.

Assumptions:
1. Input [quantities](#quantity) are [scalars](#scalar) in the [signed integer](#signed-integer) range. 
2. Number of inputs and outputs is below 2^64, such that quantities cannot wrap around the group order.

Guarantees:
1. Non-zero output quantities were not created from nowhere or dropped.
2. Non-zero output quantities were not transmuted from one [flavor](#flavor) to another.
3. Per each [flavor](#flavor), the sum of all input quantities is equal to the sum of all output quantities.
4. Each output [quantity](#quantity) is in non-negative range `[0, 2^64-1]`.

#### Secrecy

The protocol must preserve secrecy of the values and secrecy of distribution of the flavors.
In other words, all transfers with `M` inputs and `N` outputs must be indistinguishable to the verifier.

Note: protecting the metadata (e.g. linkability of asset flow between the distinct transactions)
is out of scope of this protocol. However, a higher-level system that solves this problem could
use Cloak as a building block.

## Definitions

### Scalar

An integer mod `l` where `l` is a Ristretto group order (`l = 2^252 + 27742317777372353535851937790883648493`).

### Signed integer

An integer in range [-2^64+1, 2^64-1].

### Value

The _value_ `v` is the tuple `(q, f)`, consisting of both an untyped [quantity](#quantity) `q` as well as
type information `f` that we call [flavor](#flavor).

In the rest of this specification, we will always use the word _value_
to denote the typed quantity `(q, f)` and the word _quantity_ to denote an untyped quantity `q`.

Values are encrypted using Pedersen commitments, one per component.

### Quantity

A [signed integer](#signed-integer) `q` representing a numeric amount of a given [value](#value). 

Note: input values may have a negative quantity, but all outputs of a transaction are proven to be non-negative.

### Flavor

A [scalar](#scalar) `f` representing a unique asset type of a given [value](#value).

[Values](#value) of different flavors cannot be merged. One flavor cannot be transmuted to another.

### Gadget

Each gadget represents constraints on a number of variables.
Gadgets can be composed of nested gadgets.

### Transaction

A transaction is a [gadget](#gadget) that represents the transfer of `M` input [values](#value) into `N` output [values](#value).

A transaction consists of:

1. [M-value shuffle](#k-value-shuffle) that proves that [values](#value) are sorted by [flavor](#flavor) for the following merge.
2. [M-merge](#k-merge) that proves merge of all [values](#value) of the same [flavor](#flavor) in one.
3. [K-value padded shuffle](#k-value-shuffle) (`K = max(M,N)`) that proves that [values](#value) are reordered by [flavor](#flavor) (such that non-zero values go before the zeroed ones). This gadget is [padded](#pad) with zero values on inputs or outputs as required.
4. [N-split](#k-split) that proves split of non-zero [values](#value) into a required number of smaller values per [flavor](#flavor).
5. [N-value shuffle](#k-value-shuffle) that proves that [values](#value) are preserved while being permuted in random order.
6. [N range proofs](#range-proof) that prove that each [quantity](#quantity) is in a valid range `[0, 2^64)`. This prevents the prover from creating “negative” quantities that may offset inflated “positive” quantities.

Transaction is the outermost gadget of this protocol.

```ascii

  M inputs                                                  N outputs
            -->█-->█------------->█---->█---------->█--█-->
            -->█-->█-->█--------->█---->█-->█------>█--█-->
            -->█------>█-->█----->█-------->█-->█-->█--█-->
            -->█-----------█----->█-------------█-->█--█-->
               |   |   |   |  0-->█-->0 |   |   |   |  |
               |    \  |  /   |   |   |  \  |  /    |  |
               |     \ | /    |   |   |   \ | /     |  |
               |     M-merge  |   |   |   N-split   | range proofs
               |              |   |   |             |
        first shuffle        pad  |  pad       final shuffle
                                  |
                            middle shuffle
```

Prover provides M input commitments, N output commitments, intermediate commitments, and a proof of the above relation between inputs and outputs.

Verifier constructs the relation from the commitments and parameters M and N, and verifies the proof.
If the verification is successful, the verifier is convinced of the [soundness](#soundness) of the transfer.

### K-scalar shuffle

Represents a permutation of a list of `k` [scalars](#scalar) `{x_i}`
into a list of `k` [scalars](#scalar) `{y_i}`.

Algebraically it can be expressed as a statement that for a free variable `z`,
the roots of the two polynomials in terms of `z` are the same up to a permutation:
    
    ∏(x_i - z) == ∏(y_i - z)

Prover can commit to blinded scalars `x_i` and `y_i`, then receive a random challenge `z`,
and build a proof that the above relation holds.

K-scalar shuffle requires `2*(K-1)` multipliers.

For K > 1:

```ascii
        (x_0 - z)---⊗------⊗---(y_0 - z)        // mulx[0], muly[0]
                    |      |
        (x_1 - z)---⊗      ⊗---(y_1 - z)        // mulx[1], muly[1]
                    |      |
                   ...    ...
                    |      |
    (x_{k-2} - z)---⊗      ⊗---(y_{k-2} - z)    // mulx[k-2], muly[k-2]
                   /        \
    (x_{k-1} - z)_/          \_(y_{k-1} - z)

    // Connect left and right sides of the shuffle statement
    mulx_out[0] = muly_out[0]

    // For i == [0, k-3]:
    mulx_left[i]  = x_i - z
    mulx_right[i] = mulx_out[i+1]
    muly_left[i]  = y_i - z
    muly_right[i] = muly_out[i+1]

    // last multipliers connect two last variables (on each side)
    mulx_left[k-2]  = x_{k-2} - z
    mulx_right[k-2] = x_{k-1} - z
    muly_left[k-2]  = y_{k-2} - z
    muly_right[k-2] = y_{k-1} - z
```

For K = 1:

```ascii
    (x_0 - z)--------------(y_0 - z)

    // Connect x to y directly, omitting the challenge entirely as it cancels out
    x_0 = y_0
```


### K-value shuffle

Represents a permutation of tuples ([quantity](#quantity), [flavor](#flavor)).

Each tuple of [scalars](#scalar) `(q, f)` is combined into a single scalar using a free variable `w`:

    x = q  + w*f

Then, the combined scalars are permuted using [K-scalar shuffle](#k-scalar-shuffle) gadget. 

If `w` is chosen unpredictably to a prover, any `x` scalar can be equal to a `y` scalar (computed in the same way)
iff their corresponding [quantities](#quantity) `q` and [flavors](#flavor) `f` are equal.

Note: for K = 1, no compression is necessary as the input variables can be constrained to be equal
to the output variables (or the same variables reused for adjacent gadgets).


### Pad

Represents an all-zero [value](#value) `(q, f) = (0, 0)`.
It is implemented as allocation of two variables and two constraints enforcing zero value for each variable.

In case `M == N`, no padding is required as all shuffles have the same number of inputs and outputs.

In case `M > N` (more inputs than outputs), the padding is applied to the _outputs_ to the middle [shuffle](#k-value-shuffle):
prover sorts unnecessary zero [values](#value) coming from [M-merge](#k-merge) to the end of the outputs list,
and verifier constraints them to all-zero tuples.

In case `N < M` (less inputs than outputs), the padding is applied to the _inputs_ to the middle [shuffle](#k-value-shuffle):
prover adds required zero [values](#value) in the clear to the end of the inputs list,
and secretly sorts them in required position for the subsequent [splits](#k-split).

### Mix

A _mix_ gadget proves that two [values](#value) either remain _unchanged_,
or are _redistributed_ with one value being zero.
    
    Mix(A,B,C,D):
    (a) unchanged:     A = C, B = D
    (b) redistributed: C = 0, D = A+B

_Mix_ is a building block for [K-mix](#k-mix) gadget which is itself a building block for [K-merge](#k-merge) and [K-split](#k-split) gadgets.

In case of redistribution, the verifier allows the flavor of `C` to be anything.
However, the prover must set the whole tuple `C = (q, f)` to zeroes in
order to match the [padding](#pad) that might be necessary in the middle of a [transaction](#transaction).

Boolean expression:

    Mix(A,B,C,D) = OR(
        AND( // move
            A.q == C.q,
            A.f == C.f,
            B.q == D.q,
            B.f == D.f,
        ),
        AND( // distribute
            C.q == 0,
            A.f == B.f,
            D.q == A.q + B.q,
            D.f == A.f,
        )
    )

Mix requires a single challenge variable `w` to combine 6 statements in one (in each branch),
and one multiplier for `OR` statement.

    mul_left  = (A.q - C.q) +
                (A.f - C.f) * w^1 +
                (B.q - D.q) * w^2 +
                (B.f - D.f) * w^3 +
    mul_right = (C.q - 0) +
                (A.f - B.f) * w^1 +
                (D.q - A.q - B.q) * w^2 +
                (D.f - A.f) * w^3
    mul_out   = 0
    --------------------------------------
    1 multiplier, 3 constraints

When computing the proof, the assignments of all input and output values are assumed to be known.


### K-mix

_K-mix_ is a composition of `K-1` [mix gadgets](#mix) connected sequentially.

For a pair of [mixes](#mix) M1 and M2:
* First output of M1 is the first output of K-mix.
* Second output of M1 is the first input of M2.
* Second input of M2 is the last input of K-mix.

```ascii
  
      3-mix consisting of 2 simple mixes:
  
      +-----------------------+
      |  +------+             |
    --|--|      |-------------|--
      |  |  M1  |   +------+  |
    --|--|      |---|      |--|--
      |  +------+   |  M2  |  |
    --|-------------|      |--|--
      |             +------+  |
      +-----------------------+
```

When K=1, the K-mix gadget is not necessary: the output value is instead
constrained to be equal to the input value.

### K-merge

_K-merge_ is implemented using a [K-mix](#k-mix) gadget with the same order of variables:

    K-Merge(input_{0..k-1}, output_{0..k-1})
    =
    K-Mix(input_{0..k-1}, output_{0..k-1})


### K-split

_K-split_ is implemented using a [K-mix](#k-mix) gadget with the reversed inputs and outputs
and using inputs as outputs and vice versa:

    K-Split(input_{0..k-1}, output_{0..k-1})
    =
    K-Mix(output_{k-1..0}, input_{k-1..0})


### Range proof

Proves that a given [quantity](#quantity) is in a valid range using a binary representation:
the quantity is a sum of all bits in its bit-representation multiplied by corresponding powers of two, and each bit has either 0 or 1 value.

`n` multipliers `a_i*b_i = c_i` and `1 + 2*n` constraints:

    c_i == 0           for i in [0,n)  // n constraints on multipliers’ outputs
    a_i == (1 - b_i)   for i in [0,n)  // n constraints on multipliers’ inputs
    q = Sum(b_i * 2^i, i = 0..n-1)     // 1 constraint between quantity and the multipliers’ inputs

where:

* `b_i` is a bit and a left input to the `i`th multiplier.
* `a_i` is a right input to an `i`th multiplier set to `1 - b_i` .
* `c_i` is a multiplication result of `a_i` and `b_i`.
* `q` is a [quantity](#quantity).

Computing the proof:

1. The [quantity](#quantity) is assumed to be known and be in range `[0, 2^64)`.
2. Create 64 multipliers.
3. Assign the inputs and outputs of the multipliers to the values specified above.


## Converting boolean expressions

Any gadget that expresses a boolean function of some statements needs to convert it into a form
required by _Rank-1 Constraint System_ (R1CS) which specifies linear constraints between external
commitments and multipliers.

#### 1. Normalize statements

Each statement of the form `a = b` must be converted to a form `c = 0`, where `c = a - b`.

    a = b    ->    a - b = 0

#### 2. Convert a disjunction of statements into a multiplication
    
Each statement of the form `or(a = 0, b = 0)` is converted into a statement about multiplication: `a*b = 0`.

    a = 0 or b = 0    ->    a*b = 0

This means, each `OR` function requires a multiplier.

#### 3. Convert a conjunction of statements into a polynomial

Each statement of the form `and(a = 0, b = 0)` is converted into a 1-degree polynomial with a unique free variable `x`:

    a + x*b = 0

As an optimization, conjuction of `n+1` statements can use `n`-degree polynomial of the free variable `x`:

    a = 0 and b = 0 and c = 0   ->   a + x*b + x*x*c = 0

Note: the `AND` does not require a multiplier because secrets are multiplied by a non-secret _constant_ `x`.




## Computing assignments

Prover needs to compute exact [scalar](#scalar) assignments for all variables used in all gadgets.
It is typically done at the appropriate gadget: some variables are provided by upstream gadgets,
while others need to be allocated and assigned internally.

#### [Transaction](#transaction) assignments

`M` input and `N` output [values](#value) are assumed to be already assigned and randomly ordered.
The goal is to assign values for all the intermediate variables necessary to connect
[shuffle](#k-value-shuffle), [merge](#k-merge) and [split](#k-split) gadgets.

```
               B
A              B
B              A
A   ---?--->   B
B              B
A              A
               B
```


For the first [M-value shuffle](#k-value-shuffle), the `M` [values](#value) are sorted by [flavor](#flavor):

```
A        A
B        A
A   ->   A
B        B
A        B
```

For the [M-merge](#k-merge) outputs, all values are added up within each [flavor](#flavor) group,
assigning the sum to the _last_ variable in the group, and setting all preceding variables to zeroes:

```
A        0
A        0
A   ->   A_sum
B        0
B        B_sum
```

If `N` is greater than `M`, the list is [padded](#pad) with `|M - N|` all-zero values:

```
0          0
0          0
A_sum  ->  A_sum
0          0
B_sum      B_sum
           0
           0
```

In the second half of the transaction, assign values in reverse order (from end towards the middle).

For the `N` input values of the last [N-value shuffle](#k-value-shuffle), outputs are sorted
by flavor:

```
A       B
A       B
B       A
B   <-  B
B       B
B       A
B       B
```

For the output values of the middle [K-value shuffle](#k-value-shuffle) (`K = max(N,M)`), 
all values are added up within each [flavor](#flavor) group, assigning the sum to the _first_ variable
in the group, and setting all subsequent variables in the group to zeroes:

```
A_sum       A
0           A
B_sum       B
0      <-   B
0           B
0           B
0           B
```

If `N` is less than `M` (not the case in this example transaction), the list is [padded](#pad) 
with `|M - N|` all-zero values:

```
A_sum       A_sum
0           0    
B_sum       B_sum
0      <-   0    
0           0    
0           0    
0           0    
0
0
```

Finally, the lists of values on the left and right sides of the middle [K-value shuffle](#k-value-shuffle)
have `K = max(N,M)` values in each, with the same amount of zero values and one non-zero value per flavor,
satisfying the permutation constraint that the outputs are a valid reordering of the inputs.

```
          ____________
0     ---|            |--- A_sum  
0     ---|            |--- 0      
A_sum ---|  K-value   |--- B_sum  
0     ---|  shuffle   |--- 0      
B_sum ---|            |--- 0      
0     ---|            |--- 0      
0     ---|____________|--- 0 

(Since N = M + 2, the inputs are padded with two all-zero values.)
```

Note: order of flavors with respect to each other is actually unimportant and can be inconsistent
between the left and right halves of the transaction. It must only be consistent within each half of the transaction.

#### [K-mix](#k-mix) assignments

All input values are assumed to be known.

The intermediate variables connecting inner [mix gadgets](#mix) and output variables are assigned sequentially.
For each [mix](#mix) gadget, its A and B [values](#value) are known, and C and D are to be determined.

1. If A and B have the same [flavor](#flavor), then values are redistributed: 
   - Assign D to have quantity `A.quantity + B.quantity` and have flavor equal to `A.flavor` and `B.flavor`. 
   - Assign C to have [quantity](#quantity) and [flavor](#flavor) of zero.
2. If A and B have different [flavors](#flavor), then values are unchanged: 
   - Assign C to be equal to A.
   - Assign D to be equal to B.

## Future directions

As a step towards protecting the metadata, we need to allow multiple parties to perform
individual transactions using a single circuit making them indistinguishable from a single-party transaction
of the same size. In order to achieve that we will need a multi-party computation protocol 
that allows multiple parties compute a joint proof for such combined circuit, while preserving privacy
of the participants with respect to each other.