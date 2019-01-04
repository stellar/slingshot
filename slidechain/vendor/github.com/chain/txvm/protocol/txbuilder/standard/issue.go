package standard

import (
	"fmt"

	"github.com/chain/txvm/crypto/ed25519"
	"github.com/chain/txvm/protocol/txvm"
	"github.com/chain/txvm/protocol/txvm/op"
	"github.com/chain/txvm/protocol/txvm/txvmutil"
)

// a versioned asset contract map
var assetSrcFmt = map[int]string{
	// expects either:
	//   argument stack: [... refdata pubkeys quorum assettag amount zerovalue 0]
	// or:
	//   argument stack: [... refdata pubkeys quorum assettag amount blockid maxtime] with non-zero `maxtime`
	//
	// In the latter case, a zeroval is generated with "nonce" and the given expiration time.
	//
	// pubkeys is {p1, p2, ..., p_n}
	1: `
                  # Contract stack                                          Argument stack                                                        Log
                  # []                                                      [refdata pubkeys quorum tag amount (zeroval 0)|(blockid maxms)]
get               # [(0|maxms)]                                             [refdata pubkeys quorum tag amount (zeroval|blockid)]
dup not           # [(0|maxms) ((0|maxms)==0)]                              [refdata pubkeys quorum tag amount (zeroval|blockid)]
jumpif:$havezero  # [maxms]                                                 [refdata pubkeys quorum tag amount blockid minms]
    get           # [maxms blockid]                                         [refdata pubkeys quorum tag amount]
    swap          # [blockid maxms]                                         [refdata pubkeys quorum tag amount]
    nonce         # [zeroval]                                               [refdata pubkeys quorum tag amount]                                   [{"N", <caller>, <cseed>, bid, exp} {"R", minms, maxms}]
    jump:$cont
$havezero         # [0]                                                     [refdata pubkeys quorum tag amount zeroval]                           []
drop get          # [zeroval]                                               [refdata pubkeys quorum tag amount]                                   []
$cont
get               # [zeroval amount]                                        [refdata pubkeys quorum tag]                                          [({"N", ...} {"R", ...})]
get               # [zeroval amount tag]                                    [refdata pubkeys quorum]                                              [({"N", ...} {"R", ...})]
get               # [zeroval amount tag quorum]                             [refdata pubkeys]                                                     [({"N", ...} {"R", ...})]
dup 4 bury        # [quorum zeroval amount tag quorum]                      [refdata pubkeys]                                                     [({"N", ...} {"R", ...})]
get               # [quorum zeroval amount tag quorum pubkeys]              [refdata]                                                             [({"N", ...} {"R", ...})]
dup 5 bury        # [quorum pubkeys zeroval amount tag quorum pubkeys]      []                                                                    [({"N", ...} {"R", ...})]
3 tuple           # [quorum pubkeys zeroval amount {tag, quorum, pubkeys}]  []                                                                    [({"N", ...} {"R", ...})]
encode            # [quorum pubkeys zeroval amount tag']                    []                                                                    [({"N", ...} {"R", ...})]
issue             # [quorum pubkeys issuedval]                              [refdata]                                                             [({"N", ...} {"R", ...}) {"A", <caller>, amount, assetID, zeroval.anchor}]
get log           # [quorum pubkeys issuedval]                              []                                                                    [({"N", ...} {"R", ...}) {"A", ...} {"L", <cseed>, refdata}]
anchor            # [quorum pubkeys issuedval anchor]                       []                                                                    [({"N", ...} {"R", ...}) {"A", ...} {"L", <cseed>, refdata}]
swap put          # [quorum pubkeys anchor]                                 [issuedval]                                                           [({"N", ...} {"R", ...}) {"A", ...} {"L", <cseed>, refdata}]
[%s]              # [quorum pubkeys anchor <multisigprog>]                  [issuedval]                                                           [({"N", ...} {"R", ...}) {"A", ...} {"L", <cseed>, refdata}]
yield             # [quorum pubkeys anchor]                                 [issuedval]                                                           [({"N", ...} {"R", ...}) {"A", ...} {"L", <cseed>, refdata}]
`,
	// expects either:
	//   argument stack: [... refdata pubkeys quorum assettag amount zerovalue 0]
	// or:
	//   argument stack: [... refdata pubkeys quorum assettag amount blockid nonce maxtime] with non-zero `maxtime`
	2: `
                  # Contract stack                                          Argument stack                                                        Log
                  # []                                                      [refdata pubkeys quorum tag amount (zeroval 0)|(blockid nonce maxms)]
get               # [(0|maxms)]                                             [refdata pubkeys quorum tag amount (zeroval|blockid nonce)]
dup not           # [(0|maxms) ((0|maxms)==0)]                              [refdata pubkeys quorum tag amount (zeroval|blockid nonce)]
jumpif:$havezero  # [maxms]                                                 [refdata pubkeys quorum tag amount blockid nonce]
    get drop      # [maxms]                                                 [refdata pubkeys quorum tag amount blockid]
    get           # [maxms blockid]                                         [refdata pubkeys quorum tag amount]
    swap          # [blockid maxms]                                         [refdata pubkeys quorum tag amount]
    nonce         # [zeroval]                                               [refdata pubkeys quorum tag amount]                                   [{"N", <caller>, <cseed>, bid, exp} {"R", minms, maxms}]
    jump:$cont
$havezero         # [0]                                                     [refdata pubkeys quorum tag amount zeroval]                           []
drop get          # [zeroval]                                               [refdata pubkeys quorum tag amount]                                   []
$cont
get               # [zeroval amount]                                        [refdata pubkeys quorum tag]                                          [({"N", ...} {"R", ...})]
get               # [zeroval amount tag]                                    [refdata pubkeys quorum]                                              [({"N", ...} {"R", ...})]
get               # [zeroval amount tag quorum]                             [refdata pubkeys]                                                     [({"N", ...} {"R", ...})]
dup 4 bury        # [quorum zeroval amount tag quorum]                      [refdata pubkeys]                                                     [({"N", ...} {"R", ...})]
get               # [quorum zeroval amount tag quorum pubkeys]              [refdata]                                                             [({"N", ...} {"R", ...})]
dup 5 bury        # [quorum pubkeys zeroval amount tag quorum pubkeys]      []                                                                    [({"N", ...} {"R", ...})]
3 tuple           # [quorum pubkeys zeroval amount {tag, quorum, pubkeys}]  []                                                                    [({"N", ...} {"R", ...})]
encode            # [quorum pubkeys zeroval amount tag']                    []                                                                    [({"N", ...} {"R", ...})]
issue             # [quorum pubkeys issuedval]                              [refdata]                                                             [({"N", ...} {"R", ...}) {"A", <caller>, amount, assetID, zeroval.anchor}]
get log           # [quorum pubkeys issuedval]                              []                                                                    [({"N", ...} {"R", ...}) {"A", ...} {"L", <cseed>, refdata}]
anchor            # [quorum pubkeys issuedval anchor]                       []                                                                    [({"N", ...} {"R", ...}) {"A", ...} {"L", <cseed>, refdata}]
swap put          # [quorum pubkeys anchor]                                 [issuedval]                                                           [({"N", ...} {"R", ...}) {"A", ...} {"L", <cseed>, refdata}]
[%s]              # [quorum pubkeys anchor <multisigprog>]                  [issuedval]                                                           [({"N", ...} {"R", ...}) {"A", ...} {"L", <cseed>, refdata}]
yield             # [quorum pubkeys anchor]                                 [issuedval]                                                           [({"N", ...} {"R", ...}) {"A", ...} {"L", <cseed>, refdata}]
`,
}

var (
	assetSrc = map[int]string{
		1: fmt.Sprintf(assetSrcFmt[1], multisigProgCheckSrc),
		2: fmt.Sprintf(assetSrcFmt[2], multisigProgCheckSrc),
	}
	assetProg = map[int][]byte{
		1: mustAssemble(assetSrc[1]),
		2: mustAssemble(assetSrc[2]),
	}

	// AssetContractSeed is the seed of the standard asset-issuance contract.
	AssetContractSeed = map[int][32]byte{
		1: txvm.ContractSeed(assetProg[1]),
		2: txvm.ContractSeed(assetProg[2]),
	}
)

// IssueWithAnchorContract produces the txvm bytecode of an
// issuance contract which invokes the standard asset-issuance
// contract to issue the requested number of units.
//
// The caller must ensure that a zero-value is on top of the
// txvm current-contract stack at the point where this code is
// called. If no such value is available, IssueWithoutAnchor may be
// used.
func IssueWithAnchorContract(version, quorum int, pubkeys []ed25519.PublicKey, tag []byte, amount int64, refdata []byte) []byte {
	return issue(true, version, quorum, pubkeys, tag, amount, refdata, nil, 0, nil)
}

// IssueWithoutAnchorContract produces the txvm bytecode of an
// issuance contract which invokes the standard asset-issuance
// contract to issue the requested number of units.
//
// It may be used when no value object is on top of the current
// contract stack. This requires a new nonce for use as an
// issuance anchor.
//
// When possible, callers should prefer IssueWithAnchor after
// arranging to place a zero-value on top of the stack.
func IssueWithoutAnchorContract(version, quorum int, pubkeys []ed25519.PublicKey, tag []byte, amount int64, refdata []byte, blockID []byte, expMS uint64, nonce []byte) []byte {
	return issue(false, version, quorum, pubkeys, tag, amount, refdata, blockID, expMS, nonce)
}

func issue(withAnchor bool, version, quorum int, pubkeys []ed25519.PublicKey, tag []byte, amount int64, refdata []byte, blockID []byte, expMS uint64, nonce []byte) []byte {
	var b txvmutil.Builder
	if withAnchor {
		b.Op(op.Get) // get
	}
	b.PushdataBytes(refdata).Op(op.Put)        // x'<refdata>' put
	b.Tuple(func(tup *txvmutil.TupleBuilder) { // {pk_0,...,pk_n} put
		for _, pk := range pubkeys {
			tup.PushdataBytes(pk)
		}
	})
	b.Op(op.Put)
	b.PushdataInt64(int64(quorum)).Op(op.Put) // <quorum> put
	b.PushdataBytes(tag).Op(op.Put)           // <tag> put
	b.PushdataInt64(amount).Op(op.Put)        // <amount> put
	switch {
	case withAnchor:
		b.Op(op.Put)                  // put
		b.PushdataInt64(0).Op(op.Put) // 0 put
	case version == 1:
		b.PushdataBytes(blockID).Op(op.Put) // <blockID> put
		b.PushdataUint64(expMS).Op(op.Put)  // <expMS> put
	case version == 2:
		b.PushdataBytes(blockID).Op(op.Put) // <blockID> put
		b.PushdataBytes(nonce).Op(op.Put)   // <nonce> put
		b.PushdataUint64(expMS).Op(op.Put)  // <expMS> put
	}
	b.PushdataBytes(assetProg[version]) // [<asset program>]
	b.Op(op.Contract).Op(op.Call)       // contract call
	return b.Build()
}

// AssetID computes the ID of an asset using the standard
// asset-issuance contract with the given parameters.
func AssetID(version, quorum int, pubkeys []ed25519.PublicKey, tag []byte) [32]byte {
	var pubkeysTuple txvm.Tuple
	for _, pubkey := range pubkeys {
		pubkeysTuple = append(pubkeysTuple, txvm.Bytes(pubkey))
	}
	tuple := txvm.Tuple{txvm.Bytes(tag), txvm.Int(quorum), pubkeysTuple}
	seed := AssetContractSeed[version]
	return txvm.AssetID(seed[:], txvm.Encode(tuple))
}
