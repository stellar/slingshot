package slidechain

import (
	"bytes"
	"fmt"
	"math"

	"github.com/chain/txvm/errors"
	"github.com/chain/txvm/protocol/bc"
	"github.com/chain/txvm/protocol/txvm"
	"github.com/chain/txvm/protocol/txvm/asm"
)

const (
	// createTokenProg creates a uniqueness token and is run before submitting the peg-in transaction to the Stellar network.
	// It expects the following arg stack: asset, amount, zeroval, {recip}, quorum
	// It moves them onto the contract stack and then `output`s a contract that runs a consumeToken when next called.
	createTokenFmt = `
	                        #  con stack                                                        arg stack                                log
	                        #  ---------                                                        ---------                                ---
	                        #                                                                   asset, amount, zeroval, {recip}, quorum                              
	get get get get get     #  quorum, {recip}, zeroval, amount, asset                                                                                               
	[%s]                    #  quorum, {recip}, zeroval, amount, asset, [consumeTokenProg]                                                                       
	output                  #  quorum, {recip}, zeroval, amount, asset                                                                   {"O", vm.caller, outputid}  
`

	// consumeTokenProg consumes said token and thus ensures that the import for a specific peg-in can only happen once.
	// It expects the following con stack: quorum, {recip}, zeroval, amount, asset
	// It confirms that its caller's seed is that of the import-issuance program.
	// It then moves the con stack's arguments to the arg stack for the import-issuance transaction.
	consumeTokenFmt = `
	                     #  con stack                                                                arg stack                                log
	                     #  ---------                                                                ---------                                ---
	                     #  quorum, {recip}, zeroval, amount, asset                                                                                
	caller               #  quorum, {recip}, zeroval, amount, asset, callerSeed                                                                    
	x"%x"                #  quorum, {recip}, zeroval, amount, asset, callerSeed, importIssuanceSeed                                                
	eq verify            #  quorum, {recip}, zeroval, amount, asset                                                                                
	put put put put put  #                                                                           asset, amount, zeroval, {recip}, quorum             
`

	// importIssuanceProg calls consumeTokenProg and a signature checker to produce various arguments for the import transaction.
	// It expects the following arg stack: consumeTokenContract
	// It calls that contract and gets its resulting arguments onto the con stack.
	// It then creates a contract to check the custodian's signature and puts it on the arg stack.
	// It then issues the pegged-in value and puts it, with other needed arguments for the import transaction, on the arg stack.
	importIssuanceFmt = `
	                                                    #  con stack                                arg stack                                log
	                                                    #  ---------                                ---------                                ---
	                                                    #                                           consumeTokenContract
	get call                                            #                                           asset, amount, zeroval, {recip}, quorum
	get get get get get                                 #  quorum, {recip}, zeroval, amount, asset
	[txid x"%x" get 0 checksig verify] contract put     #  quorum, {recip}, zeroval, amount, asset  sigchecker
	issue put put put                                   #                                           sigchecker, issuedval, {recip}, quorum   {"A", vm.caller, issuedval.amount, issuedval.assetid, issuedval.anchor}
`
)

var (
	createTokenSrc     = fmt.Sprintf(createTokenFmt, consumeTokenSrc)
	createTokenProg    = asm.MustAssemble(createTokenSrc)
	createTokenSeed    = txvm.ContractSeed(createTokenProg)
	consumeTokenSrc    = fmt.Sprintf(consumeTokenFmt, importIssuanceSeed)
	consumeTokenProg   = asm.MustAssemble(consumeTokenSrc)
	importIssuanceSrc  = fmt.Sprintf(importIssuanceFmt, custodianPub)
	importIssuanceProg = asm.MustAssemble(importIssuanceSrc)
	importIssuanceSeed = txvm.ContractSeed(importIssuanceProg)
	zeroSeed           [32]byte
)

// UniqueNonceHash returns a nonce hash used to prevent replay attacks.
func UniqueNonceHash(bcid []byte, expMS int64) [32]byte {
	nonce := txvm.NonceTuple(zeroSeed[:], zeroSeed[:], bcid, expMS)
	return txvm.NonceHash(nonce)
}

// BuildPrepegTx builds the pre-peg-in TxVM transaction to create a uniqueness token.
func BuildPrepegTx(bcid, assetXDR, recip []byte, amount, expMS int64) (*bc.Tx, error) {
	buf := new(bytes.Buffer)
	// Set up pre-peg tx arg stack: asset, amount, zeroval, {recip}, quorum
	fmt.Fprintf(buf, "x'%x' put\n", assetXDR)
	fmt.Fprintf(buf, "%d put\n", amount)
	fmt.Fprintf(buf, "x'%x' %d nonce 0 split put\n", bcid, expMS)
	fmt.Fprintf(buf, "{x'%x'} put\n", recip)
	fmt.Fprintf(buf, "1 put\n") // The signer quorum size of 1 is fixed.
	// Call create token contract.
	fmt.Fprintf(buf, "x'%x' contract call\n", createTokenProg)
	fmt.Fprintf(buf, "finalize\n")
	tx, err := asm.Assemble(buf.String())
	if err != nil {
		return nil, errors.Wrap(err, "assembling pre-peg tx")
	}
	_, err = txvm.Validate(tx, 3, math.MaxInt64)
	if err != nil {
		return nil, errors.Wrap(err, "validating pre-peg tx")
	}
	var runlimit int64
	prepegTx, err := bc.NewTx(tx, 3, math.MaxInt64, txvm.GetRunlimit(&runlimit))
	if err != nil {
		return nil, errors.Wrap(err, "populating new pre-peg tx")
	}
	prepegTx.Runlimit = math.MaxInt64 - runlimit
	return prepegTx, nil
}
