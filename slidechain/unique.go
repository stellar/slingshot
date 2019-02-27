package slidechain

import (
	"fmt"

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

func uniqueNonceHash(bcid []byte, expMS int64) [32]byte {
	nonce := txvm.NonceTuple(zeroSeed[:], zeroSeed[:], bcid, expMS)
	return txvm.NonceHash(nonce)
}
