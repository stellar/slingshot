package slidechain

import (
	"fmt"

	"github.com/chain/txvm/protocol/txvm"
)

const (
	prepegUniquenessFmt = `
							#  con stack                                                        arg stack                                log                         notes
							#  ---------                                                        ---------                                ---                         -----
							#                                                                   asset, amount, zeroval, {recip}, quorum                              
	get get get get get     #  quorum, {recip}, zeroval, amount, asset                                                                                               
	[%s]                    #  quorum, {recip}, zeroval, amount, asset, [importUniquenessProg]                                                                       
	output                  #  quorum, {recip}, zeroval, amount, asset                                                                   {"O", vm.caller, outputid}  
`

	importUniquenessSrc = `
						 #  con stack                                                                arg stack                                log  notes
						 #  ---------                                                                ---------                                ---  -----
		 				 #  quorum, {recip}, zeroval, amount, asset                                                                                
	caller               #  quorum, {recip}, zeroval, amount, asset, callerSeed                                                                    
	importIssuanceSeed   #  quorum, {recip}, zeroval, amount, asset, callerSeed, importIssuanceSeed                                                
	eq verify            #  quorum, {recip}, zeroval, amount, asset                                                                                
	put put put put put  #                                                                           asset, amount, zeroval, {recip}, quorum       
`

	importIssuanceSrc = `
														#  con stack                                arg stack                                log                                              notes
														#  ---------                                ---------                                ---                                              -----
														#                                           importUniquenessContract                                                                  
	get call                                            #                                           asset, amount, zeroval, {recip}, quorum                                                   
	get get get get get                                 #  quorum, {recip}, zeroval, amount, asset                                                                                            
	[txid <pubkey> get 0 checksig verify] contract put  #  quorum, {recip}, zeroval, amount, asset  sigchecker                                                                                
	issue put put put                                   #                                           sigchecker, issuedval, {recip}, quorum   {"A", vm.caller, v.amount, v.assetid, v.anchor}
`
)

var (
	importIssuanceProg   = asm.MustAssemble(importIssuanceSrc)
	importIssuanceSeed   = txvm.ContractSeed(importIssuanceProg)
	prepegUniquenessSrc  = fmt.Sprintf(prepegUniquenessFmt, importUniquenessSrc)
	prepegUniquenessProg = asm.MustAssemble(prepegUniquenessSrc)
	prepegUniquenessSeed = txvm.ContractSeed(prepegUniquenessProg)
	importUniquenessProg = asm.MustAssemble(importUniquenessSrc)
	importUniquenessSeed = txvm.ContractSeed(importUniquenessProg)
	zeroSeed             [32]byte
)

// UniqueNonceHash returns a nonce hash that can be used before pegging
// and after importing to prevent replay attacks.
func UniqueNonceHash(bcid []byte, expMS int64) [32]byte {
	nonce := txvm.NonceTuple(zeroSeed[:], zeroSeed[:], bcid, expMS)
	return txvm.NonceHash(nonce)
}
