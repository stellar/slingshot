package slidechain

import (
	"fmt"

	"github.com/chain/txvm/protocol/txvm"
	"github.com/chain/txvm/protocol/txvm/asm"
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

	importUniquenessFmt = `
							#  con stack                                                                arg stack                                log  notes
							#  ---------                                                                ---------                                ---  -----
							#  quorum, {recip}, zeroval, amount, asset                                                                                
	caller					#  quorum, {recip}, zeroval, amount, asset, callerSeed                                                                    
	%s						#  quorum, {recip}, zeroval, amount, asset, callerSeed, importIssuanceSeed                                                
	eq verify				#  quorum, {recip}, zeroval, amount, asset                                                                                
	put put put put put		#                                                                           asset, amount, zeroval, {recip}, quorum       
`

	importIssuanceSrc = `
														#  con stack                                arg stack                                log                                              notes
														#  ---------                                ---------                                ---                                              -----
														#                                           importUniquenessContract                                                                  
	get call											#                                           asset, amount, zeroval, {recip}, quorum                                                   
	get get get get get									#  quorum, {recip}, zeroval, amount, asset                                                                                            
	[txid <pubkey> get 0 checksig verify] contract put	#  quorum, {recip}, zeroval, amount, asset  sigchecker                                                                                
	issue put put put									#                                           sigchecker, issuedval, {recip}, quorum   {"A", vm.caller, v.amount, v.assetid, v.anchor}
`
)

var (
	prepegUniquenessSrc  = fmt.Sprintf(prepegUniquenessFmt, importUniquenessSrc)
	prepegUniquenessProg = asm.MustAssemble(prepegUniquenessSrc)
	prepegUniquenessSeed = txvm.ContractSeed(prepegUniquenessProg)
	importUniquenessSrc  = fmt.Sprintf(importUniquenessFmt, importIssuanceSeed)
	importUniquenessProg = asm.MustAssemble(importUniquenessSrc)
	importUniquenessSeed = txvm.ContractSeed(importUniquenessProg)
	importIssuanceProg   = asm.MustAssemble(importIssuanceSrc)
	importIssuanceSeed   = txvm.ContractSeed(importIssuanceProg)
	zeroSeed             [32]byte
)
