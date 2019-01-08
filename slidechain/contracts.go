package main

import (
	"fmt"

	"github.com/chain/txvm/protocol/txvm"
	"github.com/chain/txvm/protocol/txvm/asm"
)

func mustAssemble(src string) []byte {
	res, err := asm.Assemble(src)
	if err != nil {
		panic(err)
	}
	return res
}

// TODO(debnil): Use a more general-purpose sig checker, i.e. an exported `multisigProgCheckSrc`.
const issueProgFmt = `
                                                    #  con stack                    arg stack                        log                                              notes
                                                    #  ---------                    ---------                        ---                                              -----
                                                    #                               asset code, amount, zeroval                                                       
[txid <pubkey> get 0 checksig verify] contract put  #                               sigcheck contract                                                                 
get get get                                         #  zeroval, amount, asset code                                                                                    
issue put                                           #                               sigcheck contract, issued value  {"A", vm.caller, v.amount, v.assetid, v.anchor}  
`

var (
	issueProgSrc = fmt.Sprintf(issueProgFmt, *custPubkey)
	issueProg    = mustAssemble(issueProgSrc)
	issueSeed    = txvm.ContractSeed(issueProg)
)
