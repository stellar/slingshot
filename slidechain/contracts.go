package main

import (
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

const slidechainIssueProgSrc = `
                                                            #  con stack                    arg stack                        log
                                                            #  ---------                    ---------                        ---                                             
                                                            #                               asset code, amount, zeroval
        [txid <pubkey> get 0 checksig verify] contract put  #                               sigcheck contract
        get get get                                         #  zeroval, amount, asset code
        issue put                                           #                               sigcheck contract, issued value  {"A", vm.caller, v.amount, v.assetid, v.anchor}
`

var (
	// SlidechainIssueProg is the txvm bytecode of the issuance contract.
	SlidechainIssueProg = mustAssemble(slidechainIssueProgSrc)
	// SlidechainIssueSeed is the seed of the issuance contract.
	SlidechainIssueSeed = txvm.ContractSeed(SlidechainIssueProg)
)
