package standard

import "github.com/chain/txvm/protocol/txvm"

// expects [... refdata value] on the arg stack
const retireSrc = `
	            # Contract stack   Argument stack   Log
	            # []               [refdata value]  []
	get retire  # []               [refdata]        [{"X", <cid>, amount, assetID, anchor}]
	get log     # []               []               [{"X", <cid>, amount, assetID, anchor} {"L", <cid>, refdata}]
`

var (
	// RetireContract is the assembled txvm bytecode of the
	// standard retirement contract.
	RetireContract = mustAssemble(retireSrc)

	// RetireContractSeed is the seed of the standard retirement
	// contract.
	RetireContractSeed = txvm.ContractSeed(RetireContract)
)
