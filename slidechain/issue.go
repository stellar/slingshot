package slidechain

import (
	"fmt"

	"github.com/chain/txvm/protocol/txvm/asm"
)

// TODO(debnil): Use a more general-purpose sig checker, i.e. an exported `multisigProgCheckSrc`.
const issueProgFmt = `
	                                                 #  con stack                 arg stack                        log
	                                                 #  ---------                 ---------                        ---
	                                                 #                            assetcode amount zeroval
	get get get                                      #  zeroval amount assetcode
	[txid x"%x" get 0 checksig verify] contract put  #  zeroval amount assetcode  sigchecker
	issue put                                        #                            sigchecker issuedval             {"A", vm.caller, issuedval.amount, issuedval.assetid, issuedval.anchor}
`

var (
	issueProgSrc = fmt.Sprintf(issueProgFmt, custodianPub)
	issueProg    = asm.MustAssemble(issueProgSrc)
)