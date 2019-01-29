package standard

import (
	"fmt"

	"github.com/chain/txvm/protocol/txvm"
	"github.com/chain/txvm/protocol/txvm/asm"
)

// payToMultisigProg1 expects:
//   argument stack: [... refdata value {p1,...,p_n} quorum]
// It moves them onto the contract stack and then `output`s a contract
// that runs a PayToMultisigProgUnlock when next called.
const payToMultisigProgSrcFmt1 = `
	               # Contract stack                         Argument stack              Log
	               # []                                     [refdata v {p1,...,p_n} q]  []
	get get        # [q {p1,...,p_n}]                       [refdata v]                 []
	get            # [q {p1,...,p_n} v]                     [refdata]                   []
	get            # [q {p1,...,p_n} v refdata]             []                          []
	log            # [q {p1,...,p_n} v]                     []                          [{"L", <cid>, refdata}]
	[%s]           # [q {p1,...,p_n} v <msunlock>]          []                          [{"L", <cid>, refdata}]
	output         # [q {p1,...,p_n} v]                     []                          [{"L", <cid>, refdata} {"O", <caller>, <outputid>}]
`

var (
	// payToMultisigProgSrc1 is the source-code of the
	// first version of the standard pay-to-multisig program.
	payToMultisigProgSrc1 = fmt.Sprintf(payToMultisigProgSrcFmt1, payToMultisigProgUnlockSrc)

	// PayToMultisigProg1 is the txvm bytecode of the first
	// version of the standard pay-to-multisig contract.
	PayToMultisigProg1 = asm.MustAssemble(payToMultisigProgSrc1)

	// PayToMultisigSeed1 is the seed of the standard pay-to-multisig-program contract.
	PayToMultisigSeed1 = txvm.ContractSeed(PayToMultisigProg1)
)

// payToMultisigProg2 expects:
//   argument stack: [... refdata tags value {p1,...,p_n} quorum]
// It moves them onto the contract stack and then `output`s a contract
// that runs a PayToMultisigProgUnlock when next called.
const payToMultisigProgSrcFmt2 = `
	               # Contract stack                         Argument stack                   Log
	               # []                                     [refdata tags v {p1,...,p_n} q]  []
	get get        # [q {p1,...,p_n}]                       [refdata tags v]                 []
	get            # [q {p1,...,p_n} v]                     [refdata tags]                   []
	get log        # [q {p1,...,p_n} v]                     [refdata]                        [{"L", <cid>, tags}]
	get log        # [q {p1,...,p_n} v]                     []                               [{"L", <cid>, tags} {"L", <cid>, refdata}]
	[%s]           # [q {p1,...,p_n} v <msunlock>]          []                               [{"L", <cid>, tags} {"L", <cid>, refdata}]
	output         # [q {p1,...,p_n} v]                     []                               [{"L", <cid>, tags} {"L", <cid>, refdata} {"O", <caller>, <outputid>}]
`

var (
	// payToMultisigProgSrc2 is the source-code version of the standard pay-to-multisig-program.
	payToMultisigProgSrc2 = fmt.Sprintf(payToMultisigProgSrcFmt2, payToMultisigProgUnlockSrc)

	// PayToMultisigProg2 is the txvm bytecode of the standard
	// pay-to-multisig contract.
	PayToMultisigProg2 = asm.MustAssemble(payToMultisigProgSrc2)

	// PayToMultisigSeed2 is the seed of the standard pay-to-multisig-program contract.
	PayToMultisigSeed2 = txvm.ContractSeed(PayToMultisigProg2)
)
