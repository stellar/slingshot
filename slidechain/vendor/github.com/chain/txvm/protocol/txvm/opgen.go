// Auto-generated from op/op.go by gen.go

package txvm

import "github.com/chain/txvm/protocol/txvm/op"

var opFuncs [256]func(*VM)

func init() {
	opFuncs[op.Int] = opInt
	opFuncs[op.Add] = opAdd
	opFuncs[op.Neg] = opNeg
	opFuncs[op.Mul] = opMul
	opFuncs[op.Div] = opDiv
	opFuncs[op.Mod] = opMod
	opFuncs[op.GT] = opGT
	opFuncs[op.Not] = opNot
	opFuncs[op.And] = opAnd
	opFuncs[op.Or] = opOr
	opFuncs[op.Roll] = opRoll
	opFuncs[op.Bury] = opBury
	opFuncs[op.Reverse] = opReverse
	opFuncs[op.Get] = opGet
	opFuncs[op.Put] = opPut
	opFuncs[op.Depth] = opDepth
	opFuncs[op.Nonce] = opNonce
	opFuncs[op.Merge] = opMerge
	opFuncs[op.Split] = opSplit
	opFuncs[op.Issue] = opIssue
	opFuncs[op.Retire] = opRetire
	opFuncs[op.Amount] = opAmount
	opFuncs[op.AssetID] = opAssetID
	opFuncs[op.Anchor] = opAnchor
	opFuncs[op.VMHash] = opVMHash
	opFuncs[op.SHA256] = opSHA256
	opFuncs[op.SHA3] = opSHA3
	opFuncs[op.CheckSig] = opCheckSig
	opFuncs[op.Log] = opLog
	opFuncs[op.PeekLog] = opPeekLog
	opFuncs[op.TxID] = opTxID
	opFuncs[op.Finalize] = opFinalize
	opFuncs[op.Verify] = opVerify
	opFuncs[op.JumpIf] = opJumpIf
	opFuncs[op.Exec] = opExec
	opFuncs[op.Call] = opCall
	opFuncs[op.Yield] = opYield
	opFuncs[op.Wrap] = opWrap
	opFuncs[op.Input] = opInput
	opFuncs[op.Output] = opOutput
	opFuncs[op.Contract] = opContract
	opFuncs[op.Seed] = opSeed
	opFuncs[op.Self] = opSelf
	opFuncs[op.Caller] = opCaller
	opFuncs[op.ContractProgram] = opContractProgram
	opFuncs[op.TimeRange] = opTimeRange
	opFuncs[op.Prv] = opPrv
	opFuncs[op.Ext] = opExt
	opFuncs[op.Eq] = opEq
	opFuncs[op.Dup] = opDup
	opFuncs[op.Drop] = opDrop
	opFuncs[op.Peek] = opPeek
	opFuncs[op.Tuple] = opTuple
	opFuncs[op.Untuple] = opUntuple
	opFuncs[op.Len] = opLen
	opFuncs[op.Field] = opField
	opFuncs[op.Encode] = opEncode
	opFuncs[op.Cat] = opCat
	opFuncs[op.Slice] = opSlice
	opFuncs[op.BitNot] = opBitNot
	opFuncs[op.BitAnd] = opBitAnd
	opFuncs[op.BitOr] = opBitOr
	opFuncs[op.BitXor] = opBitXor
}
