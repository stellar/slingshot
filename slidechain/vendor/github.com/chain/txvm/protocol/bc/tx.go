package bc

import (
	"bytes"
	"io"

	"github.com/chain/txvm/errors"
	"github.com/chain/txvm/protocol/txvm"
	"github.com/chain/txvm/protocol/txvm/op"
)

// Tx contains the input to an instance of the txvm virtual machine,
// plus parsed copies of its various side effects.
type Tx struct {
	RawTx

	Finalized bool
	ID        Hash
	Log       []txvm.Tuple

	// Used in protocol validation and state updates
	Contracts  []Contract
	Timeranges []Timerange
	Nonces     []Nonce
	Anchor     []byte

	Inputs      []Input
	Issuances   []Issuance
	Outputs     []Output
	Retirements []Retirement
}

// CommitmentsTx wraps a Tx with its nonce and witness commitments.
type CommitmentsTx struct {
	Tx                *Tx
	NonceCommitments  map[Hash][]byte
	WitnessCommitment []byte
}

// The type of a Contract (below).
const (
	InputType = iota
	OutputType
)

// Contract contains the ID of an input or an output from the txvm
// log. The Type field tells which kind of contract it is (InputType
// or OutputType).
type Contract struct {
	Type int
	ID   Hash
}

// Timerange is a parsed timerange-typed txvm log entry.
type Timerange struct {
	MinMS, MaxMS int64
}

// Nonce is a parsed nonce-typed txvm log entry.
type Nonce struct {
	ID      Hash
	BlockID Hash
	ExpMS   uint64
}

// Output is a parsed output-typed txvm log entry, plus information
// derived from stack introspection during execution.
type Output struct {
	ID      Hash
	Seed    Hash
	Stack   []txvm.Data
	Program []byte
	LogPos  int
}

// Input is a parsed input-typed txvm log entry, plus information
// derived from stack introspection during execution.
type Input struct {
	ID      Hash
	Seed    Hash
	Stack   []txvm.Data
	Program []byte
	LogPos  int
}

// Issuance is a parsed issuance-typed txvm log entry.
type Issuance struct {
	Amount  int64
	AssetID Hash
	Anchor  []byte
	LogPos  int
}

// Retirement is a parsed retirement-typed txvm log entry.
type Retirement struct {
	Amount  int64
	AssetID Hash
	Anchor  []byte
	LogPos  int
}

// NewCommitmentsTx takes a Tx object and returns a CommitmentsTx
// wrapped with the transaction's nonce and witness commitments.
func NewCommitmentsTx(tx *Tx) *CommitmentsTx {
	commitmentsTx := &CommitmentsTx{Tx: tx}

	var buf bytes.Buffer
	tx.WriteWitnessCommitmentTo(&buf)
	commitmentsTx.WitnessCommitment = buf.Bytes()

	commitmentsTx.NonceCommitments = make(map[Hash][]byte)
	for _, n := range tx.Nonces {
		nc := NonceCommitment(n.ID, n.ExpMS)
		commitmentsTx.NonceCommitments[n.ID] = nc
	}
	return commitmentsTx
}

// NewTx runs the given txvm program through an instance of the txvm
// virtual machine, populating a new Tx object with its side effects.
func NewTx(prog []byte, version, runlimit int64, option ...txvm.Option) (*Tx, error) {
	tx := &Tx{
		RawTx: RawTx{
			Program:  prog,
			Version:  version,
			Runlimit: runlimit,
		},
	}
	option = append(option, txvm.OnFinalize(tx.entryHook), txvm.BeforeStep(tx.stackHook))
	vm, err := txvm.Validate(prog, version, runlimit, option...)
	if vm != nil {
		tx.Finalized = vm.Finalized
		if vm.Finalized {
			tx.ID = NewHash(vm.TxID)
		}
	}
	return tx, errors.Wrap(err)
}

func (tx *Tx) stackHook(vm *txvm.VM) {
	switch vm.OpCode() {
	case op.Output:
		seed := vm.Seed()
		var stack []txvm.Data
		for i := 0; i < vm.StackLen(); i++ {
			stack = append(stack, vm.StackItem(i))
		}
		progTup, stack := stack[len(stack)-1], stack[:len(stack)-1]
		prog := progTup.(txvm.Tuple)[1].(txvm.Bytes)

		tx.Outputs = append(tx.Outputs, Output{
			Seed:    HashFromBytes(seed),
			Program: prog,
			Stack:   stack,
		})
	case op.Input:
		inputTup := vm.StackItem(vm.StackLen() - 1).(txvm.Tuple)[1].(txvm.Tuple)
		seed := inputTup[1].(txvm.Bytes)
		prog := inputTup[2].(txvm.Bytes)
		var stack []txvm.Data
		for i := 3; i < len(inputTup); i++ {
			stack = append(stack, inputTup[i])
		}

		tx.Inputs = append(tx.Inputs, Input{
			Seed:    HashFromBytes(seed),
			Program: prog,
			Stack:   stack,
		})
	}
}

func (tx *Tx) entryHook(vm *txvm.VM) {
	tx.Version = vm.Version()
	var inputIdx, outputIdx int
	for i, tup := range vm.Log {
		tx.Log = append(tx.Log, tup)
		tupType := tup[0].(txvm.Bytes) // log tuples always have a typecode
		switch tupType[0] {
		case txvm.FinalizeCode:
			tx.Anchor = []byte(tup[3].(txvm.Bytes))

		case txvm.InputCode:
			id := HashFromBytes(tup[2].(txvm.Bytes))
			tx.Inputs[inputIdx].ID = id
			tx.Inputs[inputIdx].LogPos = i
			inputIdx++
			tx.Contracts = append(tx.Contracts, Contract{InputType, id})

		case txvm.OutputCode:
			id := HashFromBytes(tup[2].(txvm.Bytes))
			tx.Outputs[outputIdx].ID = id
			tx.Outputs[outputIdx].LogPos = i
			outputIdx++
			tx.Contracts = append(tx.Contracts, Contract{OutputType, id})

		case txvm.IssueCode:
			iss := Issuance{
				Amount:  int64(tup[2].(txvm.Int)),
				AssetID: HashFromBytes(tup[3].(txvm.Bytes)),
				Anchor:  tup[4].(txvm.Bytes),
				LogPos:  i,
			}
			tx.Issuances = append(tx.Issuances, iss)

		case txvm.RetireCode:
			ret := Retirement{
				Amount:  int64(tup[2].(txvm.Int)),
				AssetID: HashFromBytes([]byte(tup[3].(txvm.Bytes))),
				Anchor:  tup[4].(txvm.Bytes),
				LogPos:  i,
			}
			tx.Retirements = append(tx.Retirements, ret)

		case txvm.TimerangeCode:
			min := tup[2].(txvm.Int)
			max := tup[3].(txvm.Int)
			tx.Timeranges = append(tx.Timeranges, Timerange{MinMS: int64(min), MaxMS: int64(max)})

		case txvm.NonceCode:
			blockID := HashFromBytes(tup[3].(txvm.Bytes))

			exp := tup[4].(txvm.Int)

			id := txvm.VMHash("Nonce", txvm.Encode(tup))

			tx.Nonces = append(tx.Nonces, Nonce{
				ID:      NewHash(id),
				BlockID: blockID,
				ExpMS:   uint64(exp), // TODO: check signed-to-unsigned conversion
			})
		}
	}
}

// WriteWitnessCommitmentTo writes the "Transaction Witness Commitment" to w,
// consisting of the version, runlimit, and program in a tuple,
// encoded according to standard txvm convention, hashed together with
// the txid.
//
// The only errors returned are those from w.
func (tx *Tx) WriteWitnessCommitmentTo(w io.Writer) (int, error) {
	// See $I10R/docs/future/protocol/specifications/blockchain.md#transaction-witness-commitment
	// for the definition of the transaction witness commitment.
	n, err := tx.ID.WriteTo(w)
	if err != nil {
		return int(n), err
	}
	n2, err := tx.writeWitnessHashTo(w)
	if err != nil {
		return int(n) + n2, err
	}
	return int(n) + n2, nil
}

// The only errors returned are those from w.
func (tx *Tx) writeWitnessHashTo(w io.Writer) (int, error) {
	// See $I10R/docs/future/protocol/specifications/txvm.md#transaction-witness
	// for the definition of the transaction witness and
	// $I10R/docs/future/protocol/specifications/blockchain.md#transaction-witness-commitment
	// for the definition of the transaction witness commitment.
	h := txvm.VMHash("WitnessHash", txvm.Encode(txvm.Tuple{
		txvm.Int(tx.Version),
		txvm.Int(tx.Runlimit),
		txvm.Bytes(tx.Program),
	}))
	return w.Write(h[:])
}
