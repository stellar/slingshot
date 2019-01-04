package txbuilder

import (
	"context"
	"fmt"
	"math"
	"sort"
	"time"

	"github.com/chain/txvm/crypto/ed25519"
	i10rjson "github.com/chain/txvm/encoding/json"
	"github.com/chain/txvm/errors"
	"github.com/chain/txvm/math/checked"
	"github.com/chain/txvm/protocol/bc"
	"github.com/chain/txvm/protocol/txbuilder/standard"
	"github.com/chain/txvm/protocol/txvm"
	"github.com/chain/txvm/protocol/txvm/op"
	"github.com/chain/txvm/protocol/txvm/txvmutil"
)

const latestOutputVersion = 2

func NewTemplate(maxTime time.Time, tags []byte) *Template {
	tpl := new(Template)
	if tags != nil {
		tpl.SetTransactionTags(tags)
	}
	maxTimeMS := bc.Millis(maxTime)
	if tpl.MaxTimeMS == 0 || tpl.MaxTimeMS > maxTimeMS {
		tpl.MaxTimeMS = maxTimeMS
	}
	return tpl
}

// Template contains the ingredients for a transaction: Issuances,
// Inputs, Outputs, and Retirements, plus transaction tags and min- and
// maxtimes. A Template can be created directly or with a call to
// Build. Elements can be added to a template directly or with calls
// to AddIssuance, AddInput, AddOutput, AddRetirement,
// SetReferenceData, RestrictMinTime, and RestrictMaxTime. Once these
// elements have been added, any needed signatures are added with
// Sign. The completed transaction can be extracted with Tx.
type Template struct {
	Issuances   []*Issuance       `json:"issuances"`
	Inputs      []*Input          `json:"inputs"`
	Outputs     []*Output         `json:"outputs"`
	Retirements []*Retirement     `json:"retirements"`
	TxTags      i10rjson.HexBytes `json:"transaction_tags"`
	MinTimeMS   uint64            `json:"min_time_ms"`
	MaxTimeMS   uint64            `json:"max_time_ms"`

	materialization *materialization

	rollbacks []func()
	callbacks []func() error

	legacyOutputs bool
	index         uint64
}

// SetOutputV1 causes Template.Tx to produce old-style outputs, which
// don't log token tags. The default is for version 2 outputs, which
// do.
func (t *Template) SetOutputV1() {
	t.legacyOutputs = true
}

// Issuance contains information needed to add an issuance to a
// transaction. It is added to a template with AddIssuance.
type Issuance struct {
	Version      int                 `json:"contract_version"`
	BlockchainID i10rjson.HexBytes   `json:"blockchain_id"`
	Quorum       int                 `json:"quorum"`
	KeyHashes    []i10rjson.HexBytes `json:"key_hashes"`
	Path         []i10rjson.HexBytes `json:"derivation_path"`
	Pubkeys      []ed25519.PublicKey `json:"pubkeys"`
	Amount       int64               `json:"amount"`
	AssetTag     i10rjson.HexBytes   `json:"asset_tag"` // TODO(bobg): name this something that won't be confused with the mutable asset tags we already have
	Sigs         []i10rjson.HexBytes `json:"signatures"`
	Refdata      i10rjson.HexBytes   `json:"reference_data"`
	Index        uint64              `json:"index"`
	Nonce        i10rjson.HexBytes   `json:"nonce"`
	anchor       []byte
}

func (iss *Issuance) assetID() [32]byte {
	return standard.AssetID(iss.Version, iss.Quorum, iss.Pubkeys, iss.AssetTag)
}

// Input contains information needed to add an input to a
// transaction. It is added to a template with AddInput.
type Input struct {
	Quorum        int                 `json:"quorum"`
	KeyHashes     []i10rjson.HexBytes `json:"key_hashes"`
	Path          []i10rjson.HexBytes `json:"derivation_path"`
	Pubkeys       []ed25519.PublicKey `json:"pubkeys"`
	Amount        int64               `json:"amount"`
	AssetID       bc.Hash             `json:"asset_id"`
	Anchor        i10rjson.HexBytes   `json:"anchor"`
	Sigs          []i10rjson.HexBytes `json:"signatures"`
	InputRefdata  i10rjson.HexBytes   `json:"reference_data"`
	Index         uint64              `json:"index"`
	OutputIndex   *int                `json:"output_index,omitempty"` // for "spend from output" - will be blank for "normal" inputs
	OutputVersion int                 `json:"output_version"`
}

// Output contains information needed to add an output to a
// transaction. It is added to a template with AddOutput.
type Output struct {
	Quorum    int                 `json:"quorum"`
	Pubkeys   []ed25519.PublicKey `json:"pubkeys"`
	Amount    int64               `json:"amount"`
	AssetID   bc.Hash             `json:"asset_id"`
	Refdata   i10rjson.HexBytes   `json:"reference_data"`
	TokenTags i10rjson.HexBytes   `json:"token_tags"`
	Index     uint64              `json:"index"`
	anchor    []byte
}

// Retirement contains information needed to add a retirement to a
// transaction. It is added to a template with AddRetirement.
type Retirement struct {
	Amount  int64             `json:"amount"`
	AssetID bc.Hash           `json:"asset_id"`
	Refdata i10rjson.HexBytes `json:"reference_data"`
	Index   uint64            `json:"index"`
}

type entry interface {
	index() uint64
}

func (iss *Issuance) index() uint64   { return iss.Index }
func (inp *Input) index() uint64      { return inp.Index }
func (out *Output) index() uint64     { return out.Index }
func (ret *Retirement) index() uint64 { return ret.Index }

// orderedEntries satisfies sort.Interface
type orderedEntries []entry

func (oe orderedEntries) Len() int           { return len(oe) }
func (oe orderedEntries) Less(i, j int) bool { return oe[i].index() < oe[j].index() }
func (oe orderedEntries) Swap(i, j int)      { oe[i], oe[j] = oe[j], oe[i] }

// RestrictMinTime sets the template's min time to the given value if
// it's later than the mintime already present.
func (tpl *Template) RestrictMinTime(t time.Time) {
	ms := bc.Millis(t)
	if ms > tpl.MinTimeMS {
		tpl.MinTimeMS = ms
	}
}

// RestrictMaxTime sets the template's max time to the given value if
// it's earlier than the maxtime already present.
func (tpl *Template) RestrictMaxTime(t time.Time) {
	ms := bc.Millis(t)
	if ms < tpl.MaxTimeMS {
		tpl.MaxTimeMS = ms
	}
}

// OnRollback registers a function that can be
// used to attempt to undo any side effects of building
// actions. For example, it might cancel any reservations
// that were made on UTXOs in an input action.
// Rollback is a "best-effort" operation and not guaranteed
// to succeed. Each action's side effects, if any, must be
// designed with this in mind.
func (tpl *Template) OnRollback(rollbackFn func()) {
	tpl.rollbacks = append(tpl.rollbacks, rollbackFn)
}

// OnBuild registers a function that will be run after a successful
// call to Build.
func (tpl *Template) OnBuild(buildFn func() error) {
	tpl.callbacks = append(tpl.callbacks, buildFn)
}

// SetTransactionTags sets the template's transaction-level tags
// to the given value.
func (tpl *Template) SetTransactionTags(tags []byte) {
	tpl.TxTags = tags
}

func (tpl *Template) Rollback() {
	for _, f := range tpl.rollbacks {
		f()
	}
}

// Commit runs any pending template callbacks.
func (tpl *Template) Commit() error {
	for _, f := range tpl.callbacks {
		err := f()
		if err != nil {
			tpl.Rollback()
			return errors.Wrap(err, "running callbacks")
		}
	}
	tpl.rollbacks = nil
	tpl.callbacks = nil
	return nil
}

func asHexBytes(b [][]byte) []i10rjson.HexBytes {
	var res []i10rjson.HexBytes
	for _, item := range b {
		res = append(res, item)
	}
	return res
}

func asBytes(b []i10rjson.HexBytes) [][]byte {
	var res [][]byte
	for _, item := range b {
		res = append(res, item)
	}
	return res
}

// AddIssuance adds an Issuance to the template.
func (tpl *Template) AddIssuance(version int, blockchainID []byte, assetTag []byte, quorum int, keyHashes [][]byte, path [][]byte, pubkeys []ed25519.PublicKey, amount int64, refData, nonce []byte) *Issuance {
	iss := &Issuance{
		Version:      version,
		BlockchainID: blockchainID,
		Quorum:       quorum,
		KeyHashes:    asHexBytes(keyHashes),
		Path:         asHexBytes(path),
		Pubkeys:      pubkeys,
		Amount:       amount,
		AssetTag:     assetTag,
		Refdata:      i10rjson.HexBytes(refData),
		Nonce:        nonce,
		Index:        tpl.index,
	}
	tpl.index++
	tpl.Issuances = append(tpl.Issuances, iss)
	return iss
}

// AddInput adds an Input to the template.
func (tpl *Template) AddInput(quorum int, keyHashes [][]byte, path [][]byte, pubkeys []ed25519.PublicKey, amount int64, assetID bc.Hash, anchor, inputRefdata []byte, version int) *Input {
	if version == 0 {
		version = latestOutputVersion
	}
	inp := &Input{
		Quorum:        quorum,
		KeyHashes:     asHexBytes(keyHashes),
		Path:          asHexBytes(path),
		Pubkeys:       pubkeys,
		Amount:        amount,
		AssetID:       assetID,
		Anchor:        anchor,
		InputRefdata:  i10rjson.HexBytes(inputRefdata),
		Index:         tpl.index,
		OutputVersion: version,
	}
	tpl.index++
	tpl.Inputs = append(tpl.Inputs, inp)
	return inp
}

// AddOutput adds an Output to the template.
func (tpl *Template) AddOutput(quorum int, pubkeys []ed25519.PublicKey, amount int64, assetID bc.Hash, refData, tags []byte) *Output {
	out := &Output{
		Quorum:    quorum,
		Pubkeys:   pubkeys,
		Amount:    amount,
		AssetID:   assetID,
		Refdata:   i10rjson.HexBytes(refData),
		TokenTags: i10rjson.HexBytes(tags),
		Index:     tpl.index,
	}
	tpl.index++
	tpl.Outputs = append(tpl.Outputs, out)
	return out
}

// AddRetirement adds a Retirement to the template.
func (tpl *Template) AddRetirement(amount int64, assetID bc.Hash, refData []byte) *Retirement {
	ret := &Retirement{
		Amount:  amount,
		AssetID: assetID,
		Refdata: i10rjson.HexBytes(refData),
		Index:   tpl.index,
	}
	tpl.index++
	tpl.Retirements = append(tpl.Retirements, ret)
	return ret
}

// SignFunc is the type of a callback that can generate a signature
// for a given message and a given keyID and derivation path. If the
// function does not recognize the keyID, it should return (nil, nil),
// not an error.
type SignFunc func(ctx context.Context, msg []byte, keyID []byte, path [][]byte) ([]byte, error)

// Sign invokes a callback function to add signatures to Inputs and
// Issuances in the template. The callback adds as many as it can, up
// to the number needed for each Input or Issuance. Multiple calls to
// Sign might be necessary to marshal enough signatures to authorize a
// transaction, each with a callback invoking a different signing HSM
// responsible for a different subset of keys.
func (tpl *Template) Sign(ctx context.Context, signFn SignFunc) error {
	txID, _, err := tpl.Materialize()
	if err != nil {
		return errors.Wrap(err, "cannot get txid for computing signature message")
	}

	txidProg := standard.VerifyTxID(txID.Byte32())
	callSign := func(quorum int, keyIDs [][]byte, inPath []i10rjson.HexBytes, anchor []byte, sigs *[]i10rjson.HexBytes) error {
		if *sigs == nil {
			*sigs = make([]i10rjson.HexBytes, len(keyIDs))
		}

		// Have we already reached a quorum?
		for _, s := range *sigs {
			if len(s) > 0 {
				quorum--
				if quorum <= 0 {
					return nil
				}
			}
		}

		path := asBytes(inPath)
		msg := append(txidProg, anchor...)

		for i, keyID := range keyIDs {
			if len((*sigs)[i]) > 0 {
				// We already have a signature for this key, skip it
				continue
			}
			sig, err := signFn(ctx, msg, keyID, path)
			if err != nil {
				return err
			}
			if len(sig) > 0 {
				(*sigs)[i] = sig
				quorum--
				if quorum <= 0 {
					return nil
				}
			}
		}

		return nil
	}

	for _, iss := range tpl.Issuances {
		err := callSign(iss.Quorum, asBytes(iss.KeyHashes), iss.Path, iss.anchor, &iss.Sigs)
		if err != nil {
			return err
		}
	}
	for _, inp := range tpl.Inputs {
		err := callSign(inp.Quorum, asBytes(inp.KeyHashes), inp.Path, inp.Anchor, &inp.Sigs)
		if err != nil {
			return err
		}
	}
	return nil
}

type stackItem struct {
	// values
	amount  int64 // valid only if anchor is not empty
	assetID bc.Hash
	anchor  []byte

	// signature checks
	pubkeys []ed25519.PublicKey
	sigs    *[]i10rjson.HexBytes
}

var (
	// ErrNoAnchor happens when the top-level contract stack contains no
	// values suitable for use as an anchor for finalize. This can
	// happen when invoking Tx on a Template that includes no Issuances
	// or Inputs.
	ErrNoAnchor = errors.New("no anchor for finalize")

	// ErrNonSigCheck happens when an unexpected item is left on the
	// top-level contract stack after finalize. This should be
	// impossible.
	ErrNonSigCheck = errors.New("non-signature-check item on stack after finalize")

	// ErrNumSigs happens when the number of signatures in an Input or
	// Issuance is not zero and not equal to the number of pubkeys.
	ErrNumSigs = errors.New("wrong number of signatures for pubkeys")

	// ErrInsufficientValue happens when an Output or Retirement
	// requires more units of a certain flavor than exist in values on
	// the top-level contract stack.
	ErrInsufficientValue = errors.New("cannot find enough units of desired flavor on the stack")

	// ErrRunlimit happens when a template has too many entries,
	// too many keys, or too much refdata.
	ErrRunlimit = errors.New("transaction exceeds maximum runlimit")
)

type materialization struct {
	tx       *bc.Tx
	resumer  func([]byte) error
	runlimit int64
	stack    []stackItem // stack at op.Finalize
	done     bool
}

// Materialize returns the transaction's program and ID.
// If the transaction ID cannot be computed because the
// transaction is not finalized or because of an error,
// the last return value will be a non-nil error.
func (tpl *Template) Materialize() (txid bc.Hash, prog []byte, err error) {
	if tpl.materialization == nil {
		tpl.materialization, err = tpl.materializeTx()
		if err != nil {
			return txid, prog, err
		}
	}
	return tpl.materialization.tx.ID, tpl.materialization.tx.Program, nil
}

// Dematerialize clears any previous materialization.
// This is helpful when a change to the template has been made,
// and it needs to be recognized.
func (tpl *Template) Dematerialize() {
	tpl.materialization = nil
}

// materializeTx materializes the template into txvm bytecode.
//
// The resulting program is complete up until op.Finalize.
// It does not include the transaction's signatures.
func (tpl *Template) materializeTx() (*materialization, error) {
	var entries []entry

	for _, inp := range tpl.Inputs {
		entries = append(entries, inp)
	}
	for _, iss := range tpl.Issuances {
		entries = append(entries, iss)
	}
	for _, out := range tpl.Outputs {
		entries = append(entries, out)
	}
	for _, ret := range tpl.Retirements {
		entries = append(entries, ret)
	}

	var b txvmutil.Builder
	var stack []stackItem // top-level contract stack

	firstVal := true
	ensureZeroval := func() error {
		if firstVal {
			stack = zerovalToTopSplit(&b, stack)
			if stack == nil {
				return ErrNoAnchor
			}
			firstVal = false
		}
		return nil
	}

	sort.Sort(orderedEntries(entries))

	for _, entry := range entries {
		switch entry := entry.(type) {
		case *Input:
			if entry.OutputIndex != nil {
				entry.Anchor = tpl.Outputs[*entry.OutputIndex].anchor
			}
			var seed []byte
			switch entry.OutputVersion {
			case 1:
				seed = standard.PayToMultisigSeed1[:]
			case 2:
				seed = standard.PayToMultisigSeed2[:]
			default:
				return nil, fmt.Errorf("unknown output contract version %d", entry.OutputVersion)
			}
			b.PushdataBytes(entry.InputRefdata) // x'<entry.InputRefdata>'
			b.Op(op.Put)                        // put
			standard.SpendMultisig(&b, entry.Quorum, entry.Pubkeys, entry.Amount, entry.AssetID, entry.Anchor, seed)

			// arg stack: [... value sigcheck]
			b.Op(op.Get).Op(op.Get) // get get
			stack = append(stack, stackItem{pubkeys: entry.Pubkeys, sigs: &entry.Sigs}, stackItem{amount: entry.Amount, assetID: entry.AssetID, anchor: entry.Anchor})

			err := ensureZeroval()
			if err != nil {
				return nil, err
			}

		case *Issuance:
			var issbuilder txvmutil.Builder

			stack2 := zerovalToTopSplit(&issbuilder, stack)
			if stack2 == nil {
				contract := standard.IssueWithoutAnchorContract(entry.Version, entry.Quorum, entry.Pubkeys, entry.AssetTag, entry.Amount, entry.Refdata, entry.BlockchainID, tpl.MaxTimeMS, entry.Nonce)
				b.PushdataBytes(contract)     // [<issuance contract>]
				b.Op(op.Contract).Op(op.Call) // contract call
				contractSeed := standard.AssetContractSeed[entry.Version]
				caller := txvm.ContractSeed(contract)
				nonce := txvm.NonceTuple(caller[:], contractSeed[:], entry.BlockchainID, int64(tpl.MaxTimeMS)) // TODO: check the unsigned times can be converted to signed ints safely
				hash := txvm.NonceHash(nonce)
				entry.anchor = hash[:]
			} else {
				contract := standard.IssueWithAnchorContract(entry.Version, entry.Quorum, entry.Pubkeys, entry.AssetTag, entry.Amount, entry.Refdata)
				stack = stack2

				b.Concat(issbuilder.Build())
				b.Op(op.Put)                  // put
				b.PushdataBytes(contract)     // [<issuance contract>]
				b.Op(op.Contract).Op(op.Call) // contract call
				entry.anchor = stack[len(stack)-1].anchor
				stack = stack[:len(stack)-1] // the put above removes the zeroval from the stack
			}
			// arg stack: [... value sigcheck]
			b.Op(op.Get).Op(op.Get) // get get
			assetID := entry.assetID()
			stack = append(stack, stackItem{pubkeys: entry.Pubkeys, sigs: &entry.Sigs}, stackItem{amount: entry.Amount, assetID: bc.NewHash(assetID), anchor: entry.anchor})
			err := ensureZeroval()
			if err != nil {
				return nil, err
			}

		case *Output:
			b.PushdataBytes(entry.Refdata) // x'<entry.Refdata>'
			b.Op(op.Put)                   // put
			if !tpl.legacyOutputs {
				b.PushdataBytes(entry.TokenTags) // x'<entry.TokenTags>'
				b.Op(op.Put)                     // put
			}
			var err error
			stack, err = valueToTop(&b, stack, entry.Amount, entry.AssetID)
			if err != nil {
				return nil, errors.Wrap(err, "locating value for output")
			}
			b.Op(op.Put) // put
			entry.anchor = stack[len(stack)-1].anchor
			stack = stack[:len(stack)-1]

			// {
			for _, pubkey := range entry.Pubkeys {
				b.PushdataBytes(pubkey) // x'<pubkey>'
			}
			b.PushdataInt64(int64(len(entry.Pubkeys)))
			b.Op(op.Tuple) // }

			b.Op(op.Put)                         // put
			b.PushdataInt64(int64(entry.Quorum)) // <entry.Quorum>
			b.Op(op.Put)                         // put
			if tpl.legacyOutputs {
				b.PushdataBytes(standard.PayToMultisigProg1) // [<multisig program>]
			} else {
				b.PushdataBytes(standard.PayToMultisigProg2) // [<multisig program>]
			}
			b.Op(op.Contract).Op(op.Call) // contract call

		case *Retirement:
			var err error
			stack, err = valueToTop(&b, stack, entry.Amount, entry.AssetID)
			if err != nil {
				return nil, errors.Wrap(err, "locating value for retirement")
			}
			b.PushdataBytes(entry.Refdata)           // x'<entry.Refdata>'
			b.Op(op.Put).Op(op.Put)                  // put put
			b.PushdataBytes(standard.RetireContract) // [<standard.RetireContract>]
			b.Op(op.Contract).Op(op.Call)            // contract call
			stack = stack[:len(stack)-1]
		}
	}

	b.PushdataUint64(tpl.MinTimeMS) // <tpl.MinTimeMS>
	b.PushdataUint64(tpl.MaxTimeMS) // <tpl.MaxTimeMS>
	b.Op(op.TimeRange)              // timerange
	b.PushdataBytes(tpl.TxTags)     // x'<tpl.TxTags>'
	b.Op(op.Log)                    // log

	stack = zerovalToTop(&b, stack)
	if stack == nil {
		return nil, ErrNoAnchor
	}
	b.Op(op.Finalize) // finalize
	stack = stack[:len(stack)-1]

	m := &materialization{
		stack: stack,
	}

	// Run the finalized but not-yet-signed tx to get the txid
	tx, err := bc.NewTx(b.Build(), 3, math.MaxInt64, txvm.Resumer(&m.resumer), txvm.GetRunlimit(&m.runlimit))
	if err != nil {
		return nil, errors.Wrap(err, "computing transaction ID")
	}
	if !tx.Finalized {
		return nil, errors.Wrap(txvm.ErrUnfinalized, "computing transaction ID")
	}
	m.tx = tx

	return m, nil
}

// Tx produces a bc.Tx from the transaction currently described by the
// template. This involves rendering the transaction as txvm code,
// running it, and extracting various values from the result.
func (tpl *Template) Tx() (tx *bc.Tx, err error) {
	if tpl.materialization == nil {
		tpl.materialization, err = tpl.materializeTx()
		if err != nil {
			return nil, err
		}
	}
	m := tpl.materialization
	if m.done {
		return m.tx, nil
	}

	var b txvmutil.Builder
	txidProg := standard.VerifyTxID(m.tx.ID.Byte32())
	for i := 0; i < len(m.stack); i++ {
		stackIdx := len(m.stack) - i - 1
		item := m.stack[stackIdx]
		if len(item.pubkeys) == 0 {
			return nil, ErrNonSigCheck
		}
		if len(*item.sigs) == 0 {
			for range item.pubkeys {
				b.PushdataBytes(nil) // x''
				b.Op(op.Put)         // put
			}
		} else {
			if len(*item.sigs) != len(item.pubkeys) {
				return nil, errors.WithDetailf(ErrNumSigs, "%d sig(s), %d pubkey(s)", len(*item.sigs), len(item.pubkeys))
			}
			for _, sig := range *item.sigs {
				b.PushdataBytes(sig) // x'<sig>'
				b.Op(op.Put)         // put
			}
		}
		b.PushdataBytes(txidProg) // [<txidProgSrc>]
		b.Op(op.Put).Op(op.Call)  // put call
	}

	// TODO(bobg): maybe do blank-check checking in a txvm callback here?
	// I think that would take the form of checking the txvm stacks for any Value objects on exit.
	err = m.resumer(b.Build())
	if err != nil {
		return m.tx, err
	}
	m.tx.Program = append(m.tx.Program, b.Build()...)
	m.tx.Runlimit = math.MaxInt64 - m.runlimit
	m.done = true
	return m.tx, nil
}

func findAndRoll(b *txvmutil.Builder, stack []stackItem, f func(int, stackItem) bool) []stackItem {
	for i := len(stack) - 1; i >= 0; i-- {
		if f(i, stack[i]) {
			if i == len(stack)-1 {
				return stack
			}
			b.PushdataInt64(int64(len(stack) - i - 1))
			b.Op(op.Roll)
			return append(stack[:i], append(stack[i+1:], stack[i])...)
		}
	}
	return nil
}

func bury(b *txvmutil.Builder, stack []stackItem, n int) []stackItem {
	b.PushdataInt64(int64(n)) // <n>
	b.Op(op.Bury)             // bury
	item, stack := stack[len(stack)-1], stack[:len(stack)-1]
	before, after := stack[:len(stack)-n], stack[len(stack)-n:]
	stack = append([]stackItem{}, before...)
	stack = append(stack, item)
	stack = append(stack, after...)
	return stack
}

func split(b *txvmutil.Builder, stack []stackItem, amount int64) []stackItem {
	b.PushdataInt64(amount) // <amount>
	b.Op(op.Split)          // split

	a := stack[len(stack)-1]
	anchor1 := txvm.VMHash("Split1", a.anchor[:])
	anchor2 := txvm.VMHash("Split2", a.anchor[:])

	stack[len(stack)-1].anchor = anchor1[:]
	stack[len(stack)-1].amount -= amount
	return append(stack, stackItem{assetID: a.assetID, anchor: anchor2[:], amount: amount})
}

// merge modifies the stack by combining the top two values
// to create a single value with the sum of the two amounts.
//
// If the sum of the values overflows int64, then the first value
// is split with the excess removed, such that the sum of the values
// will equal the value desired.
// e.g: merge([..., 20, MaxInt64 - 10], MaxInt64 - 5) -> [..., 15, MaxInt64 - 5]
func merge(b *txvmutil.Builder, stack []stackItem, desired int64) []stackItem {
	top, second := stack[len(stack)-1], stack[len(stack)-2]
	if _, ok := checked.AddInt64(top.amount, second.amount); !ok {
		excess := top.amount - (desired - second.amount)
		stack = split(b, stack, excess)
		stack = bury(b, stack, 2)
		// sort
		top, second = stack[len(stack)-1], stack[len(stack)-2]
	}
	b.Op(op.Merge)
	anchor := txvm.VMHash("Merge", append(top.anchor, second.anchor...))
	stack = stack[:len(stack)-2]
	stack = append(stack, stackItem{amount: top.amount + second.amount, assetID: top.assetID, anchor: anchor[:]})
	return stack
}

// Find any value on the stack, move it to the top, and splitzero
// it. Returns nil if no value is found.
func zerovalToTopSplit(b *txvmutil.Builder, stack []stackItem) []stackItem {
	stack = findAndRoll(b, stack, func(_ int, item stackItem) bool {
		return len(item.anchor) != 0
	})
	if stack != nil {
		return split(b, stack, 0)
	}
	return nil
}

// Find a zero value on the stack, move it to the top
func zerovalToTop(b *txvmutil.Builder, stack []stackItem) []stackItem {
	return findAndRoll(b, stack, func(_ int, item stackItem) bool {
		return len(item.anchor) != 0 && item.amount == 0
	})
}

func valueToTop(b *txvmutil.Builder, stack []stackItem, amount int64, assetID bc.Hash) ([]stackItem, error) {
	if len(stack) == 0 {
		return nil, errors.New("empty stack")
	}
	for {
		top := stack[len(stack)-1]
		if top.amount > 0 && top.assetID == assetID {
			if top.amount == amount {
				return stack, nil
			}
			if top.amount > amount {
				// con stack is [... val(orig - amount) val(amount)]
				return split(b, stack, amount), nil
			}
			if len(stack) > 1 {
				second := stack[len(stack)-2]
				if second.amount > 0 && second.assetID == assetID {
					stack = merge(b, stack, amount)
					continue
				}
			}
		}

		stack = findAndRoll(b, stack, func(i int, item stackItem) bool {
			return i != len(stack)-1 && item.amount > 0 && item.assetID == assetID
		})
		if stack == nil {
			return nil, errors.WithDetailf(ErrInsufficientValue, "amount=%d, assetID=%x", amount, assetID.Bytes())
		}
	}
}
