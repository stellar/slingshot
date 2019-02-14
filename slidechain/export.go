package slidechain

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"strconv"
	"time"

	"github.com/bobg/sqlutil"
	"github.com/chain/txvm/crypto/ed25519"
	i10rjson "github.com/chain/txvm/encoding/json"
	"github.com/chain/txvm/errors"
	"github.com/chain/txvm/protocol/bc"
	"github.com/chain/txvm/protocol/txbuilder/standard"
	"github.com/chain/txvm/protocol/txvm"
	"github.com/chain/txvm/protocol/txvm/asm"
	"github.com/chain/txvm/protocol/txvm/op"
	"github.com/chain/txvm/protocol/txvm/txvmutil"
	"github.com/interstellar/slingshot/slidechain/stellar"
	"github.com/interstellar/starlight/worizon/xlm"
	b "github.com/stellar/go/build"
	"github.com/stellar/go/clients/horizon"
	"github.com/stellar/go/keypair"
	"github.com/stellar/go/strkey"
	"github.com/stellar/go/xdr"
)

const (
	baseFee                = 100
	custodianSigCheckerFmt = `txid x"%x" get 0 checksig verify`
	exportContract1Fmt     = `
	              #  con stack                arg stack              log      notes
	              #  ---------                ---------              ---      -----
	              #                           json, value, {exporter}           
	get get get   #  {exporter}, value, json                                  
	x'%x' output  #                                                  {O,...}
`

	exportContract2Fmt = `
	                     #  con stack                          arg stack                 log                 notes
	                     #  ---------                          ---------                 ---                 -----
	                     #  {exporter}, value, json            selector                                              
	get		             #  {exporter}, value, json, selector                                                
	jumpif:$doretire     #                                                                                   
	                     #  {exporter}, value, json                                                          
	"" put               #  {exporter}, value, json            ""                                            
	drop                 #  {exporter}, value                  ""                                              
	put put 1 put        #                                     "", value, {exporter}, 1                      
	x'%x' contract call  #                                                               {'L',...}{'O',...}  
	jump:$end		     #                                                                                   
	                     #                                                                                   
	$doretire            #                                                                                   
	                     #  {exporter}, value, json                                                          
	put put drop         #                                     json, value                                   
	x'%x' contract call  #                                                                                   
	                     #                                                                                   
	                     #                                                                                   
	$end	      	     #                                                                                   
`
)

// [%s] yield           #                                     sigchecker
// custodianSigCheckerSrc

var (
	custodianSigCheckerSrc = fmt.Sprintf(custodianSigCheckerFmt, custodianPub)
	exportContract1Src     = fmt.Sprintf(exportContract1Fmt, exportContract2Prog)
	exportContract1Prog    = asm.MustAssemble(exportContract1Src)
	exportContract1Seed    = txvm.ContractSeed(exportContract1Prog)
	exportContract2Src     = fmt.Sprintf(exportContract2Fmt, standard.PayToMultisigProg1, standard.RetireContract)
	exportContract2Prog    = asm.MustAssemble(exportContract2Src)
)

// Runs as a goroutine.
func (c *Custodian) pegOutFromExports(ctx context.Context) {
	defer log.Print("pegOutFromExports exiting")

	ch := make(chan struct{})
	go func() {
		c.exports.L.Lock()
		defer c.exports.L.Unlock()
		for {
			if ctx.Err() != nil {
				return
			}
			c.exports.Wait()
			ch <- struct{}{}
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ch:
		}

		const q = `SELECT txid, amount, asset_xdr, exporter, temp, seqnum FROM exports WHERE exported=0`

		var (
			txids, assetXDRs [][]byte
			amounts, seqnums []int
			exporters, temps []string
		)
		err := sqlutil.ForQueryRows(ctx, c.DB, q, func(txid []byte, amount int, assetXDR []byte, exporter string, temp string, seqnum int) {
			txids = append(txids, txid)
			amounts = append(amounts, amount)
			assetXDRs = append(assetXDRs, assetXDR)
			exporters = append(exporters, exporter)
			temps = append(temps, temp)
			seqnums = append(seqnums, seqnum)
		})
		if err != nil {
			log.Fatalf("reading export rows: %s", err)
		}
		for i, txid := range txids {
			var asset xdr.Asset
			err = xdr.SafeUnmarshal(assetXDRs[i], &asset)
			if err != nil {
				log.Fatalf("unmarshalling asset from XDR %x: %s", assetXDRs[i], err)
			}
			var tempID xdr.AccountId
			err = tempID.SetAddress(temps[i])
			if err != nil {
				log.Fatalf("setting temp address to %s: %s", temps[i], err)
			}
			var exporter xdr.AccountId
			err = exporter.SetAddress(exporters[i])
			if err != nil {
				log.Fatalf("setting exporter address to %s: %s", exporters[i], err)
			}

			log.Printf("pegging out export %x: %d of %s to %s", txid, amounts[i], asset.String(), exporters[i])
			// TODO(vniu): flag txs that fail with unretriable errors in the db
			// PRTODO: Pass information for the post-peg-out smart contract to to the peg-out tx.
			var peggedOut int
			for i := 0; i < 5; i++ {
				err = c.pegOut(ctx, exporter, asset, int64(amounts[i]), tempID, xdr.SequenceNumber(seqnums[i]))
				if err == nil { // successful peg-out
					peggedOut = 1
					break
				}
				if herr, ok := errors.Root(err).(*horizon.Error); ok {
					resultCodes, err := herr.ResultCodes()
					if err != nil {
						log.Fatalf("getting error codes from failed submission of tx %s", txid)
					}
					if resultCodes.TransactionCode != xdr.TransactionResultCodeTxBadSeq.String() { // non-retriable error
						break
					}
				} else {
					break
				}
				if i == 0 {
					_, err = c.DB.ExecContext(ctx, `UPDATE exports SET exported=1, pegged_out=2 WHERE txid=$1`, txid)
					if err != nil {
						log.Fatalf("updating export table for retriable tx: %s", err)
					}
				}
			}
			_, err = c.DB.ExecContext(ctx, `UPDATE exports SET exported=1, pegged_out=$1 WHERE txid=$2`, peggedOut, txid)
			if err != nil {
				log.Fatalf("updating export table: %s", err)
			}
			// Wake up a goroutine for post-peg-out txvm txs
			c.pegouts.Broadcast()
		}
	}
}

func (c *Custodian) pegOut(ctx context.Context, exporter xdr.AccountId, asset xdr.Asset, amount int64, temp xdr.AccountId, seqnum xdr.SequenceNumber) error {
	tx, err := buildPegOutTx(c.AccountID.Address(), exporter.Address(), temp.Address(), c.network, asset, amount, seqnum)
	if err != nil {
		return errors.Wrap(err, "building peg-out tx")
	}
	_, err = stellar.SignAndSubmitTx(c.hclient, tx, c.seed)
	if err != nil {
		return errors.Wrap(err, "submitting peg-out tx")
	}
	return nil
}

func buildPegOutTx(custodian, exporter, temp, network string, asset xdr.Asset, amount int64, seqnum xdr.SequenceNumber) (*b.TransactionBuilder, error) {
	var paymentOp b.PaymentBuilder
	switch asset.Type {
	case xdr.AssetTypeAssetTypeNative:
		lumens := xlm.Amount(amount)
		paymentOp = b.Payment(
			b.SourceAccount{AddressOrSeed: custodian},
			b.Destination{AddressOrSeed: exporter},
			b.NativeAmount{Amount: lumens.HorizonString()},
		)
	case xdr.AssetTypeAssetTypeCreditAlphanum4:
		paymentOp = b.Payment(
			b.SourceAccount{AddressOrSeed: custodian},
			b.Destination{AddressOrSeed: exporter},
			b.CreditAmount{
				Code:   string(asset.AlphaNum4.AssetCode[:]),
				Issuer: asset.AlphaNum4.Issuer.Address(),
				Amount: strconv.FormatInt(amount, 10),
			},
		)
	case xdr.AssetTypeAssetTypeCreditAlphanum12:
		paymentOp = b.Payment(
			b.SourceAccount{AddressOrSeed: custodian},
			b.Destination{AddressOrSeed: exporter},
			b.CreditAmount{
				Code:   string(asset.AlphaNum12.AssetCode[:]),
				Issuer: asset.AlphaNum12.Issuer.Address(),
				Amount: strconv.FormatInt(amount, 10),
			},
		)
	}
	mergeAccountOp := b.AccountMerge(
		b.Destination{AddressOrSeed: exporter},
	)
	return b.Transaction(
		b.Network{Passphrase: network},
		b.SourceAccount{AddressOrSeed: temp},
		b.Sequence{Sequence: uint64(seqnum) + 1},
		b.BaseFee{Amount: baseFee},
		mergeAccountOp,
		paymentOp,
	)
	// PRTODO: Add a MemoHash with unique info for the post-peg-out smart contract.
}

// createTempAccount builds and submits a transaction to the Stellar
// network that creates a new temporary account. It returns the
// temporary account keypair and sequence number.
func createTempAccount(hclient horizon.ClientInterface, kp *keypair.Full) (*keypair.Full, xdr.SequenceNumber, error) {
	root, err := hclient.Root()
	if err != nil {
		return nil, 0, errors.Wrap(err, "getting Horizon root")
	}
	temp, err := keypair.Random()
	if err != nil {
		return nil, 0, errors.Wrap(err, "generating random account")
	}
	tx, err := b.Transaction(
		b.Network{Passphrase: root.NetworkPassphrase},
		b.SourceAccount{AddressOrSeed: kp.Address()},
		b.AutoSequence{SequenceProvider: hclient},
		b.BaseFee{Amount: baseFee},
		b.CreateAccount(
			b.NativeAmount{Amount: (2 * xlm.Lumen).HorizonString()},
			b.Destination{AddressOrSeed: temp.Address()},
		),
	)
	if err != nil {
		return nil, 0, errors.Wrap(err, "building temp account creation tx")
	}
	_, err = stellar.SignAndSubmitTx(hclient, tx, kp.Seed())
	if err != nil {
		return nil, 0, errors.Wrapf(err, "submitting temp account creation tx")
	}
	seqnum, err := hclient.SequenceForAccount(temp.Address())
	if err != nil {
		return nil, 0, errors.Wrapf(err, "getting sequence number for temp account %s", temp.Address())
	}
	return temp, seqnum, nil
}

// SubmitPreExportTx builds and submits the two pre-export transactions
// to the Stellar network.
// The first transaction creates a new temporary account.
// The second transaction sets the signer on the temporary account
// to be a preauth transaction, which merges the account and pays
// out the pegged-out funds.
// The function returns the temporary account ID and sequence number.
func SubmitPreExportTx(hclient horizon.ClientInterface, kp *keypair.Full, custodian string, asset xdr.Asset, amount int64) (string, xdr.SequenceNumber, error) {
	root, err := hclient.Root()
	if err != nil {
		return "", 0, errors.Wrap(err, "getting Horizon root")
	}

	temp, seqnum, err := createTempAccount(hclient, kp)
	if err != nil {
		return "", 0, errors.Wrap(err, "creating temp account")
	}

	preauthTx, err := buildPegOutTx(custodian, kp.Address(), temp.Address(), root.NetworkPassphrase, asset, amount, seqnum)
	if err != nil {
		return "", 0, errors.Wrap(err, "building preauth tx")
	}
	preauthTxHash, err := preauthTx.Hash()
	if err != nil {
		return "", 0, errors.Wrap(err, "hashing preauth tx")
	}
	hashStr, err := strkey.Encode(strkey.VersionByteHashTx, preauthTxHash[:])
	if err != nil {
		return "", 0, errors.Wrap(err, "encoding preauth tx hash")
	}

	tx, err := b.Transaction(
		b.Network{Passphrase: root.NetworkPassphrase},
		b.SourceAccount{AddressOrSeed: kp.Address()},
		b.AutoSequence{SequenceProvider: hclient},
		b.BaseFee{Amount: baseFee},
		b.SetOptions(
			b.SourceAccount{AddressOrSeed: temp.Address()},
			b.MasterWeight(0),
			b.SetThresholds(1, 1, 1),
			b.AddSigner(hashStr, 1),
		),
	)
	if err != nil {
		return "", 0, errors.Wrap(err, "building pre-export tx")
	}
	_, err = stellar.SignAndSubmitTx(hclient, tx, kp.Seed(), temp.Seed())
	if err != nil {
		return "", 0, errors.Wrap(err, "pre-exporttx")
	}
	return temp.Address(), seqnum, nil
}

// BuildExportTx locks money to be retired in a TxVM smart contract.
// Based on the success of the peg-out transaction, it either retires this amount
// or returns it to the exporter address.
func BuildExportTx(ctx context.Context, asset xdr.Asset, amount, inputAmt int64, temp string, anchor []byte, prv ed25519.PrivateKey, seqnum xdr.SequenceNumber) (*bc.Tx, error) {
	if inputAmt < amount {
		return nil, fmt.Errorf("cannot have input amount %d less than export amount %d", inputAmt, amount)
	}
	assetXDR, err := xdr.MarshalBase64(asset)
	if err != nil {
		return nil, err
	}
	assetBytes, err := asset.MarshalBinary()
	if err != nil {
		return nil, err
	}
	assetID := bc.NewHash(txvm.AssetID(importIssuanceSeed[:], assetBytes))
	var rawSeed [32]byte
	copy(rawSeed[:], prv)
	kp, err := keypair.FromRawSeed(rawSeed)
	if err != nil {
		return nil, err
	}
	pubkey := prv.Public().(ed25519.PublicKey)
	ref := struct {
		AssetXDR string `json:"asset"`
		Temp     string `json:"temp"`
		Seqnum   int64  `json:"seqnum"`
		Exporter string `json:"exporter"`
		Amount   int64  `json:"amount"`
		Anchor   []byte `json:"anchor"`
		Pubkey   []byte `json:"pubkey"`
	}{
		assetXDR,
		temp,
		int64(seqnum),
		kp.Address(),
		inputAmt,
		anchor,
		pubkey,
	}
	inputRefdata, err := json.Marshal(ref)
	if err != nil {
		return nil, errors.Wrap(err, "marshaling reference data")
	}
	inputRefdataHex := i10rjson.HexBytes(inputRefdata)

	ref.Amount = amount
	// We first split off the difference between inputAmt and amt.
	// Then, we split off the zero-value for finalize.
	retireAnchor1 := txvm.VMHash("Split2", anchor)
	retireAnchor := txvm.VMHash("Split1", retireAnchor1[:])
	ref.Anchor = retireAnchor[:]
	retireRefdata, err := json.Marshal(ref)
	if err != nil {
		return nil, errors.Wrap(err, "marshaling reference data")
	}
	retireRefdataHex := i10rjson.HexBytes(retireRefdata)
	b := new(txvmutil.Builder)
	b.PushdataBytes(inputRefdataHex)                                                                                     // con stack: json
	b.Op(op.Put)                                                                                                         // arg stack: json
	standard.SpendMultisig(b, 1, []ed25519.PublicKey{pubkey}, inputAmt, assetID, anchor, standard.PayToMultisigSeed1[:]) // arg stack: inputval, sigcheck
	b.Op(op.Get).Op(op.Get)                                                                                              // con stack: sigcheck, inputval
	b.PushdataInt64(amount).Op(op.Split)                                                                                 // con stack: sigcheck, changeval, retireval
	b.PushdataInt64(1).Op(op.Roll).Op(op.Drop)                                                                           // con stack: sigcheck, retireval
	b.PushdataBytes(retireRefdataHex).Op(op.Put)                                                                         // con stack: sigcheck, value; arg stack: json
	b.PushdataInt64(0).Op(op.Split).PushdataInt64(1).Op(op.Roll).Op(op.Put)                                              // con stack: sigcheck, zeroval; arg stack: json, value
	b.Tuple(func(tup *txvmutil.TupleBuilder) {
		tup.PushdataBytes(pubkey)
	})
	b.Op(op.Put) // con stack: sigchecker, zeroval; arg stack: json, value, {pubkey}
	b.PushdataBytes(exportContract1Prog)
	b.Op(op.Contract).Op(op.Call) // con stack: sigchecker, zeroval
	b.Op(op.Finalize)             // con stack: sigchecker
	prog1 := b.Build()

	log.Print("PRINTING EXPORT TX BYTES")
	log.Printf("x'%x'", i10rjson.HexBytes(prog1))
	vm, err := txvm.Validate(prog1, 3, math.MaxInt64, txvm.StopAfterFinalize)
	if err != nil {
		return nil, errors.Wrap(err, "computing transaction ID")
	}
	sigProg := standard.VerifyTxID(vm.TxID)
	msg := append(sigProg, anchor...)
	sig := ed25519.Sign(prv, msg)
	b.PushdataBytes(sig).Op(op.Put)
	b.PushdataBytes(sigProg).Op(op.Put)
	b.Op(op.Call)

	prog2 := b.Build()
	tx, err := bc.NewTx(prog2, 3, math.MaxInt64)
	if err != nil {
		return nil, errors.Wrap(err, "making pre-export tx")
	}
	return tx, nil
}

func (c *Custodian) doPostExport(ctx context.Context, assetXDR, anchor, txid []byte, amount, seqnum, peggedOut int64, exporter, temp string, pubkey []byte) error {
	var asset xdr.Asset
	err := asset.UnmarshalBinary(assetXDR)
	if err != nil {
		return errors.Wrap(err, "unmarshaling asset xdr")
	}
	assetBytes, err := asset.MarshalBinary()
	if err != nil {
		return errors.Wrap(err, "marshaling asset bytes")
	}
	assetID := bc.NewHash(txvm.AssetID(importIssuanceSeed[:], assetBytes))
	ref := struct {
		AssetXDR []byte `json:"asset"`
		Temp     string `json:"temp"`
		Seqnum   int64  `json:"seqnum"`
		Exporter string `json:"exporter"`
		Amount   int64  `json:"amount"`
		Anchor   []byte `json:"anchor"`
		Pubkey   []byte `json:"pubkey"`
	}{
		assetXDR,
		temp,
		seqnum,
		exporter,
		amount,
		anchor,
		pubkey,
	}
	refdata, err := json.Marshal(ref)
	if err != nil {
		return errors.Wrap(err, "marshaling reference data")
	}
	refdataHex := i10rjson.HexBytes(refdata)
	b := new(txvmutil.Builder)
	b.Tuple(func(contract *txvmutil.TupleBuilder) { // {'C', ...}
		contract.PushdataByte(txvm.ContractCode)
		contract.PushdataBytes(exportContract1Seed[:])
		contract.PushdataBytes(exportContract2Prog)
		contract.Tuple(func(tup *txvmutil.TupleBuilder) { // {'T', pubkey}
			tup.PushdataByte(txvm.TupleCode)
			tup.Tuple(func(pktup *txvmutil.TupleBuilder) {
				pktup.PushdataBytes(pubkey)
			})
		})
		contract.Tuple(func(tup *txvmutil.TupleBuilder) { // {'V', amount, assetID, anchor}
			tup.PushdataByte(txvm.ValueCode)
			tup.PushdataInt64(amount)
			tup.PushdataBytes(assetID.Bytes())
			tup.PushdataBytes(anchor)
		})
		contract.Tuple(func(tup *txvmutil.TupleBuilder) { // {'S', refdata}
			tup.PushdataByte(txvm.BytesCode)
			tup.PushdataBytes(refdataHex)
		})
	})
	b.PushdataInt64(peggedOut).Op(op.Put) // arg stack: selector
	b.Op(op.Input).Op(op.Call)
	b.PushdataBytes(c.InitBlockHash.Bytes())
	b.PushdataInt64(int64(bc.Millis(time.Now().Add(10 * time.Minute))))
	b.Op(op.Nonce).Op(op.Finalize)

	// PRTODO: I feel like there was a sigcheck here... check if there should be one.

	// Build and submit tx
	// TODO(debnil): confirm we need to wait on the tx hitting txvm before deleting the row
	prog := b.Build()

	log.Print("PRINTING IMPORT TX BYTES")
	log.Printf("x'%x'", i10rjson.HexBytes(prog))
	var runlimit int64
	tx, err := bc.NewTx(prog, 3, math.MaxInt64, txvm.GetRunlimit(&runlimit))
	if err != nil {
		return errors.Wrap(err, "making post-export tx")
	}
	tx.Runlimit = math.MaxInt64 - runlimit
	r, err := c.S.submitTx(ctx, tx)
	if err != nil {
		return errors.Wrap(err, "submitting post-export tx")
	}
	err = c.S.waitOnTx(ctx, tx.ID, r)
	if err != nil {
		return errors.Wrap(err, "waiting on post-export tx to hit txvm")
	}
	_, err = c.DB.ExecContext(ctx, `DELETE FROM exports WHERE txid=$1`, txid)
	return errors.Wrapf(err, "deleting export for tx %x", txid)
}

// IsExportTx returns whether or not a txvm transaction matches the slidechain export tx format.
//
// Expected log is:
// {"I", ...}
// {"L", ...}
// {"O", caller, outputid}
// {"F", ...}
func IsExportTx(tx *bc.Tx, asset xdr.Asset, inputAmt int64, temp, exporter string, seqnum int64, anchor, pubkey []byte) bool {
	if len(tx.Log) != 4 {
		return false
	}
	if tx.Log[0][0].(txvm.Bytes)[0] != txvm.InputCode {
		return false
	}
	if tx.Log[1][0].(txvm.Bytes)[0] != txvm.LogCode {
		return false
	}
	if tx.Log[2][0].(txvm.Bytes)[0] != txvm.OutputCode {
		return false
	}
	if tx.Log[3][0].(txvm.Bytes)[0] != txvm.FinalizeCode {
		return false
	}
	assetXDR, err := xdr.MarshalBase64(asset)
	if err != nil {
		return false
	}
	ref := struct {
		AssetXDR string `json:"asset"`
		Temp     string `json:"temp"`
		Seqnum   int64  `json:"seqnum"`
		Exporter string `json:"exporter"`
		Amount   int64  `json:"amount"`
		Anchor   []byte `json:"anchor"`
		Pubkey   []byte `json:"pubkey"`
	}{
		assetXDR,
		temp,
		seqnum,
		exporter,
		inputAmt,
		anchor,
		pubkey,
	}
	refdata, err := json.Marshal(ref)
	if !bytes.Equal(refdata, tx.Log[1][2].(txvm.Bytes)) {
		return false
	}
	return true
}
