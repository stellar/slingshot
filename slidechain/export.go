package slidechain

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strconv"
	"time"

	"github.com/bobg/sqlutil"
	"github.com/chain/txvm/crypto/ed25519"
	"github.com/chain/txvm/errors"
	"github.com/chain/txvm/protocol/bc"
	"github.com/chain/txvm/protocol/txbuilder"
	"github.com/chain/txvm/protocol/txbuilder/txresult"
	"github.com/chain/txvm/protocol/txvm"
	"github.com/interstellar/starlight/worizon/xlm"
	b "github.com/stellar/go/build"
	"github.com/stellar/go/clients/horizon"
	"github.com/stellar/go/keypair"
	"github.com/stellar/go/strkey"
	"github.com/stellar/go/xdr"
)

const baseFee = 100

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
			txids     [][]byte
			amounts   []int
			assetXDRs [][]byte
			exporters []string
			temps     []string
			seqnums   []int
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
			err = c.pegOut(ctx, exporter, asset, int64(amounts[i]), tempID, xdr.SequenceNumber(seqnums[i]))
			if err != nil {
				log.Fatalf("pegging out tx: %s", err)
			}
			_, err = c.DB.ExecContext(ctx, `UPDATE exports SET exported=1 WHERE txid=$1`, txid)
			if err != nil {
				log.Fatalf("updating export table: %s", err)
			}
		}
	}
}

func (c *Custodian) pegOut(ctx context.Context, exporter xdr.AccountId, asset xdr.Asset, amount int64, temp xdr.AccountId, seqnum xdr.SequenceNumber) error {
	tx, err := buildPegOutTx(c.AccountID.Address(), exporter.Address(), temp.Address(), c.network, asset, amount, seqnum)
	if err != nil {
		return errors.Wrap(err, "building tx")
	}
	txenv, err := tx.Sign(c.seed)
	if err != nil {
		return errors.Wrap(err, "signing tx")
	}
	txstr, err := xdr.MarshalBase64(txenv.E)
	if err != nil {
		return errors.Wrap(err, "marshaling tx to base64")
	}
	resp, err := c.hclient.SubmitTransaction(txstr)
	if err != nil {
		log.Printf("error submitting tx: %s\ntx: %s", err, txstr)
		var (
			resultStr string
			err       error
			tr        xdr.TransactionResult
		)
		if herr, ok := err.(*horizon.Error); ok {
			resultStr, err = herr.ResultString()
			if err != nil {
				log.Print(err, "extracting result string from horizon.Error")
			}
		}
		if resultStr == "" {
			resultStr = resp.Result
			if resultStr == "" {
				log.Print("cannot locate result string from failed tx submission")
			}
		}
		err = xdr.SafeUnmarshalBase64(resultStr, &tr)
		if err != nil {
			log.Print(err, "unmarshaling TransactionResult")
		}
		log.Println("Result: ", resultStr)
	}
	return errors.Wrap(err, "submitting tx")
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
}

// createTempAccount builds and submits a transaction to the Stellar
// network that creates a new temporary account. It returns the
// temporary account keypair and sequence number.
func createTempAccount(hclient *horizon.Client, kp *keypair.Full) (*keypair.Full, xdr.SequenceNumber, error) {
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
	txenv, err := tx.Sign(kp.Seed())
	if err != nil {
		return nil, 0, errors.Wrap(err, "signing temp account tx")
	}
	txstr, err := xdr.MarshalBase64(txenv.E)
	if err != nil {
		return nil, 0, errors.Wrap(err, "marshaling temp account txenv")
	}
	_, err = hclient.SubmitTransaction(txstr)
	if err != nil {
		return nil, 0, errors.Wrapf(err, "submitting pre-export tx: %s", txstr)
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
func SubmitPreExportTx(hclient *horizon.Client, kp *keypair.Full, custodian string, asset xdr.Asset, amount int64) (string, xdr.SequenceNumber, error) {
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
	txenv, err := tx.Sign(kp.Seed(), temp.Seed())
	if err != nil {
		return "", 0, errors.Wrap(err, "signing pre-export tx")
	}
	txstr, err := xdr.MarshalBase64(txenv.E)
	if err != nil {
		return "", 0, errors.Wrap(err, "marshaling pre-export txenv")
	}
	_, err = hclient.SubmitTransaction(txstr)
	if err != nil {
		return "", 0, errors.Wrapf(err, "submitting pre-export tx: %s", txstr)
	}
	return temp.Address(), seqnum, nil
}

// BuildExportTx builds a txvm retirement tx for an asset issued
// onto slidechain. It will retire `amount` of the asset, and the
// remaining input will be output back to the original account.
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
	}{
		assetXDR,
		temp,
		int64(seqnum),
		kp.Address(),
	}
	refdata, err := json.Marshal(ref)
	if err != nil {
		return nil, errors.Wrap(err, "marshaling reference data")
	}
	tpl := txbuilder.NewTemplate(time.Now().Add(time.Minute), nil)
	tpl.AddInput(1, [][]byte{prv}, nil, []ed25519.PublicKey{pubkey}, inputAmt, assetID, anchor, nil, 1)
	tpl.AddRetirement(int64(amount), assetID, refdata)
	if inputAmt > amount {
		tpl.AddOutput(1, []ed25519.PublicKey{pubkey}, inputAmt-amount, assetID, nil, nil)
	}
	err = tpl.Sign(ctx, func(_ context.Context, msg []byte, prv []byte, path [][]byte) ([]byte, error) {
		return ed25519.Sign(prv, msg), nil
	})
	if err != nil {
		return nil, errors.Wrap(err, "signing tx")
	}
	tx, err := tpl.Tx()
	if err != nil {
		return nil, errors.Wrap(err, "building tx")
	}
	if inputAmt > amount {
		txresult := txresult.New(tx)
		output := txresult.Outputs[0].Value
		log.Printf("output: assetid %x amount %x anchor %x", output.AssetID.Bytes(), output.Amount, output.Anchor)
	}
	return tx, nil
}

// IsExportTx returns whether or not a txvm transaction matches the slidechain export tx format.
//
// Expected log is:
// For an export that fully consumes the input:
// {"I", ...}
// {"L", ...}
// {"X", vm seed, inputAmount, asset id, anchor}
// {"L", vm seed, refdata}
// {"R", ...} timerange
// {"L", ...}
// {"F", ...}
//
// For an export that partially consumes the input:
// {"I", ...}
// {"L", ...}
// {"X", vm seed, inputAmount, asset id, anchor}
// {"L", vm seed, refdata}
// {"L", ...}
// {"L", ...}
// {"O", caller, outputid}
// {"R", ...}
// {"L", ...}
// {"F", ...}
func IsExportTx(tx *bc.Tx, asset xdr.Asset, inputAmt int64, temp, exporter string, seqnum int64) bool {
	// The export transaction when we export the full input amount has seven operations, and when we export
	// part of the input and output the rest back to the exporter, it has ten operations
	if len(tx.Log) != 7 && len(tx.Log) != 10 {
		return false
	}
	if tx.Log[0][0].(txvm.Bytes)[0] != txvm.InputCode {
		return false
	}
	if tx.Log[1][0].(txvm.Bytes)[0] != txvm.LogCode {
		return false
	}
	if tx.Log[2][0].(txvm.Bytes)[0] != txvm.RetireCode {
		return false
	}
	if int64(tx.Log[2][2].(txvm.Int)) != inputAmt {
		return false
	}
	assetBytes, err := asset.MarshalBinary()
	if err != nil {
		return false
	}
	assetXDR, err := xdr.MarshalBase64(asset)
	if err != nil {
		return false
	}
	wantAssetID := txvm.AssetID(importIssuanceSeed[:], assetBytes)
	if !bytes.Equal(wantAssetID[:], tx.Log[2][3].(txvm.Bytes)) {
		return false
	}
	if tx.Log[3][0].(txvm.Bytes)[0] != txvm.LogCode {
		return false
	}
	ref := struct {
		AssetXDR string `json:"asset"`
		Temp     string `json:"temp"`
		Seqnum   int64  `json:"seqnum"`
		Exporter string `json:"exporter"`
	}{
		assetXDR,
		temp,
		seqnum,
		exporter,
	}
	refdata, err := json.Marshal(ref)
	if !bytes.Equal(refdata, tx.Log[3][2].(txvm.Bytes)) {
		return false
	}
	// Beyond this, the two transactions diverge but must either finalize
	// or output the remaining unconsumed input
	return true
}
