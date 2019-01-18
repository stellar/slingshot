package slidechain

import (
	"context"
	"fmt"
	"log"
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

		const q = `SELECT txid, recipient, amount, asset_xdr FROM exports WHERE exported=0`

		var (
			txids      [][]byte
			recipients []string
			amounts    []int
			assetXDRs  [][]byte
		)
		err := sqlutil.ForQueryRows(ctx, c.DB, q, func(txid []byte, recipient string, amount int, assetXDR []byte) {
			txids = append(txids, txid)
			recipients = append(recipients, recipient)
			amounts = append(amounts, amount)
			assetXDRs = append(assetXDRs, assetXDR)
		})
		if err != nil {
			log.Fatalf("reading export rows: %s", err)
		}
		for i, txid := range txids {
			var recipientID xdr.AccountId
			err := recipientID.SetAddress(recipients[i])
			if err != nil {
				log.Fatalf("setting recipient to %s: %s", recipients[i], err)
			}
			var asset xdr.Asset
			err = xdr.SafeUnmarshal(assetXDRs[i], &asset)
			if err != nil {
				log.Fatalf("unmarshalling asset from XDR %x: %s", assetXDRs[i], err)
			}

			log.Printf("pegging out export %x: %d of %s to %s", txid, amounts[i], asset.String(), recipients[i])
			// TODO(vniu): flag txs that fail with unretriable errors in the db
			err = c.pegOut(ctx, recipientID, asset, xlm.Amount(amounts[i]))
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

func (c *Custodian) pegOut(ctx context.Context, recipient xdr.AccountId, asset xdr.Asset, amount xlm.Amount) error {
	tx, err := c.buildPegOutTx(recipient, asset, amount)
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

func (c *Custodian) buildPegOutTx(recipient xdr.AccountId, asset xdr.Asset, amount xlm.Amount) (*b.TransactionBuilder, error) {
	var paymentOp b.PaymentBuilder
	switch asset.Type {
	case xdr.AssetTypeAssetTypeNative:
		paymentOp = b.Payment(
			b.Destination{AddressOrSeed: recipient.Address()},
			b.NativeAmount{Amount: amount.HorizonString()},
		)
	case xdr.AssetTypeAssetTypeCreditAlphanum4:
		paymentOp = b.Payment(
			b.Destination{AddressOrSeed: recipient.Address()},
			b.CreditAmount{
				Code:   string(asset.AlphaNum4.AssetCode[:]),
				Issuer: asset.AlphaNum4.Issuer.Address(),
				Amount: amount.HorizonString(),
			},
		)
	case xdr.AssetTypeAssetTypeCreditAlphanum12:
		paymentOp = b.Payment(
			b.Destination{AddressOrSeed: recipient.Address()},
			b.CreditAmount{
				Code:   string(asset.AlphaNum12.AssetCode[:]),
				Issuer: asset.AlphaNum12.Issuer.Address(),
				Amount: amount.HorizonString(),
			},
		)
	}
	return b.Transaction(
		b.Network{Passphrase: c.network},
		b.SourceAccount{AddressOrSeed: c.accountID.Address()},
		b.AutoSequence{SequenceProvider: c.hclient},
		b.BaseFee{Amount: baseFee},
		paymentOp,
	)
}

// BuildExportTx builds a txvm retirement tx for an asset issued
// onto slidechain. It will retire `amount` of the asset, and the
// remaining input will be output back to the original account.
func BuildExportTx(ctx context.Context, asset xdr.Asset, amount, inputAmt int64, addr string, anchor []byte, prv ed25519.PrivateKey) (*bc.Tx, error) {
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
	refdata := []byte(fmt.Sprintf(`{"asset":"%s","account":"%s"}`, assetXDR, addr))
	assetIDBytes := txvm.AssetID(issueSeed[:], assetBytes)
	assetID := bc.NewHash(assetIDBytes)
	pubkey := prv.Public().(ed25519.PublicKey)
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
