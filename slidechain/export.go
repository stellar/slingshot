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
	"github.com/stellar/go/keypair"
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

		const q = `SELECT txid, recipient, amount, asset_xdr, exporter, temp, seqnum FROM exports WHERE exported=0`

		var (
			txids      [][]byte
			recipients []string
			amounts    []int
			assetXDRs  [][]byte
			temps      []string
			seqnums    []int
			exporters  []string
		)
		err := sqlutil.ForQueryRows(ctx, c.DB, q, func(txid []byte, recipient string, amount int, assetXDR []byte, exporter string, temp string, seqnum int) {
			txids = append(txids, txid)
			recipients = append(recipients, recipient)
			amounts = append(amounts, amount)
			assetXDRs = append(assetXDRs, assetXDR)
			temps = append(temps, temp)
			seqnums = append(seqnums, seqnum)
			exporters = append(exporters, exporter)
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

			log.Printf("pegging out export %x: %d of %s to %s", txid, amounts[i], asset.String(), recipients[i])
			// TODO(vniu): flag txs that fail with unretriable errors in the db
			err = c.pegOut(ctx, recipientID, exporter, asset, xlm.Amount(amounts[i]), tempID, xdr.SequenceNumber(seqnums[i]))
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

func (c *Custodian) pegOut(ctx context.Context, recipient, exporter xdr.AccountId, asset xdr.Asset, amount xlm.Amount, temp xdr.AccountId, seqnum xdr.SequenceNumber) error {
	tx, err := c.buildPegOutTx(recipient, exporter, asset, amount, temp, seqnum)
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

func (c *Custodian) buildPegOutTx(recipient, exporter xdr.AccountId, asset xdr.Asset, amount xlm.Amount, temp xdr.AccountId, seqnum xdr.SequenceNumber) (*b.TransactionBuilder, error) {
	var paymentOp b.PaymentBuilder
	switch asset.Type {
	case xdr.AssetTypeAssetTypeNative:
		paymentOp = b.Payment(
			b.SourceAccount{AddressOrSeed: c.accountID.Address()},
			b.Destination{AddressOrSeed: recipient.Address()},
			b.NativeAmount{Amount: amount.HorizonString()},
		)
	case xdr.AssetTypeAssetTypeCreditAlphanum4:
		paymentOp = b.Payment(
			b.SourceAccount{AddressOrSeed: c.accountID.Address()},
			b.Destination{AddressOrSeed: recipient.Address()},
			b.CreditAmount{
				Code:   string(asset.AlphaNum4.AssetCode[:]),
				Issuer: asset.AlphaNum4.Issuer.Address(),
				Amount: amount.HorizonString(),
			},
		)
	case xdr.AssetTypeAssetTypeCreditAlphanum12:
		paymentOp = b.Payment(
			b.SourceAccount{AddressOrSeed: c.accountID.Address()},
			b.Destination{AddressOrSeed: recipient.Address()},
			b.CreditAmount{
				Code:   string(asset.AlphaNum12.AssetCode[:]),
				Issuer: asset.AlphaNum12.Issuer.Address(),
				Amount: amount.HorizonString(),
			},
		)
	}
	mergeAccountOp := b.AccountMerge(
		b.Destination{AddressOrSeed: exporter.Address()},
	)
	return b.Transaction(
		b.Network{Passphrase: c.network},
		b.SourceAccount{AddressOrSeed: temp.Address()},
		b.Sequence{Sequence: uint64(seqnum) + 1},
		b.BaseFee{Amount: baseFee},
		mergeAccountOp,
		paymentOp,
	)
}

// PreExportTx builds and submits a pre-export transaction to the Stellar
// network that creates a new temporary account, and sets the custodian as the
// sole signer. It returns the temporary account ID and sequence number
func PreExportTx(ctx context.Context, hclient *horizon.Client, custodian string, kp *keypair.Full) (string, xdr.SequenceNumber, error) {
	root, err := hclient.Root()
	if err != nil {
		return "", 0, errors.Wrap(err, "getting Horizon root")
	}
	temp, err := keypair.Random()
	if err != nil {
		return "", 0, errors.Wrap(err, "generating random account")
	}
	createAccountOp := b.CreateAccount(
		b.Destination{AddressOrSeed: temp.Address()},
		b.NativeAmount{Amount: (2 * xlm.Lumen).HorizonString()},
	)
	tx, err := b.Transaction(
		b.Network{Passphrase: root.NetworkPassphrase},
		b.SourceAccount{AddressOrSeed: kp.Address()},
		b.AutoSequence{SequenceProvider: hclient},
		b.BaseFee{Amount: baseFee},
		createAccountOp,
		b.SetOptions(
			b.SourceAccount{AddressOrSeed: temp.Address()},
			b.MasterWeight(0),
			b.AddSigner(custodian, 1),
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
	seqnum, err := hclient.SequenceForAccount(temp.Address())
	if err != nil {
		return "", 0, errors.Wrapf(err, "getting sequence number for temp account %s", temp.Address())
	}
	return temp.Address(), seqnum, nil
}

// BuildExportTx builds a txvm retirement tx for an asset issued
// onto slidechain. It will retire `amount` of the asset, and the
// remaining input will be output back to the original account.
func BuildExportTx(ctx context.Context, asset xdr.Asset, amount, inputAmt int64, addr, temp string, anchor []byte, prv ed25519.PrivateKey, seqnum xdr.SequenceNumber) (*bc.Tx, error) {
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
	assetIDBytes := txvm.AssetID(issueSeed[:], assetBytes)
	assetID := bc.NewHash(assetIDBytes)
	var rawSeed [32]byte
	copy(rawSeed[:], prv)
	kp, err := keypair.FromRawSeed(rawSeed)
	if err != nil {
		return nil, err
	}
	pubkey := prv.Public().(ed25519.PublicKey)
	refdata := []byte(fmt.Sprintf(`{"asset":"%s","account":"%s","temp":"%s","seqnum":%d,"exporter":"%s"}`, assetXDR, addr, temp, int64(seqnum), kp.Address()))
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
