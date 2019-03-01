package slidechain

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"strconv"

	"github.com/bobg/sqlutil"
	"github.com/chain/txvm/crypto/ed25519"
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

type pegOut struct {
	TxID     []byte      `json:"txid,omitempty"`
	AssetXDR []byte      `json:"asset"`
	TempAddr string      `json:"temp"`
	Seqnum   int64       `json:"seqnum"`
	Exporter string      `json:"exporter"`
	Amount   int64       `json:"amount"`
	Anchor   []byte      `json:"anchor"`
	Pubkey   []byte      `json:"pubkey"`
	State    pegOutState `json:"state,omitempty"`
}

type pegOutState int

const (
	pegOutNotYet pegOutState = iota
	pegOutOK
	pegOutRetry
	pegOutFail
)

const baseFee = 100

const (
	custodianSigCheckerFmt = `txid x"%x" get 0 checksig verify`

	// TODO(debnil): Add a log statement in this contract, and check for
	// its existence, with appropriate seed, in the watchExports goroutine.
	// This more robustly checks for the export tx.
	exportContract1Fmt = `
	              #  con stack                arg stack              log
	              #  ---------                ---------              ---
	              #                           json, value, {exporter}       
	get get get   #  {exporter}, value, json                                  
	x'%x' output  #                                                  {O,...}
`

	// TODO(debnil): Modify this contract to produce a zeroval from the value it contains,
	// so the caller does not have to do a new `nonce`.
	exportContract2Fmt = `
	                     #  con stack                          arg stack                 log
	                     #  ---------                          ---------                 ---
	                     #  {exporter}, value, json            selector                                    
	get                  #  {exporter}, value, json, selector                                              
	jumpif:$doretire     #                                                                                 
	                     #  {exporter}, value, json                                                        
	"" put               #  {exporter}, value, json            ""                                          
	drop                 #  {exporter}, value                                                              
	put put 1 put        #                                     "", value, {exporter}, 1                    
	x'%x' contract call  #                                                               {'L',...}{'O',...}
	jump:$checksig       #                                                                                   
	                     #                                                                                   
	$doretire            #                                                                                   
	                     #  {exporter}, value, json                                                          
	put put drop         #                                     json, value                                   
	x'%x' contract call  #                                                                                   
	                     #                                                                                                        
	$checksig            #                                                                                   
	[%s] yield           #                                     sigchecker                                    
                                                                                   
`
)

var (
	custodianSigCheckerSrc = fmt.Sprintf(custodianSigCheckerFmt, custodianPub)
	exportContract1Src     = fmt.Sprintf(exportContract1Fmt, exportContract2Prog)
	exportContract1Prog    = asm.MustAssemble(exportContract1Src)
	exportContract1Seed    = txvm.ContractSeed(exportContract1Prog)
	exportContract2Src     = fmt.Sprintf(exportContract2Fmt, standard.PayToMultisigProg1, standard.RetireContract, custodianSigCheckerSrc)
	exportContract2Prog    = asm.MustAssemble(exportContract2Src)
)

// Runs as a goroutine.
func (c *Custodian) pegOutFromExports(ctx context.Context, pegouts chan<- pegOut) {
	defer log.Print("pegOutFromExports exiting")
	defer close(pegouts)

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
		const q = `SELECT txid, anchor, pubkey, asset_xdr, amount, seqnum, exporter, temp_addr FROM exports WHERE pegged_out IN ($1, $2)`

		var (
			txids, anchors, assetXDRs, pubkeys [][]byte
			amounts, seqnums                   []int64
			exporters, tempAddrs               []string
		)
		err := sqlutil.ForQueryRows(ctx, c.DB, q, pegOutNotYet, pegOutRetry, func(txid, anchor, pubkey, assetXDR []byte, amount, seqnum int64, exporter, tempAddr string) {
			txids = append(txids, txid)
			amounts = append(amounts, amount)
			assetXDRs = append(assetXDRs, assetXDR)
			exporters = append(exporters, exporter)
			tempAddrs = append(tempAddrs, tempAddr)
			seqnums = append(seqnums, seqnum)
			anchors = append(anchors, anchor)
			pubkeys = append(pubkeys, pubkey)
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
			err = tempID.SetAddress(tempAddrs[i])
			if err != nil {
				log.Fatalf("setting temp address to %s: %s", tempAddrs[i], err)
			}
			var exporter xdr.AccountId
			err = exporter.SetAddress(exporters[i])
			if err != nil {
				log.Fatalf("setting exporter address to %s: %s", exporters[i], err)
			}

			log.Printf("pegging out export %x: %d of %s to %s", txid, amounts[i], asset.String(), exporters[i])

			peggedOut := pegOutOK
			err = c.pegOut(ctx, exporter, asset, amounts[i], tempID, xdr.SequenceNumber(seqnums[i]))
			if err != nil {
				peggedOut = pegOutFail
				if herr, ok := errors.Root(err).(*horizon.Error); ok {
					resultCodes, rerr := herr.ResultCodes()
					if rerr != nil {
						log.Fatalf("getting error codes from failed submission of tx %x (with horizon err '%s'): %s", txid, herr, rerr)
					}
					if resultCodes.TransactionCode == xdr.TransactionResultCodeTxBadSeq.String() {
						peggedOut = pegOutRetry
					}
				}
			}
			result, err := c.DB.ExecContext(ctx, `UPDATE exports SET pegged_out=$1 WHERE txid=$2`, peggedOut, txid)
			if err != nil {
				log.Fatalf("updating pegged_out in export table: %s", err)
			}
			numAffected, err := result.RowsAffected()
			if err != nil {
				log.Fatalf("checking rows affected by update exports query for txid %x: %s", txid, err)
			}
			if numAffected != 1 {
				log.Fatalf("got %d rows affected by update exports query for txid %x, want 1", numAffected, txid)
			}
			// Send peg-out info to goroutine for successes and non-retriable failures.
			if peggedOut == pegOutOK || peggedOut == pegOutFail {
				pegouts <- pegOut{
					TxID:     txid,
					AssetXDR: assetXDRs[i],
					TempAddr: tempAddrs[i],
					Seqnum:   seqnums[i],
					Exporter: exporters[i],
					Amount:   amounts[i],
					State:    peggedOut,
					Anchor:   anchors[i],
					Pubkey:   pubkeys[i],
				}
			}
		}
	}
}

func (c *Custodian) pegOut(ctx context.Context, exporter xdr.AccountId, asset xdr.Asset, amount int64, tempID xdr.AccountId, seqnum xdr.SequenceNumber) error {
	tx, err := buildPegOutTx(c.AccountID.Address(), exporter.Address(), tempID.Address(), c.network, asset, amount, seqnum)
	if err != nil {
		return errors.Wrap(err, "building peg-out tx")
	}
	_, err = stellar.SignAndSubmitTx(c.hclient, tx, c.seed)
	return errors.Wrap(err, "submitting peg-out tx")
}

func buildPegOutTx(custodianAddr, exporterAddr, tempAddr, network string, asset xdr.Asset, amount int64, seqnum xdr.SequenceNumber) (*b.TransactionBuilder, error) {
	var paymentOp b.PaymentBuilder
	switch asset.Type {
	case xdr.AssetTypeAssetTypeNative:
		lumens := xlm.Amount(amount)
		paymentOp = b.Payment(
			b.SourceAccount{AddressOrSeed: custodianAddr},
			b.Destination{AddressOrSeed: exporterAddr},
			b.NativeAmount{Amount: lumens.HorizonString()},
		)
	case xdr.AssetTypeAssetTypeCreditAlphanum4:
		paymentOp = b.Payment(
			b.SourceAccount{AddressOrSeed: custodianAddr},
			b.Destination{AddressOrSeed: exporterAddr},
			b.CreditAmount{
				Code:   string(asset.AlphaNum4.AssetCode[:]),
				Issuer: asset.AlphaNum4.Issuer.Address(),
				Amount: strconv.FormatInt(amount, 10),
			},
		)
	case xdr.AssetTypeAssetTypeCreditAlphanum12:
		paymentOp = b.Payment(
			b.SourceAccount{AddressOrSeed: custodianAddr},
			b.Destination{AddressOrSeed: exporterAddr},
			b.CreditAmount{
				Code:   string(asset.AlphaNum12.AssetCode[:]),
				Issuer: asset.AlphaNum12.Issuer.Address(),
				Amount: strconv.FormatInt(amount, 10),
			},
		)
	}
	mergeAccountOp := b.AccountMerge(
		b.Destination{AddressOrSeed: exporterAddr},
	)
	return b.Transaction(
		b.Network{Passphrase: network},
		b.SourceAccount{AddressOrSeed: tempAddr},
		b.Sequence{Sequence: uint64(seqnum) + 1},
		b.BaseFee{Amount: baseFee},
		mergeAccountOp,
		paymentOp,
	)
}

// createTempAccount builds and submits a transaction to the Stellar
// network that creates a new temporary account. It returns the
// temporary account keypair and sequence number.
func createTempAccount(hclient horizon.ClientInterface, kp *keypair.Full) (*keypair.Full, xdr.SequenceNumber, error) {
	root, err := hclient.Root()
	if err != nil {
		return nil, 0, errors.Wrap(err, "getting Horizon root")
	}
	tempKP, err := keypair.Random()
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
			b.Destination{AddressOrSeed: tempKP.Address()},
		),
	)
	if err != nil {
		return nil, 0, errors.Wrap(err, "building temp account creation tx")
	}
	_, err = stellar.SignAndSubmitTx(hclient, tx, kp.Seed())
	if err != nil {
		return nil, 0, errors.Wrapf(err, "submitting temp account creation tx")
	}
	seqnum, err := hclient.SequenceForAccount(tempKP.Address())
	if err != nil {
		return nil, 0, errors.Wrapf(err, "getting sequence number for temp account %s", tempKP.Address())
	}
	return tempKP, seqnum, nil
}

// SubmitPreExportTx builds and submits the two pre-export transactions
// to the Stellar network.
// The first transaction creates a new temporary account.
// The second transaction sets the signer on the temporary account
// to be a preauth transaction, which merges the account and pays
// out the pegged-out funds.
// The function returns the temporary account address and sequence number.
func SubmitPreExportTx(hclient horizon.ClientInterface, kp *keypair.Full, custodian string, asset xdr.Asset, amount int64) (string, xdr.SequenceNumber, error) {
	root, err := hclient.Root()
	if err != nil {
		return "", 0, errors.Wrap(err, "getting Horizon root")
	}

	tempKP, seqnum, err := createTempAccount(hclient, kp)
	if err != nil {
		return "", 0, errors.Wrap(err, "creating temp account")
	}

	preauthTx, err := buildPegOutTx(custodian, kp.Address(), tempKP.Address(), root.NetworkPassphrase, asset, amount, seqnum)
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
			b.SourceAccount{AddressOrSeed: tempKP.Address()},
			b.MasterWeight(0),
			b.SetThresholds(1, 1, 1),
			b.AddSigner(hashStr, 1),
		),
	)
	if err != nil {
		return "", 0, errors.Wrap(err, "building pre-export tx")
	}
	_, err = stellar.SignAndSubmitTx(hclient, tx, kp.Seed(), tempKP.Seed())
	if err != nil {
		return "", 0, errors.Wrap(err, "pre-exporttx")
	}
	return tempKP.Address(), seqnum, nil
}

// BuildExportTx builds a txvm retirement tx for an asset issued
// onto slidechain. It will retire `amount` of the asset, and the
// remaining input will be output back to the original account.
func BuildExportTx(ctx context.Context, asset xdr.Asset, exportAmt, inputAmt int64, tempAddr string, anchor []byte, prv ed25519.PrivateKey, seqnum xdr.SequenceNumber) (*bc.Tx, error) {
	if inputAmt < exportAmt {
		return nil, fmt.Errorf("cannot have input amount %d less than export amount %d", inputAmt, exportAmt)
	}
	assetXDR, err := asset.MarshalBinary()
	if err != nil {
		return nil, err
	}
	assetID := bc.NewHash(txvm.AssetID(importIssuanceSeed[:], assetXDR))
	var rawSeed [32]byte
	copy(rawSeed[:], prv)
	kp, err := keypair.FromRawSeed(rawSeed)
	if err != nil {
		return nil, err
	}
	pubkey := prv.Public().(ed25519.PublicKey)

	// We first split off the difference between inputAmt and exportAmt.
	// Then, we split off the zero-value for finalize, creating the retire anchor.
	retireAnchor1 := txvm.VMHash("Split2", anchor)
	retireAnchor := txvm.VMHash("Split1", retireAnchor1[:])
	ref := pegOut{
		AssetXDR: assetXDR,
		TempAddr: tempAddr,
		Seqnum:   int64(seqnum),
		Exporter: kp.Address(),
		Amount:   exportAmt,
		Anchor:   retireAnchor[:],
		Pubkey:   pubkey,
	}
	refdata, err := json.Marshal(ref)
	if err != nil {
		return nil, errors.Wrap(err, "marshaling reference data")
	}
	b := new(txvmutil.Builder)
	b.PushdataBytes(refdata)                                                                                             // con stack: json
	b.Op(op.Put)                                                                                                         // arg stack: json
	standard.SpendMultisig(b, 1, []ed25519.PublicKey{pubkey}, inputAmt, assetID, anchor, standard.PayToMultisigSeed1[:]) // arg stack: inputval, sigcheck
	b.Op(op.Get).Op(op.Get)                                                                                              // con stack: sigcheck, inputval
	b.PushdataInt64(exportAmt).Op(op.Split)                                                                              // con stack: sigcheck, changeval, retireval
	b.PushdataInt64(1).Op(op.Roll)                                                                                       // con stack: sigcheck, retireval, changeval
	if inputAmt != exportAmt {
		b.PushdataBytes(nil).Op(op.Put)                                                    // con stack: sigcheck, retireval, changeval; arg stack: refdata
		b.Op(op.Put)                                                                       // con stack: sigcheck, retireval; arg stack: refdata, changeval
		b.Tuple(func(tup *txvmutil.TupleBuilder) { tup.PushdataBytes(pubkey) }).Op(op.Put) // con stack: sigcheck, retireval; arg stack: refdata, changeval, {pubkey}
		b.PushdataInt64(1).Op(op.Put)                                                      // con stack: sigcheck, retireval; arg stack: refdata, changeval, {pubkey}, 1
		b.PushdataBytes(standard.PayToMultisigProg1).Op(op.Contract).Op(op.Call)           // con stack: sigcheck, retireval
	} else {
		b.Op(op.Drop) // con stack: sigcheck, retireval
	}
	// con stack: sigcheck, retireval
	b.PushdataBytes(refdata).Op(op.Put)                                                // con stack: sigcheck, retireval; arg stack: json
	b.PushdataInt64(0).Op(op.Split).PushdataInt64(1).Op(op.Roll).Op(op.Put)            // con stack: sigcheck, zeroval; arg stack: json, retireval
	b.Tuple(func(tup *txvmutil.TupleBuilder) { tup.PushdataBytes(pubkey) }).Op(op.Put) // con stack: sigcheck, zeroval; arg stack: json, retireval, {pubkey}
	b.PushdataBytes(exportContract1Prog)                                               // con stack: sigchecker, zeroval, exportContract; arg stack: json, retireval, {pubkey}
	b.Op(op.Contract).Op(op.Call)                                                      // con stack: sigchecker, zeroval
	b.Op(op.Finalize)                                                                  // con stack: sigchecker
	prog1 := b.Build()
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
	var runlimit int64
	tx, err := bc.NewTx(prog2, 3, math.MaxInt64, txvm.GetRunlimit(&runlimit))
	if err != nil {
		return nil, errors.Wrap(err, "making export tx")
	}
	tx.Runlimit = math.MaxInt64 - runlimit
	return tx, nil
}
