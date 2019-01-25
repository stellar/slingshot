package slidechain

import (
	"context"
	"fmt"

	"github.com/chain/txvm/errors"
	"github.com/stellar/go/xdr"
)

// RecordPegs records a peg-in transaction in the database.
func (c *Custodian) RecordPegs(ctx context.Context, tx xdr.Transaction, recipientPubkey []byte, expMS int64) error {
	for _, op := range tx.Operations {
		if op.Body.Type != xdr.OperationTypePayment {
			continue
		}
		payment := op.Body.PaymentOp
		if !payment.Destination.Equals(c.AccountID) {
			continue
		}

		// This operation is a payment to the custodian account - i.e., a peg.
		// We record it in the db.
		const q = `INSERT INTO pegs 
					(nonce_hash, amount, asset_xdr, recipient_pubkey, expiration_ms)
					VALUES ($1, $2, $3, $4, $5)`
		assetXDR, err := payment.Asset.MarshalBinary()
		if err != nil {
			return errors.Wrap(err, fmt.Sprintf("marshaling asset to XDR %s", payment.Asset.String()))
		}
		nonceHash := UniqueNonceHash(c.InitBlockHash.Bytes(), expMS)
		_, err = c.DB.ExecContext(ctx, q, nonceHash[:], payment.Amount, assetXDR, recipientPubkey, expMS)
		if err != nil {
			return errors.Wrap(err, "inserting peg-in tx")
		}
	}
	return nil
}
