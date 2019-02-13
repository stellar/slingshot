package mockhorizon

import (
	"context"
	"sync"

	"github.com/pkg/errors"
	"github.com/stellar/go/clients/horizon"
	"github.com/stellar/go/network"
	"github.com/stellar/go/xdr"
)

// New returns a new instance of the mockhorizon
// struct, which implements horizon.ClientInterface
func New() *Client {
	return &Client{
		mu:        new(sync.Mutex),
		submitted: sync.NewCond(new(sync.Mutex)),
	}
}

// Client is a mock Horizon client, implemengint the Horizon
// client interface.
//
// Our mock implementation assumes that the calling functions
// want to submit transactions and then stream to see if they
// have been successfully included in the ledger.
type Client struct {
	txs       []string
	mu        *sync.Mutex
	submitted *sync.Cond
}

// SubmitTransaction unmarshals the tx envelope string into a xdr.TransactionEnvelope,
// and then adds the transaction to the Client's internal record of transactions to
// "stream".
func (c *Client) SubmitTransaction(txeBase64 string) (horizon.TransactionSuccess, error) {
	var txe xdr.TransactionEnvelope
	err := xdr.SafeUnmarshalBase64(txeBase64, &txe)
	if err != nil {
		return horizon.TransactionSuccess{}, errors.Wrap(err, "submittx: unmarshaling tx envelope")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.txs = append(c.txs, txeBase64)
	c.submitted.Broadcast()
	return horizon.TransactionSuccess{}, nil
}

// StreamTransactions "streams" all transactions that have been submitted to SubmitTransaction.
func (c *Client) StreamTransactions(ctx context.Context, accountID string, cursor *horizon.Cursor, handler horizon.TransactionHandler) error {
	txindex := 0
	ch := make(chan struct{})

	go func() {
		c.submitted.L.Lock()
		defer c.submitted.L.Unlock()
		for {
			if ctx.Err() != nil {
				return
			}
			c.submitted.Wait()
			ch <- struct{}{}
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ch:
		}

		c.mu.Lock()
		txs := c.txs[txindex:]
		c.mu.Unlock()

		for _, tx := range txs {
			htx := horizon.Transaction{EnvelopeXdr: tx}
			handler(htx)
			txindex++
		}
	}
}

// Unimplemented functions
func (*Client) Root() (horizon.Root, error) {
	return horizon.Root{
		NetworkPassphrase: network.TestNetworkPassphrase,
	}, nil
}

func (*Client) HomeDomainForAccount(aid string) (string, error) {
	return "", nil
}

func (*Client) LoadAccount(accountID string) (horizon.Account, error) {
	return horizon.Account{}, nil
}

func (*Client) LoadAccountOffers(accountID string, params ...interface{}) (horizon.OffersPage, error) {
	return horizon.OffersPage{}, nil
}

func (*Client) LoadTradeAggregations(baseAsset, counterAsset horizon.Asset, resolution int64, params ...interface{}) (horizon.TradeAggregationsPage, error) {
	return horizon.TradeAggregationsPage{}, nil
}

func (*Client) LoadTrades(baseAsset, counterAsset horizon.Asset, offerID, resolution int64, params ...interface{}) (horizon.TradesPage, error) {
	return horizon.TradesPage{}, nil
}

func (*Client) LoadAccountMergeAmount(p *horizon.Payment) error {
	return nil
}

func (*Client) LoadMemo(p *horizon.Payment) error {
	return nil
}

func (*Client) LoadOperation(operationID string) (horizon.Payment, error) {
	return horizon.Payment{}, nil
}

func (*Client) LoadOrderBook(selling, buying horizon.Asset, params ...interface{}) (horizon.OrderBookSummary, error) {
	return horizon.OrderBookSummary{}, nil
}

func (*Client) LoadTransaction(transactionID string) (horizon.Transaction, error) {
	return horizon.Transaction{}, nil
}

func (*Client) SequenceForAccount(accountID string) (xdr.SequenceNumber, error) {
	return xdr.SequenceNumber(0), nil
}

func (*Client) StreamLedgers(ctx context.Context, cursor *horizon.Cursor, handler horizon.LedgerHandler) error {
	return nil
}

func (*Client) StreamPayments(ctx context.Context, accountID string, cursor *horizon.Cursor, handler horizon.PaymentHandler) error {
	return nil
}
