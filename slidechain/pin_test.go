package slidechain

import (
	"context"
	"database/sql"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/chain/txvm/protocol"
	"github.com/chain/txvm/protocol/bc"
)

func TestPins(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	withTestServer(ctx, t, func(ctx context.Context, db *sql.DB, s *submitter, _ *httptest.Server, chain *protocol.Chain) {
		c := &Custodian{
			S:  s,
			DB: db,
		}

		pin1ctx, pin1cancel := context.WithCancel(ctx)
		defer pin1cancel()

		pin1ch := make(chan *bc.Block)
		go c.RunPin(pin1ctx, "pin1", func(_ context.Context, block *bc.Block) error {
			t.Logf("running pin1")
			pin1ch <- block
			return nil
		})

		pin2ch := make(chan *bc.Block)
		go c.RunPin(ctx, "pin2", func(_ context.Context, block *bc.Block) error {
			t.Logf("running pin2")
			pin2ch <- block
			return nil
		})

		blockTime := time.Now()

		bb := protocol.NewBlockBuilder()
		err := bb.Start(chain.State(), bc.Millis(blockTime))
		if err != nil {
			t.Fatal(err)
		}
		u, snap, err := bb.Build()
		if err != nil {
			t.Fatal(err)
		}
		block2 := &bc.Block{UnsignedBlock: u}
		err = s.commitBlock(ctx, block2, snap)
		if err != nil {
			t.Fatal(err)
		}

		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())

		case b1 := <-pin1ch:
			if !reflect.DeepEqual(block2, b1) {
				t.Error("block mismatch on pin 1")
			}
		}

		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())

		case b2 := <-pin2ch:
			if !reflect.DeepEqual(block2, b2) {
				t.Error("block mismatch on pin 2")
			}
		}

		pin1cancel()

		bb = protocol.NewBlockBuilder()
		err = bb.Start(s.chain.State(), bc.Millis(blockTime))
		if err != nil {
			t.Fatal(err)
		}
		u, snap, err = bb.Build()
		if err != nil {
			t.Fatal(err)
		}
		block3 := &bc.Block{UnsignedBlock: u}
		err = s.commitBlock(ctx, block3, snap)
		if err != nil {
			t.Fatal(err)
		}

		select {
		case <-pin1ch:
			t.Fatal("did not expect to see another block from pin1 (yet)")

		default:
		}

		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())

		case b2 := <-pin2ch:
			if !reflect.DeepEqual(block3, b2) {
				t.Error("block mismatch on pin 2")
			}
		}

		pin1ach := make(chan *bc.Block)
		go c.RunPin(ctx, "pin1", func(_ context.Context, block *bc.Block) error {
			t.Logf("running pin1a")
			pin1ach <- block
			return nil
		})

		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())

		case b1 := <-pin1ach:
			if !reflect.DeepEqual(block3, b1) {
				t.Error("block mismatch on pin 1")
			}
		}

		bb = protocol.NewBlockBuilder()
		err = bb.Start(s.chain.State(), bc.Millis(blockTime))
		if err != nil {
			t.Fatal(err)
		}
		u, snap, err = bb.Build()
		if err != nil {
			t.Fatal(err)
		}
		block4 := &bc.Block{UnsignedBlock: u}
		err = s.commitBlock(ctx, block4, snap)
		if err != nil {
			t.Fatal(err)
		}

		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())

		case b1 := <-pin1ach:
			if !reflect.DeepEqual(block4, b1) {
				t.Error("block mismatch on pin 1")
			}
		}

		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())

		case b2 := <-pin2ch:
			if !reflect.DeepEqual(block4, b2) {
				t.Error("block mismatch on pin 2")
			}
		}
	})
}
