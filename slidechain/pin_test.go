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
		pin1done := make(chan struct{})
		go func() {
			c.RunPin(pin1ctx, "pin1", func(_ context.Context, block *bc.Block) error {
				pin1ch <- block
				return nil
			})
			close(pin1done)
		}()

		pin2ch := make(chan *bc.Block)
		go c.RunPin(ctx, "pin2", func(_ context.Context, block *bc.Block) error {
			pin2ch <- block
			return nil
		})

		blockTime := time.Now().Add(time.Millisecond)
		time.Sleep(time.Until(blockTime))

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

		// Read and discard initial block from both pin channels.
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())

		case b1 := <-pin1ch:
			if b1.Height != 1 {
				t.Fatalf("got block height %d from pin1, want 1", b1.Height)
			}
			t.Logf("pin1: block %d", b1.Height)
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())

		case b2 := <-pin2ch:
			if b2.Height != 1 {
				t.Fatalf("got block height %d from pin1, want 1", b2.Height)
			}
			t.Logf("pin2: block %d", b2.Height)
		}

		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())

		case b1 := <-pin1ch:
			if !reflect.DeepEqual(block2, b1) {
				t.Errorf("block mismatch on pin 1 (got height %d, want 2)", b1.Height)
			}
			t.Logf("pin1: block %d", b1.Height)
		}

		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())

		case b2 := <-pin2ch:
			if !reflect.DeepEqual(block2, b2) {
				t.Errorf("block mismatch on pin 2 (got height %d, want 2)", b2.Height)
			}
			t.Logf("pin2: block %d", b2.Height)
		}

		pin1cancel()
		<-pin1done

		blockTime = blockTime.Add(time.Millisecond)
		time.Sleep(time.Until(blockTime))

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
				t.Errorf("block mismatch on pin 2 (got height %d, want 3)", b2.Height)
			}
			t.Logf("pin2: block %d", b2.Height)
		}

		pin1ach := make(chan *bc.Block)
		go c.RunPin(ctx, "pin1", func(_ context.Context, block *bc.Block) error {
			pin1ach <- block
			return nil
		})

		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())

		case b1 := <-pin1ach:
			if !reflect.DeepEqual(block3, b1) {
				t.Errorf("block mismatch on pin 1 (got height %d, want 3)", b1.Height)
			}
			t.Logf("pin1: block %d", b1.Height)
		}

		blockTime = blockTime.Add(time.Millisecond)
		time.Sleep(time.Until(blockTime))

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
				t.Errorf("block mismatch on pin 1 (got height %d, want 4)", b1.Height)
			}
			t.Logf("pin1: block %d", b1.Height)
		}

		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())

		case b2 := <-pin2ch:
			if !reflect.DeepEqual(block4, b2) {
				t.Errorf("block mismatch on pin 2 (got height %d, want 4)", b2.Height)
			}
			t.Logf("pin2: block %d", b2.Height)
		}
	})
}
