package main

import (
	"io/ioutil"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/bobg/multichan"
	"github.com/chain/txvm/errors"
	"github.com/chain/txvm/protocol"
	"github.com/chain/txvm/protocol/bc"
	"github.com/golang/protobuf/proto"
)

// TODO: make this configurable.
var blockInterval = 5 * time.Second

type submitter struct {
	// Protects bb.
	bbmu sync.Mutex

	// Normally nil. Once a tx is submitted, this is set to a new block
	// builder and a timer set. Other txs that arrive during that
	// interval are added to the block a-building. When the timer fires,
	// the block is added to the blockchain and this field is set back to nil.
	//
	// This is the only way that blocks are added to the chain.
	bb *protocol.BlockBuilder

	// New blocks are written here.
	// Anything monitoring the blockchain can create a reader and consume them.
	// (Really, what we want here is the Sequence "pin" mechanism.)
	w *multichan.W
}

func (s *submitter) submitTx(tx bc.RawTx) error {
	s.bbmu.Lock()
	defer s.bbmu.Unlock()

	if s.bb == nil {
		s.bb = protocol.NewBlockBuilder()
		nextBlockTime := time.Now().Add(blockInterval)

		st := chain.State()
		if st.Header == nil {
			err = st.ApplyBlockHeader(initialBlock.BlockHeader)
			if err != nil {
				return errors.Wrap(err, "initializing empty state")
			}
		}

		err := s.bb.Start(chain.State(), bc.Millis(nextBlockTime))
		if err != nil {
			return errors.Wrap(err, "starting a new tx pool")
		}
		log.Printf("starting new block, will commit at %s", nextBlockTime)
		time.AfterFunc(blockInterval, func() {
			s.bbmu.Lock()
			defer s.bbmu.Unlock()

			unsignedBlock, newSnapshot, err := s.bb.Build()
			if err != nil {
				return errors.Wrap(err, "building new block")
			}
			b := &bc.Block{UnsignedBlock: unsignedBlock}
			err = chain.CommitAppliedBlock(ctx, b, newSnapshot)
			if err != nil {
				return errors.Wrap(err, "committing new block")
			}

			s.w.Write(b)
			log.Printf("committed block %d with %d transaction(s)", unsignedBlock.Height, len(unsignedBlock.Transactions))
			s.bb = nil
		})
	}

	err = s.bb.AddTx(bc.NewCommitmentsTx(tx))
	if err != nil {
		return errors.Wrap(err, "adding tx to pool")
	}
	log.Printf("added tx %x to the pending block", tx.ID.Bytes())
}

func (s *submitter) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	ctx := req.Context()

	bits, err := ioutil.ReadAll(req.Body)
	if err != nil {
		httpErrf(w, http.StatusInternalServerError, "reading request body: %s", err)
		return
	}

	var rawTx bc.RawTx
	err = proto.Unmarshal(bits, &rawTx)
	if err != nil {
		httpErrf(w, http.StatusBadRequest, "parsing request body: %s", err)
		return
	}

	tx, err := bc.NewTx(rawTx.Program, rawTx.Version, rawTx.Runlimit)
	if err != nil {
		httpErrf(w, http.StatusBadRequest, "building tx: %s", err)
		return
	}

	err = s.submitTx(tx)
	if err != nil {
		httpErrf(w, http.StatusBadRequest, "submitting tx: %s", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
