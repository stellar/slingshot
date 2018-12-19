package main

import (
	"io/ioutil"
	"log"
	"net/http"
	"time"

	"github.com/golang/protobuf/proto"

	"i10r.io/errors"
	"i10r.io/protocol"
	"i10r.io/protocol/bc"
)

func submit(w http.ResponseWriter, req *http.Request) {
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

	bbmu.Lock()
	defer bbmu.Unlock()

	if bb == nil {
		bb = protocol.NewBlockBuilder()
		nextBlockTime := time.Now().Add(blockInterval)

		st := chain.State()
		if st.Header == nil {
			err = st.ApplyBlockHeader(initialBlock.BlockHeader)
			if err != nil {
				httpErrf(w, http.StatusInternalServerError, "initializing empty state: %s", err)
				return
			}
		}

		err := bb.Start(chain.State(), bc.Millis(nextBlockTime))
		if err != nil {
			httpErrf(w, http.StatusInternalServerError, "starting a new tx pool: %s", err)
			return
		}
		log.Printf("starting new block, will commit at %s", nextBlockTime)
		time.AfterFunc(blockInterval, func() {
			bbmu.Lock()
			defer bbmu.Unlock()

			unsignedBlock, newSnapshot, err := bb.Build()
			if err != nil {
				log.Fatal(errors.Wrap(err, "building new block"))
			}
			err = chain.CommitAppliedBlock(ctx, &bc.Block{UnsignedBlock: unsignedBlock}, newSnapshot)
			if err != nil {
				log.Fatal(errors.Wrap(err, "committing new block"))
			}
			log.Printf("committed block %d with %d transaction(s)", unsignedBlock.Height, len(unsignedBlock.Transactions))

			bb = nil
		})
	}

	err = bb.AddTx(bc.NewCommitmentsTx(tx))
	if err != nil {
		httpErrf(w, http.StatusBadRequest, "adding tx to pool: %s", err)
		return
	}
	log.Printf("added tx %x to the pending block", tx.ID.Bytes())
	w.WriteHeader(http.StatusNoContent)
}
