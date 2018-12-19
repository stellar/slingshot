package main

import (
	"net/http"
	"strconv"
)

func get(w http.ResponseWriter, req *http.Request) {
	wantStr := req.FormValue("height")
	var (
		want uint64 = 1
		err  error
	)
	if wantStr != "" {
		want, err = strconv.ParseUint(wantStr, 10, 64)
		if err != nil {
			httpErrf(w, http.StatusBadRequest, "parsing height: %s", err)
			return
		}
	}

	height := chain.Height()
	if want == 0 {
		want = height
	}
	if want > height {
		ctx := req.Context()
		waiter := chain.BlockWaiter(want)
		select {
		case <-waiter:
			// ok
		case <-ctx.Done():
			httpErrf(w, http.StatusRequestTimeout, "timed out")
			return
		}
	}

	ctx := req.Context()

	b, err := chain.GetBlock(ctx, want)
	if err != nil {
		httpErrf(w, http.StatusInternalServerError, "getting block %d: %s", want, err)
		return
	}

	bits, err := b.Bytes()
	if err != nil {
		httpErrf(w, http.StatusInternalServerError, "serializing block %d: %s", want, err)
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	_, err = w.Write(bits)
	if err != nil {
		httpErrf(w, http.StatusInternalServerError, "sending response: %s", err)
		return
	}
}
