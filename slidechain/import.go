package main

import "net/http"

func doImport(w http.ResponseWriter, req *http.Request) {
	// TODO: Check whether the peg described by the args in req is valid.
	// If it is, submit a transaction to the txvm chain issuing a corresponding amount and asset type.
}
