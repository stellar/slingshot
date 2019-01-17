package net

import (
	"fmt"
	"log"
	"net/http"
)

// Errorf replies to an HTTP request with the specified error, also logging it to stderr.
func Errorf(w http.ResponseWriter, code int, msgfmt string, args ...interface{}) {
	http.Error(w, fmt.Sprintf(msgfmt, args...), code)
	log.Printf(msgfmt, args...)
}
