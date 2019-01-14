package net

import (
	"net"
)

// IsLoopback returns if and only if the provided address
// is a loopback address.
func IsLoopback(addr string) bool {
	a, err := net.ResolveTCPAddr("tcp", addr)
	return err == nil && a.IP.IsLoopback()
}
