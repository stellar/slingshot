package net

import (
	"context"
	"net"
	"time"
)

// Dialer satisfies the interface pq.Dialer
type Dialer net.Dialer

// DialTimeout acts like Dial but takes a timeout.
func (d *Dialer) DialTimeout(network, addr string, timeout time.Duration) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	conn, err := (*net.Dialer)(d).DialContext(ctx, network, addr)
	return conn, err
}

// Dial connects to the address on the named network.
func (d *Dialer) Dial(network, addr string) (net.Conn, error) {
	return (*net.Dialer)(d).Dial(network, addr)
}
