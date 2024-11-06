package aws_signing_helper

import (
	"net"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

type ttlListener struct {
	l   net.Listener
	ttl int
}

// NewListenerWithTTL wraps a net.Listener and sets the TTL on outgoing packets to the specififed value
func NewListenerWithTTL(l net.Listener, ttl int) net.Listener {
	return &ttlListener{l, ttl}
}

func (w *ttlListener) Accept() (net.Conn, error) {
	c, err := w.l.Accept()
	if err != nil {
		return nil, err
	}
	if c.RemoteAddr().(*net.TCPAddr).IP.To16() != nil && c.RemoteAddr().(*net.TCPAddr).IP.To4() == nil {
		p := ipv6.NewConn(c)
		if err := p.SetHopLimit(w.ttl); err != nil {
			return nil, err
		}
	} else if c.RemoteAddr().(*net.TCPAddr).IP.To4() != nil {
		p := ipv4.NewConn(c)
		if err := p.SetTTL(w.ttl); err != nil {
			return nil, err
		}

	}
	return c, nil
}

func (w *ttlListener) Close() error { return w.l.Close() }

func (w *ttlListener) Addr() net.Addr { return w.l.Addr() }
