package proxy

import (
	"context"
	"net"
	"net/http"

	log "github.com/sirupsen/logrus"
)

type transparentHTTPEntry struct {
	proxy *Proxy
}

func newTransparentHTTPEntry(proxy *Proxy) *transparentHTTPEntry {
	return &transparentHTTPEntry{proxy: proxy}
}

func (e *transparentHTTPEntry) start(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	log.Infof("Transparent HTTP listener started on %s", addr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			_ = ln.Close()
			return err
		}
		go e.handleConn(conn)
	}
}

func (e *transparentHTTPEntry) handleConn(conn net.Conn) {
	clientConn := newWrapClientConn(conn, e.proxy)
	connCtx := newConnContext(clientConn, e.proxy)
	clientConn.connCtx = connCtx

	for _, addon := range e.proxy.Addons {
		addon.ClientConnected(connCtx.ClientConn)
	}

	// attacker.server takes ownership of this connection.
	// Do not close it here after handing it off.
	e.proxy.attacker.listener.accept(&attackerConn{
		Conn:    clientConn,
		connCtx: connCtx,
	})
}

// Ensure the standard context package remains available for this package's
// context-related implementation if it is extended later.
var _ context.Context
var _ http.Handler
