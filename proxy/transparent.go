package proxy

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"

	log "github.com/sirupsen/logrus"
)

const (
	// TEST ONLY: usuń wymuszenie w handleConn,
	// gdy będziesz chciał używać hosta odczytanego z SNI.
	transparentTestUpstream = "onet.pl:443"

	maxClientHelloSize = 1 << 20
	maxTLSRecordSize   = 18432
)

type transparentEntry struct {
	proxy *Proxy

	mu       sync.Mutex
	listener net.Listener
}

func newTransparentEntry(proxy *Proxy) *transparentEntry {
	return &transparentEntry{proxy: proxy}
}

func (e *transparentEntry) start(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("transparent listen %s: %w", addr, err)
	}

	e.mu.Lock()
	e.listener = ln
	e.mu.Unlock()

	log.Infof("Transparent proxy listening at %s", addr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			e.mu.Lock()
			closed := e.listener == nil
			e.mu.Unlock()

			if closed {
				return nil
			}
			return fmt.Errorf("transparent accept: %w", err)
		}

		go e.handleConn(conn)
	}
}

func (e *transparentEntry) close() error {
	e.mu.Lock()
	ln := e.listener
	e.listener = nil
	e.mu.Unlock()

	if ln == nil {
		return nil
	}
	return ln.Close()
}

func (e *transparentEntry) handleConn(conn net.Conn) {
	// Odczytaj SNI, ale zachowaj wszystkie pobrane bajty,
	// aby istniejący TLS handshake mógł odczytać je ponownie.
	sni, replayedConn, err := readClientHelloSNI(conn)
	if err != nil {
		log.Errorf("transparent: read client SNI: %v", err)
		_ = conn.Close()
		return
	}
	// defer replayedConn.Close()
	handedOff := false

	defer func() {
		if !handedOff {
			_ = replayedConn.Close()
		}
	}()

	log.Infof("Transparent connection: SNI=%s", sni)

	clientConn := newWrapClientConn(replayedConn, e.proxy)
	connCtx := newConnContext(clientConn, e.proxy)
	clientConn.connCtx = connCtx

	for _, addon := range e.proxy.Addons {
		addon.ClientConnected(connCtx.ClientConn)
	}

	connCtx.ClientConn.Tls = true
	connCtx.Intercept = true

	// Normalnie upstream wynika z SNI.
	upstreamHost := net.JoinHostPort(sni, "443")

	// TEST ONLY: wymuś Onet, zachowując oryginalne SNI
	// dla certyfikatu prezentowanego klientowi.
	// upstreamHost = transparentTestUpstream

	targetURL := &url.URL{
		Scheme: "https",
		Host:   upstreamHost,
	}

	ctx := context.WithValue(
		context.Background(),
		connContextKey,
		connCtx,
	)

	req := (&http.Request{
		Method: "GET",
		URL:    targetURL,
		Host:   upstreamHost,
		Header: make(http.Header),
	}).WithContext(ctx)

	// Istniejąca implementacja MITM.
	// Nie modyfikujemy attacker.go.
	log.Infof("transparent: SNI=%q, forwarding to onet.pl:443", sni)
	handedOff = true
	e.proxy.attacker.httpsLazyAttack(ctx, clientConn, req)

	log.Infof("transparent: httpsLazyAttack returned, SNI=%q", sni)
}

// replayConn odtwarza bajty ClientHello przed dalszym czytaniem
// z oryginalnego połączenia TCP.
type replayConn struct {
	net.Conn
	reader io.Reader
}

func (c *replayConn) Read(p []byte) (int, error) {
	return c.reader.Read(p)
}

// readClientHelloSNI odczytuje komplet wiadomości ClientHello
// i zwraca połączenie, z którego można odczytać te same bajty ponownie.
func readClientHelloSNI(conn net.Conn) (string, net.Conn, error) {
	var raw []byte
	var handshake []byte

	for {
		var header [5]byte
		if _, err := io.ReadFull(conn, header[:]); err != nil {
			return "", nil, fmt.Errorf("read TLS record header: %w", err)
		}

		// TLS handshake record.
		if header[0] != 22 {
			return "", nil, fmt.Errorf(
				"expected TLS handshake record, got type %d",
				header[0],
			)
		}

		recordLen := int(binary.BigEndian.Uint16(header[3:5]))
		if recordLen == 0 || recordLen > maxTLSRecordSize {
			return "", nil, fmt.Errorf("invalid TLS record length: %d", recordLen)
		}

		payload := make([]byte, recordLen)
		if _, err := io.ReadFull(conn, payload); err != nil {
			return "", nil, fmt.Errorf("read TLS record: %w", err)
		}

		raw = append(raw, header[:]...)
		raw = append(raw, payload...)
		handshake = append(handshake, payload...)

		if len(raw) > maxClientHelloSize {
			return "", nil, fmt.Errorf("ClientHello exceeds size limit")
		}

		if len(handshake) < 4 {
			continue
		}

		if handshake[0] != 1 {
			return "", nil, fmt.Errorf(
				"expected ClientHello handshake, got type %d",
				handshake[0],
			)
		}

		helloLen := 4 +
			(int(handshake[1]) << 16) +
			(int(handshake[2]) << 8) +
			int(handshake[3])

		if helloLen > maxClientHelloSize {
			return "", nil, fmt.Errorf("ClientHello exceeds size limit")
		}

		if len(handshake) < helloLen {
			continue
		}

		sni, err := parseClientHelloSNI(handshake[:helloLen])
		if err != nil {
			return "", nil, err
		}

		replayed := &replayConn{
			Conn:   conn,
			reader: io.MultiReader(bytes.NewReader(raw), conn),
		}

		return sni, replayed, nil
	}
}

func parseClientHelloSNI(message []byte) (string, error) {
	if len(message) < 4 || message[0] != 1 {
		return "", fmt.Errorf("invalid ClientHello")
	}

	bodyLen := 4 +
		(int(message[1]) << 16) +
		(int(message[2]) << 8) +
		int(message[3])

	if bodyLen > len(message) || bodyLen < 4+34 {
		return "", fmt.Errorf("invalid ClientHello length")
	}

	body := message[4:bodyLen]
	pos := 34 // legacy_version (2) + random (32)

	if pos >= len(body) {
		return "", fmt.Errorf("missing session ID")
	}

	sessionLen := int(body[pos])
	pos++
	if pos+sessionLen+2 > len(body) {
		return "", fmt.Errorf("invalid session ID")
	}
	pos += sessionLen

	cipherLen := int(binary.BigEndian.Uint16(body[pos : pos+2]))
	pos += 2
	if cipherLen == 0 || pos+cipherLen+1 > len(body) {
		return "", fmt.Errorf("invalid cipher suites")
	}
	pos += cipherLen

	compressionLen := int(body[pos])
	pos++
	if pos+compressionLen > len(body) {
		return "", fmt.Errorf("invalid compression methods")
	}
	pos += compressionLen

	if pos == len(body) {
		return "", fmt.Errorf("ClientHello has no SNI extension")
	}
	if pos+2 > len(body) {
		return "", fmt.Errorf("missing extensions length")
	}

	extensionsLen := int(binary.BigEndian.Uint16(body[pos : pos+2]))
	pos += 2
	if pos+extensionsLen != len(body) {
		return "", fmt.Errorf("invalid extensions length")
	}

	end := pos + extensionsLen

	for pos+4 <= end {
		extType := binary.BigEndian.Uint16(body[pos : pos+2])
		extLen := int(binary.BigEndian.Uint16(body[pos+2 : pos+4]))
		pos += 4

		if pos+extLen > end {
			return "", fmt.Errorf("invalid TLS extension length")
		}

		if extType == 0 {
			sni, err := parseSNIExtension(body[pos : pos+extLen])
			if err != nil {
				return "", err
			}
			return sni, nil
		}

		pos += extLen
	}

	return "", fmt.Errorf("SNI extension not found")
}

func parseSNIExtension(extension []byte) (string, error) {
	if len(extension) < 2 {
		return "", fmt.Errorf("invalid SNI extension")
	}

	listLen := int(binary.BigEndian.Uint16(extension[:2]))
	if listLen != len(extension)-2 {
		return "", fmt.Errorf("invalid SNI list length")
	}

	list := extension[2:]

	for pos := 0; pos < len(list); {
		if pos+3 > len(list) {
			return "", fmt.Errorf("invalid SNI entry")
		}

		nameType := list[pos]
		nameLen := int(binary.BigEndian.Uint16(list[pos+1 : pos+3]))
		pos += 3

		if pos+nameLen > len(list) {
			return "", fmt.Errorf("invalid SNI hostname length")
		}

		if nameType == 0 {
			host := string(list[pos : pos+nameLen])
			if host == "" || strings.ContainsAny(host, "\x00\r\n") {
				return "", fmt.Errorf("invalid SNI hostname")
			}
			return host, nil
		}

		pos += nameLen
	}

	return "", fmt.Errorf("DNS hostname not found in SNI")
}
