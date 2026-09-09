package main

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

type DefaultBasicAuth struct {
	auth map[string]string
}

// Create a new BasicAuth instance from a user:password string
func NewDefaultBasicAuth(auth string) (*DefaultBasicAuth, error) {
	basicAuth := &DefaultBasicAuth{
		auth: make(map[string]string),
	}
	for _, e := range strings.Split(auth, "|") {
		n := strings.SplitN(e, ":", 2)
		if len(n) != 2 {
			return nil, fmt.Errorf("invalid proxy auth format: %s, expected user:pass", e)
		}
		if n[0] == "" {
			return nil, fmt.Errorf("invalid proxy auth format: %s, username cannot be empty", e)
		}
		basicAuth.auth[n[0]] = n[1]
	}
	return basicAuth, nil
}

// Validate proxy authentication
func (b *DefaultBasicAuth) EntryAuth(res http.ResponseWriter, req *http.Request) (bool, error) {
	get := req.Header.Get("Proxy-Authorization")
	if get == "" {
		return false, errors.New("missing authentication")
	}
	ret := b.parseRequestAuth(get)
	if !ret {
		return false, errors.New("invalid credentials")
	}
	return true, nil
}

// Parse and verify the Proxy-Authorization header
func (b *DefaultBasicAuth) parseRequestAuth(proxyAuth string) bool {
	if !strings.HasPrefix(proxyAuth, "Basic ") {
		return false
	}
	encodedAuth := strings.TrimPrefix(proxyAuth, "Basic ")
	decodedAuth, err := base64.StdEncoding.DecodeString(encodedAuth)
	if err != nil {
		return false
	}

	n := strings.SplitN(string(decodedAuth), ":", 2)
	if len(n) < 2 {
		return false
	}
	if s, ok := b.auth[n[0]]; !ok || s != n[1] {
		return false
	}
	return true
}
