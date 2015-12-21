// +build !go1.6

package main

import (
	"net/http"

	"golang.org/x/net/http2"
)

func http2ConfigureServer(s *http.Server) error {
	return http2.ConfigureServer(s, nil)
}

func http2ConfigureTransport(_ *http.Transport) error {
	return nil
}
