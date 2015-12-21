// +build go1.6

package main

import (
	"net/http"

	"golang.org/x/net/http2"
)

func http2ConfigureServer(_ *http.Server) error {
	return nil
}

func http2ConfigureTransport(t1 *http.Transport) error {
	return http2.ConfigureTransport(t1)
}
