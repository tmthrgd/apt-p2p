// +build go1.6

package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"runtime"
)

const hasVerifyCertificate = true

var errNoCertificate = errors.New("apt: tls: no certificate provided")

func tlsConfigServer(config *tls.Config, verify func(*x509.Certificate, x509.VerifyOptions) ([][]*x509.Certificate, error)) *tls.Config {
	config.CipherSuites = append(
		[]uint16{
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		},
		config.CipherSuites...,
	)

	config.VerifyCertificate = verify
	return config
}

func tlsConfigClient(config *tls.Config, verify func(*x509.Certificate, x509.VerifyOptions) ([][]*x509.Certificate, error)) *tls.Config {
	if runtime.GOARCH == "arm" {
		config.CipherSuites = append(
			[]uint16{
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			},
			config.CipherSuites...,
		)
	} else {
		config.CipherSuites = append(config.CipherSuites, tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305, tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305)
	}

	config.VerifyCertificate = verify
	return config
}

func tlsFallbackVerify(_ []*x509.Certificate, _ func(*x509.Certificate, x509.VerifyOptions) ([][]*x509.Certificate, error)) error {
	return nil
}
