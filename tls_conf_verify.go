// +build verify

package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
)

const hasVerifyCertificate = true

var errNoCertificate = errors.New("apt: tls: no certificate provided")

func tlsConfigServer(config *tls.Config, verify func(*x509.Certificate, x509.VerifyOptions) ([][]*x509.Certificate, error)) *tls.Config {
	config.VerifyCertificate = verify
	return config
}

func tlsConfigClient(config *tls.Config, verify func(*x509.Certificate, x509.VerifyOptions) ([][]*x509.Certificate, error)) *tls.Config {
	config.VerifyCertificate = verify
	return config
}

func tlsFallbackVerify(_ []*x509.Certificate, _ func(*x509.Certificate, x509.VerifyOptions) ([][]*x509.Certificate, error)) error {
	return nil
}
