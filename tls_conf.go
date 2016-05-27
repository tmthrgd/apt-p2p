// +build !verify

package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log"
	"sync"
)

const hasVerifyCertificate = false

var errNoCertificate = errors.New("apt: tls: no certificate provided")

var verifyWarnOnce sync.Once

func tlsConfigServer(config *tls.Config, verify func(*x509.Certificate, x509.VerifyOptions) ([][]*x509.Certificate, error)) *tls.Config {
	if verify == nil {
		return config
	}

	verifyWarnOnce.Do(func() {
		log.Println("** WARNING ** TLS certificates can not be properly verified in go < 1.6")
	})

	config.InsecureSkipVerify = true
	return config
}

var tlsConfigClient = tlsConfigServer

func tlsFallbackVerify(certs []*x509.Certificate, verify func(*x509.Certificate, x509.VerifyOptions) ([][]*x509.Certificate, error)) error {
	if len(certs) == 0 {
		return errNoCertificate
	}

	opts := x509.VerifyOptions{
		Intermediates: x509.NewCertPool(),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}

	for _, cert := range certs[1:] {
		opts.Intermediates.AddCert(cert)
	}

	_, err := verify(certs[0], opts)
	return err
}
