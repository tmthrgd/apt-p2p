// Copyright 2015 Tom Thorogood. All rights reserved.
// Use of this source code is governed by a
// Modified BSD License license that can be found in
// the LICENSE file.

package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"os"
	"time"

	"github.com/tmthrgd/apt-p2p/hash"
)

func generatePeerCertificate(persistent bool) (cert []byte, priv *ecdsa.PrivateKey, err error) {
	name, err := os.Hostname()
	if err != nil {
		return
	}

	var curve elliptic.Curve
	var sigAlg x509.SignatureAlgorithm

	if persistent {
		curve = elliptic.P384()
		sigAlg = x509.ECDSAWithSHA384
	} else {
		curve = elliptic.P256()
		sigAlg = x509.ECDSAWithSHA256
	}

	cert, privKey, err := generateCertificate(&generateCertConfig{
		Subject: pkix.Name{
			CommonName: name + "." + dnssdDefaultDomain,
		},
		DNSNames: []string{name + "." + dnssdDefaultDomain, name},

		Curve: curve,

		ValidForever: persistent,

		SignatureAlgorithm: sigAlg,

		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	})
	if err != nil {
		return
	}

	priv, ok := privKey.(*ecdsa.PrivateKey)
	if !ok {
		panic("generateCertificate did not produce ECDSA key")
	}

	return
}

type generateCertConfig struct {
	_ struct{} // to prevent unkeyed literals

	Rand io.Reader

	SerialNumber *big.Int
	Subject      pkix.Name
	DNSNames     []string
	IPAddresses  []net.IP

	ValidFrom      time.Time
	ValidTo        time.Time
	ValidFor       time.Duration
	ValidForYears  int
	ValidForMonths int
	ValidForDays   int
	ValidForever   bool

	PrivateKey crypto.PrivateKey
	Curve      elliptic.Curve
	Bits       int

	SignatureAlgorithm x509.SignatureAlgorithm

	Issuer           *x509.Certificate
	IssuerPrivateKey crypto.PrivateKey

	KeyUsage    x509.KeyUsage
	ExtKeyUsage []x509.ExtKeyUsage

	IsCA bool
}

func generateCertificate(config *generateCertConfig) (cert []byte, priv crypto.PrivateKey, err error) {
	if config == nil {
		config = new(generateCertConfig)
	}

	c := *config

	if c.Rand == nil {
		c.Rand = rand.Reader
	}

	if priv = c.PrivateKey; priv == nil {
		if c.Curve != nil {
			priv, err = ecdsa.GenerateKey(c.Curve, c.Rand)
		} else {
			if c.Bits == 0 {
				c.Bits = 2048
			}

			priv, err = rsa.GenerateKey(c.Rand, c.Bits)
		}

		if err != nil {
			return
		}
	}

	var pub crypto.PublicKey

	switch priv := priv.(type) {
	case *rsa.PrivateKey:
		pub = &priv.PublicKey
	case *ecdsa.PrivateKey:
		pub = &priv.PublicKey
	default:
		return nil, nil, errKeyTypeUnsupported
	}

	if c.SerialNumber == nil {
		if c.SerialNumber, err = rand.Int(c.Rand, new(big.Int).Lsh(big.NewInt(1), 128)); err != nil {
			return
		}
	}

	if c.ValidFrom.IsZero() {
		notBefore := time.Now().UTC()
		c.ValidFrom = time.Date(notBefore.Year(), notBefore.Month(), notBefore.Day(), 0, 0, 0, 0, notBefore.Location())
	}

	if c.ValidTo.IsZero() {
		if c.ValidForever {
			notAfter := c.ValidFrom.AddDate(10, 0, 0).UTC()

			year := notAfter.Year()
			if year%10 != 0 {
				year = (year - year%10) + 10
			}

			c.ValidTo = time.Date(year, notAfter.Month(), notAfter.Day(), 23, 59, 59, 0, notAfter.Location())
		} else if c.ValidFor != 0 {
			c.ValidTo = c.ValidFrom.Add(c.ValidFor)
		} else {
			if c.ValidForYears == 0 && c.ValidForMonths == 0 && c.ValidForDays == 0 {
				c.ValidForMonths = 6
			}

			notAfter := c.ValidFrom.AddDate(c.ValidForYears, c.ValidForMonths, c.ValidForDays).UTC()
			c.ValidTo = time.Date(notAfter.Year(), notAfter.Month(), notAfter.Day(), 23, 59, 59, 0, notAfter.Location())
		}
	}

	if c.SignatureAlgorithm == x509.UnknownSignatureAlgorithm {
		switch priv.(type) {
		case *rsa.PrivateKey:
			c.SignatureAlgorithm = x509.SHA256WithRSA
		case *ecdsa.PrivateKey:
			c.SignatureAlgorithm = x509.ECDSAWithSHA256
		default:
			err = errKeyTypeUnsupported
			return
		}
	}

	if c.KeyUsage == 0 {
		if c.IsCA {
			c.KeyUsage = x509.KeyUsageCertSign
		} else {
			c.KeyUsage = x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature
		}
	}

	if c.ExtKeyUsage == nil && !c.IsCA {
		c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}

	template := x509.Certificate{
		SignatureAlgorithm: c.SignatureAlgorithm,

		SerialNumber: c.SerialNumber,
		Subject:      c.Subject,
		NotBefore:    c.ValidFrom,
		NotAfter:     c.ValidTo,
		KeyUsage:     c.KeyUsage,

		ExtKeyUsage: c.ExtKeyUsage,

		BasicConstraintsValid: true,
		IsCA: c.IsCA,

		DNSNames:    c.DNSNames,
		IPAddresses: c.IPAddresses,
	}

	if c.Issuer != nil {
		template.Issuer = c.Issuer.Subject
	} else {
		c.Issuer = &template
		c.IssuerPrivateKey = priv
	}

	cert, err = x509.CreateCertificate(c.Rand, &template, c.Issuer, pub, c.IssuerPrivateKey)
	return
}

func generateCertificateAndParse(config *generateCertConfig) (cert *x509.Certificate, priv crypto.PrivateKey, err error) {
	certData, priv, err := generateCertificate(config)
	if err != nil {
		return
	}

	cert, err = x509.ParseCertificate(certData)
	return
}

func spkiHashForCertificate(pubKey crypto.PublicKey, alg crypto.Hash) (*hash.Hash, error) {
	rawSubjectPublicKeyInfo, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return nil, err
	}

	return hash.New(rawSubjectPublicKeyInfo, alg)
}
