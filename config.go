// Copyright 2015 Tom Thorogood. All rights reserved.
// Use of this source code is governed by a
// Modified BSD License license that can be found in
// the LICENSE file.

package main

type configStruct struct {
	Verbose bool
	Quiet   bool

	Archives     []string
	ArchiveFiles []string

	Trusted map[string]struct {
		SPKI string
	}

	Storage struct {
		Address string

		CertFile string
		KeyFile  string
	}

	Proxy struct {
		Address string

		CertFile string
		KeyFile  string

		GNUTLS2 bool
	}
}

const (
	configDir = "/etc/apt-p2p"

	configPeerCertPath = configDir + "/peer-cert.pem"
	configPeerKeyPath  = configDir + "/peer-key.pem"

	configProxyCertPath = configDir + "/proxy-cert.pem"
	configProxyKeyPath  = configDir + "/proxy-key.pem"
)

var configPath = configDir + "/apt-p2p.conf"

var config configStruct
