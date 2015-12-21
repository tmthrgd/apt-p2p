package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"sync/atomic"

	"github.com/tmthrgd/apt-p2p/hash"
)

var errPeerRemoved = errors.New("dns-sd: peer removed from network")

var (
	peers = struct {
		sync.RWMutex
		m map[string]*aptPeer
	}{m: make(map[string]*aptPeer)}
	peerNamesToHosts = struct {
		sync.RWMutex
		m map[string]string
	}{m: make(map[string]string)}
)

type aptPeer struct {
	_ struct{} // to prevent unkeyed literals

	name string
	host string
	port int

	address string

	spki *hash.Hash

	removed int32 // accessed atomically.

	mutex sync.Mutex // protects tr
	tr    *http.Transport
}

func newPeer(name, host string, port int, spki *hash.Hash) *aptPeer {
	return &aptPeer{
		name: name,
		host: host,
		port: port,

		spki: spki,

		address: net.JoinHostPort(host, strconv.Itoa(port)),
	}
}

func (peer *aptPeer) Add() {
	go func() {
		if err := addedPeer(peer); err != nil {
			log.Println(err)
		}
	}()

	peerNamesToHosts.Lock()
	defer peerNamesToHosts.Unlock()

	peers.Lock()
	defer peers.Unlock()

	peers.m[peer.host] = peer
	peerNamesToHosts.m[peer.name] = peer.host
}

func (peer *aptPeer) Remove() {
	go func() {
		if err := removedPeer(peer); err != nil {
			log.Println(err)
		}
	}()

	atomic.StoreInt32(&peer.removed, 1)

	peerNamesToHosts.Lock()
	defer peerNamesToHosts.Unlock()

	peers.Lock()
	defer peers.Unlock()

	delete(peerNamesToHosts.m, peer.name)
	delete(peers.m, peer.host)
}

func (peer *aptPeer) Removed() bool {
	return atomic.LoadInt32(&peer.removed) != 0
}

func (peer *aptPeer) getVerifyCertificate() func(*x509.Certificate, x509.VerifyOptions) ([][]*x509.Certificate, error) {
	return func(cert *x509.Certificate, opts x509.VerifyOptions) ([][]*x509.Certificate, error) {
		if len(cert.UnhandledCriticalExtensions) > 0 {
			return nil, x509.UnhandledCriticalExtension{}
		}

		// err = cert.isValid(leafCertificate, nil, &opts)

		if len(opts.DNSName) > 0 {
			if err := cert.VerifyHostname(opts.DNSName); err != nil {
				return nil, err
			}
		}

		// opts.KeyUsages

		if peer.spki.EqualData(cert.RawSubjectPublicKeyInfo) {
			return [][]*x509.Certificate{{cert}}, nil
		}

		return nil, x509.UnknownAuthorityError{}
	}
}

func (peer *aptPeer) transport() *http.Transport {
	peer.mutex.Lock()
	defer peer.mutex.Unlock()

	if peer.tr != nil {
		return peer.tr
	}

	verifyCertificate := peer.getVerifyCertificate()

	tr := &http.Transport{
		TLSClientConfig: tlsConfigClient(&tls.Config{
			ServerName: peer.host,

			Certificates: []tls.Certificate{aptCert},

			CipherSuites: []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			},

			MinVersion: tls.VersionTLS12,
		}, verifyCertificate),
	}

	// Move into tls_conf.go
	if !hasVerifyCertificate {
		tr.DialTLS = func(network, addr string) (net.Conn, error) {
			conn, err := tls.Dial(network, addr, tr.TLSClientConfig)

			if err != nil {
				return nil, err
			}

			if err = tlsFallbackVerify(conn.ConnectionState().PeerCertificates, verifyCertificate); err != nil {
				return nil, err
			}

			return conn, nil
		}
	}

	if err := http2ConfigureTransport(tr); err != nil {
		log.Println(err)
	}

	peer.tr = tr
	return tr
}

func (peer *aptPeer) Request(method, path string, headers http.Header) (*http.Response, error) {
	if peer.Removed() {
		return nil, errPeerRemoved
	}

	req := &http.Request{
		Method: method,
		URL: &url.URL{
			Scheme: "https",
			Host:   peer.address,
			Path:   path,
		},

		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,

		Header: http.Header{
			"User-Agent": []string{userAgent},
		},

		Host: peer.address,
	}

	for k, vv := range headers {
		if k == "User-Agent" {
			continue
		}

		for _, v := range vv {
			req.Header.Add(k, v)
		}
	}

	client := &http.Client{Transport: peer.transport()}
	resp, err := client.Do(req)

	if urlErr, ok := err.(*url.Error); ok {
		if opErr, ok := urlErr.Err.(*net.OpError); ok {
			if dnsErr, ok := opErr.Err.(*net.DNSError); ok && !dnsErr.Temporary() && dnsErr.Err == "no such host" {
				peer.Remove()
			}
		}
	}

	return resp, err
}

func (peer *aptPeer) Get(path string, headers http.Header) (*http.Response, error) {
	return peer.Request("GET", path, headers)
}

func (peer *aptPeer) Head(path string, headers http.Header) (*http.Response, error) {
	return peer.Request("HEAD", path, headers)
}
