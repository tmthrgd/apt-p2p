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

func (peer *aptPeer) getVerifyCertificate() func([][]byte, [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		cert, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return err
		}

		if len(cert.UnhandledCriticalExtensions) > 0 {
			return x509.UnhandledCriticalExtension{}
		}

		if peer.spki.EqualData(cert.RawSubjectPublicKeyInfo) {
			return nil
		}

		return x509.UnknownAuthorityError{}
	}
}

func (peer *aptPeer) transport() *http.Transport {
	peer.mutex.Lock()
	defer peer.mutex.Unlock()

	if peer.tr != nil {
		return peer.tr
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			ServerName: peer.host,

			Certificates: []tls.Certificate{aptCert},

			CipherSuites: []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			},

			MinVersion: tls.VersionTLS12,

			VerifyPeerCertificate: peer.getVerifyCertificate(),
			InsecureSkipVerify:    true,
		},
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
