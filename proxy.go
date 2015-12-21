package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"mime"
	"net"
	"net/http"
	"os/exec"
	"path"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/elazarl/goproxy"
	"github.com/tmthrgd/apt-p2p/hash"
)

var (
	packageNameRegex = regexp.MustCompile(`([^_\s]+)_([^_\s]+)_([^_\s]+)\.deb$`)
	packagePathRegex = regexp.MustCompile("/" + packageNameRegex.String())

	aptCacheRegex = regexp.MustCompile(`(?:^|\n)SHA256: ([0-9A-Fa-f]{64})(?:\n|$)`)
)

const (
	aptProxyTimeout = time.Minute

	aptMaxPeers = 12
)

var (
	rsaCACert *x509.Certificate
	rsaCAKey  crypto.PrivateKey

	ecdsaCACert *x509.Certificate
	ecdsaCAKey  crypto.PrivateKey
)

func aptProxyReq(req *http.Request, _ *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	_, name := path.Split(req.URL.Path)

	match := packageNameRegex.FindStringSubmatch(name)
	aptCache, err := exec.Command("apt-cache", "show", match[1]+"="+match[2]).Output()

	if err != nil {
		log.Println(err)
		return req, nil
	}

	if match = aptCacheRegex.FindStringSubmatch(string(aptCache)); match == nil {
		log.Printf("error: apt-cache output does not match pattern %s", aptCacheRegex)
		return req, nil
	}

	hashBytes, err := hex.DecodeString(match[1])

	if err != nil {
		panic(err)
	}

	reqPath := path.Join("/get", hash.NewRaw(hashBytes, crypto.SHA256).String(), name)

	mimeType := mime.TypeByExtension(path.Ext(name))

	if strings.Contains(mimeType, ";") {
		mimeType = ""
	}

	rangeHeader := req.Header.Get("Range")

	peers.RLock()
	peerSlice := make([]*aptPeer, 0, len(peers.m))

	for _, peer := range peers.m {
		peerSlice = append(peerSlice, peer)
	}
	peers.RUnlock()

	c := make(chan *aptPeer, 1)

	switch len(peerSlice) {
	case 0:
		close(c)
	case 1:
		defer close(c)

		c <- peerSlice[0]
	default:
		peerIndexes := rand.Perm(len(peerSlice))

		if len(peerIndexes) > aptMaxPeers {
			peerIndexes = peerIndexes[:aptMaxPeers]
		}

		var wg sync.WaitGroup
		wg.Add(len(peerIndexes))

		for _, i := range peerIndexes {
			go func(peer *aptPeer) {
				defer wg.Done()

				headers := http.Header{}

				if len(mimeType) != 0 {
					headers.Add("Accept", mimeType+"; q=1.0, */*; q=0.1")
				}

				if len(rangeHeader) != 0 {
					headers.Add("Range", rangeHeader)
				}

				resp, err := peer.Head(reqPath, headers)

				if err != nil {
					log.Println(err)
					return
				}

				// https://golang.org/src/net/http/client.go#L391
				// Read the body if small so underlying TCP connection will be re-used.
				// No need to check for errors: if it fails, Transport won't reuse it anyway.
				const maxBodySlurpSize = 2 << 10
				if resp.ContentLength == -1 || resp.ContentLength <= maxBodySlurpSize {
					io.CopyN(ioutil.Discard, resp.Body, maxBodySlurpSize)
				}
				resp.Body.Close()

				if resp.StatusCode >= 200 && resp.StatusCode < 300 && !peer.Removed() {
					select {
					case c <- peer:
					default:
					}
				}
			}(peerSlice[i])
		}

		go func() {
			wg.Wait()
			close(c)
		}()
	}

	select {
	case peer, more := <-c:
		if !more {
			break
		}

		headers := http.Header{}

		if len(mimeType) != 0 {
			headers.Add("Accept", mimeType+"; q=1.0, */*; q=0.1")
		}

		if len(rangeHeader) != 0 {
			headers.Add("Range", rangeHeader)
		}

		if resp, err := peer.Get(reqPath, headers); err != nil {
			log.Println(err)
		} else if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return req, resp
		}
	case <-time.After(aptProxyTimeout):
	}

	return req, nil
}

var (
	aptProxyRSACerts = struct {
		sync.Mutex
		m map[string]*tls.Certificate
	}{m: make(map[string]*tls.Certificate, 12)}
	aptProxyECDSACerts = struct {
		sync.Mutex
		m map[string]*tls.Certificate
	}{m: make(map[string]*tls.Certificate, 12)}
)

var tlsCurves = map[tls.CurveID]func() elliptic.Curve{
	tls.CurveP256: elliptic.P256,
	tls.CurveP384: elliptic.P384,
	tls.CurveP521: elliptic.P521,
}

var errUnsupportedCipherSuites = errors.New("apt: tls: no cipher suite supported by both client and server")

func aptProxyHandleConnectTLSConfig(hostPort string, _ *goproxy.ProxyCtx) (*tls.Config, error) {
	tlsConfig := &tls.Config{
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		},
		PreferServerCipherSuites: true,
	}

	if hasGNUTLS2 {
		// apt-transport-https relies on libcurl3-gnutls which relies on gnutls
		//
		// On Ubuntu <=14.04 the version of gnutls (~2.1x) only supports old (read: insecure) ciphers.
		tlsConfig.CipherSuites = append(tlsConfig.CipherSuites, tls.TLS_RSA_WITH_AES_128_CBC_SHA, tls.TLS_RSA_WITH_AES_256_CBC_SHA)
	} else {
		tlsConfig.MinVersion = tls.VersionTLS10
	}

	host, _, err := net.SplitHostPort(hostPort)

	if err != nil || len(host) == 0 {
		host = hostPort
	}

	tlsConfig.GetCertificate = func(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		var curve elliptic.Curve
		issuerCert, issuerKey := rsaCACert, rsaCAKey
		certCache := &aptProxyRSACerts

		if ecdsaCAKey != nil {
		LoopCurves:
			for curveID, curveFunc := range tlsCurves {
				for _, c := range clientHello.SupportedCurves {
					if c == curveID {
						curve = curveFunc()
						issuerCert, issuerKey = ecdsaCACert, ecdsaCAKey
						certCache = &aptProxyECDSACerts
						break LoopCurves
					}
				}
			}

			if curve == nil && rsaCAKey == nil {
				return nil, errUnsupportedCipherSuites
			}
		}

		certCache.Lock()
		defer certCache.Unlock()

		// This could be expired...
		if tlsCert, ok := certCache.m[host]; ok {
			tlsConfig.Certificates = append(tlsConfig.Certificates, *tlsCert)
			return tlsCert, nil
		}

		if curve != nil {
			log.Printf("signing for %s with ecdsa", host)
		} else {
			log.Printf("signing for %s with rsa", host)
		}

		var ipAddresses []net.IP

		if ip := net.ParseIP(host); ip != nil {
			ipAddresses = append(ipAddresses, ip)
		}

		cert, priv, err := generateCertificate(&generateCertConfig{
			Subject: pkix.Name{
				CommonName: host,
			},
			IPAddresses: ipAddresses,

			Curve: curve,
			Bits:  1024,

			Issuer:           issuerCert,
			IssuerPrivateKey: issuerKey,
		})

		if err != nil {
			return nil, err
		}

		tlsCert := &tls.Certificate{
			Certificate: [][]byte{cert},
			PrivateKey:  priv,
		}

		for len(certCache.m) >= 12 {
			for x := range certCache.m {
				// Not necessarily the oldest - https://blog.golang.org/go-maps-in-action#TOC_7.
				delete(certCache.m, x)
				break
			}
		}

		certCache.m[host] = tlsCert
		tlsConfig.Certificates = append(tlsConfig.Certificates, *tlsCert)
		return tlsCert, nil
	}

	return tlsConfig, nil
}

func aptProxyHandleConnect(host string, _ *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
	return &goproxy.ConnectAction{Action: goproxy.ConnectMitm, TLSConfig: aptProxyHandleConnectTLSConfig}, host
}

func aptProxy() error {
	// x509 Certificate
	if len(config.Proxy.CertFile) == 0 && len(config.Proxy.KeyFile) == 0 {
		config := &generateCertConfig{
			Subject: pkix.Name{
				Organization: []string{"APT-P2P RSA Proxy CA"},
			},

			Bits: 1024,

			IsCA: true,
		}

		var err error

		if rsaCACert, rsaCAKey, err = generateCertificateAndParse(config); err != nil {
			return err
		}

		if _, ok := rsaCAKey.(*rsa.PrivateKey); !ok {
			panic("generateCertificateAndParse failed to produce rsa key")
		}

		config.Curve = elliptic.P256()
		config.Subject.Organization[0] = "APT-P2P ECDSA Proxy CA"

		if ecdsaCACert, ecdsaCAKey, err = generateCertificateAndParse(config); err != nil {
			return err
		}

		if _, ok := ecdsaCAKey.(*ecdsa.PrivateKey); !ok {
			panic("generateCertificateAndParse failed to produce ecdsa key")
		}
	} else {
		cert, err := tls.LoadX509KeyPair(config.Proxy.CertFile, config.Proxy.KeyFile)

		if err != nil {
			return err
		}

		if len(cert.Certificate) == 0 {
			return errNoCertificate
		}

		parsedCert, err := x509.ParseCertificate(cert.Certificate[0])

		if err != nil {
			return err
		}

		switch priv := cert.PrivateKey.(type) {
		case *rsa.PrivateKey:
			rsaCACert, rsaCAKey = parsedCert, priv
		case *ecdsa.PrivateKey:
			ecdsaCACert, ecdsaCAKey = parsedCert, priv
		default:
			return errKeyTypeUnsupported
		}
	}

	aptProxy := goproxy.NewProxyHttpServer()
	//aptProxy.Verbose = config.Verbose

	aptProxy.OnRequest().HandleConnectFunc(aptProxyHandleConnect)

	aptProxy.OnRequest(goproxy.UrlMatches(packagePathRegex)).DoFunc(aptProxyReq)

	// Serve
	server := &http.Server{Addr: config.Proxy.Address, Handler: aptProxy}
	ln, err := net.Listen("tcp", server.Addr)

	if err != nil {
		return err
	}

	if host, port, err := net.SplitHostPort(config.Proxy.Address); err == nil && port == "0" {
		config.Proxy.Address = net.JoinHostPort(host, strconv.Itoa(ln.Addr().(*net.TCPAddr).Port))

		if dbusProps != nil {
			dbusProps.SetMust(dbusIface, "ProxyAddress", config.Proxy.Address)
		}
	}

	log.Printf("APT Proxy listening on %s", config.Proxy.Address)
	return server.Serve(tcpKeepAliveListener{ln.(*net.TCPListener)})

	/*log.Printf("APT Proxy listening on %s", config.Proxy.Address)
	err = http.ListenAndServe(config.Proxy.Address, aptProxy)
	return*/
}

// https://golang.org/src/net/http/server.go?s=58314:58369#L2126
type tcpKeepAliveListener struct {
	*net.TCPListener
}

func (ln tcpKeepAliveListener) Accept() (c net.Conn, err error) {
	tc, err := ln.AcceptTCP()

	if err != nil {
		return
	}

	tc.SetKeepAlive(true)
	tc.SetKeepAlivePeriod(3 * time.Minute)
	return tc, nil
}
