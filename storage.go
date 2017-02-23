package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"log"
	"net"
	"net/http"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/handlers"
	"github.com/julienschmidt/httprouter"
	"github.com/tmthrgd/apt-p2p/hash"
)

var (
	aptCert  tls.Certificate
	spkiHash *hash.Hash
)

const stsHeaderValue = "max-age=15552000"

// 1px by 1px GIF
var gif1x1 = []byte("GIF87a\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\xff\xff\xff,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;")

const gifMimeType = "image/gif"

// robots.txt
var robotsTXT = []byte(`User-agent: *
Disallow: /`)

const robotsMimeType = "text/plain"

// https://golang.org/src/net/http/fs.go#L263
func checkLastModified(w http.ResponseWriter, r *http.Request, modtime time.Time) bool {
	// The Date-Modified header truncates sub-second precision, so
	// use mtime < t+1s instead of mtime <= t to check for unmodified.
	if t, err := time.Parse(http.TimeFormat, r.Header.Get("If-Modified-Since")); err == nil && modtime.Before(t.Add(1*time.Second)) {
		h := w.Header()
		delete(h, "Content-Type")
		delete(h, "Content-Length")

		w.WriteHeader(http.StatusNotModified)
		return true
	}

	w.Header().Set("Last-Modified", modtime.UTC().Format(http.TimeFormat))
	return false
}

func canServeFile(dir, name string, _ *http.Request) bool {
	switch path.Ext(name) {
	case ".deb":
		return true
	default:
		return false
	}
}

func verifyCertificate(rawCerts [][]byte, _ [][]*x509.Certificate) error {
	cert, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return err
	}

	if len(cert.UnhandledCriticalExtensions) > 0 {
		return x509.UnhandledCriticalExtension{}
	}

	spkis := make(map[crypto.Hash]*hash.Hash)

	for _, peer := range config.Trusted {
		spki, err := hash.Parse(peer.SPKI)
		if err != nil {
			log.Println(err)
			continue
		}

		certSPKI, ok := spkis[spki.HashAlgorithm()]
		if !ok {
			if certSPKI, err = hash.New(cert.RawSubjectPublicKeyInfo, spki.HashAlgorithm()); err != nil {
				return err
			}

			spkis[spki.HashAlgorithm()] = certSPKI
		}

		if spki.Equal(certSPKI) {
			return nil
		}
	}

	return x509.UnknownAuthorityError{}
}

func emptyResponse(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	checkLastModified(w, r, startTime)
}

func serveFakeStatic(w http.ResponseWriter, r *http.Request, body []byte, mimeType string) {
	if checkLastModified(w, r, startTime) {
		return
	}

	now := time.Now()
	expires := now.AddDate(0, 6, 0)

	h := w.Header()
	h.Set("Content-Type", mimeType)
	h.Set("Content-Length", strconv.Itoa(len(body)))
	h.Set("Cache-Control", "public, max-age="+strconv.Itoa(int(expires.Sub(now)/time.Second)))
	h.Set("Expires", expires.Format(http.TimeFormat))

	if _, err := w.Write(body); err != nil {
		log.Println(err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	}
}

func fakeFavicon(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	serveFakeStatic(w, r, gif1x1, gifMimeType)
}

func fakeRobots(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	serveFakeStatic(w, r, robotsTXT, robotsMimeType)
}

func getArchive(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
	var err error
	var ok bool
	var file http.File
	var stat os.FileInfo
	var fileHash *hash.Hash

	name, hashString := p.ByName("name"), p.ByName("hash")
	if len(hashString) == 0 || strings.HasPrefix(name, ".") {
		err = os.ErrNotExist
		goto respondError
	}

	if fileHash, err = hash.Parse(hashString); err != nil {
		log.Println(err)

		err = os.ErrNotExist
		goto respondError
	}

	for _, path := range config.Archives {
		if !canServeFile(path, name, r) {
			continue
		}

		if file, err = http.Dir(path).Open(name); !os.IsNotExist(err) {
			break
		}
	}

	if os.IsNotExist(err) {
		for _, extra := range config.ArchiveFiles {
			dir, n := path.Split(extra)
			if n != name || !canServeFile(dir, name, r) {
				continue
			}

			if file, err = http.Dir(dir).Open(name); !os.IsNotExist(err) {
				break
			}
		}
	}

	if err != nil {
		goto respondError
	}

	if file == nil {
		err = os.ErrNotExist
		goto respondError
	}

	if ok, _ = fileHash.EqualReader(file); !ok {
		err = os.ErrNotExist
		goto respondError
	}

	if _, err = file.Seek(0, 0); err != nil {
		goto respondError
	}

	if stat, err = file.Stat(); err != nil {
		goto respondError
	}

	http.ServeContent(w, r, name, stat.ModTime(), file)
	return

respondError:
	switch {
	case os.IsNotExist(err):
		http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
	case err != nil:
		log.Println(err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	default:
		panic("unreachable")
	}
}

type notFoundRouter struct {
	h http.Handler
}

var faviconRedirector = http.RedirectHandler("/favicon.ico", http.StatusMovedPermanently)

func (r *notFoundRouter) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	h := r.h

	if _, name := path.Split(req.URL.Path); name == "favicon.ico" {
		h = faviconRedirector
	}

	if h != nil {
		h.ServeHTTP(w, req)
	} else {
		http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
	}
}

var _ http.Handler = (*notFoundRouter)(nil)

type storageHeaderServer struct {
	h http.Handler
}

func (s *storageHeaderServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Server", serverName)
	h.Add("Strict-Transport-Security", stsHeaderValue)

	s.h.ServeHTTP(w, r)
}

var _ http.Handler = (*storageHeaderServer)(nil)

func storageServerPrepare() error {
	var certData []byte
	var privKey interface{}

	// x509 Certificate
	if len(config.Storage.CertFile) == 0 && len(config.Storage.KeyFile) == 0 {
		var err error
		if certData, privKey, err = generatePeerCertificate(false); err != nil {
			return err
		}

		if spkiHash, err = spkiHashForCertificate(&privKey.(*ecdsa.PrivateKey).PublicKey, crypto.SHA256); err != nil {
			return err
		}
	} else {
		cert, err := tls.LoadX509KeyPair(config.Storage.CertFile, config.Storage.KeyFile)
		if err != nil {
			return err
		}

		if len(cert.Certificate) == 0 {
			return errNoCertificate
		}

		certData = cert.Certificate[0]

		var pubKey crypto.PublicKey
		switch priv := cert.PrivateKey.(type) {
		case *rsa.PrivateKey:
			privKey, pubKey = priv, &priv.PublicKey
		case *ecdsa.PrivateKey:
			privKey, pubKey = priv, &priv.PublicKey
		default:
			return errKeyTypeUnsupported
		}

		if spkiHash, err = spkiHashForCertificate(pubKey, crypto.SHA384); err != nil {
			return err
		}
	}

	aptCert = tls.Certificate{
		Certificate: [][]byte{certData},
		PrivateKey:  privKey,
	}
	return nil
}

func storageServer(done chan struct{}) error {
	// Router
	router := httprouter.New()
	router.NotFound = new(notFoundRouter)

	router.GET("/", emptyResponse)
	router.GET("/favicon.ico", fakeFavicon)
	router.GET("/robots.txt", fakeRobots)

	router.HEAD("/get/:hash/:name", getArchive)
	router.GET("/get/:hash/:name", getArchive)

	// Server
	clientAuth := tls.NoClientCert
	if len(config.Trusted) != 0 {
		clientAuth = tls.RequireAndVerifyClientCert
	}

	server := &http.Server{
		Addr:    config.Storage.Address,
		Handler: &storageHeaderServer{router},

		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{aptCert},

			CipherSuites: []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			},
			PreferServerCipherSuites: true,

			MinVersion: tls.VersionTLS12,

			ClientAuth: clientAuth,

			VerifyPeerCertificate: verifyCertificate,
			InsecureSkipVerify:    true,
		},
	}

	if config.Verbose {
		server.Handler = handlers.LoggingHandler(os.Stdout, server.Handler)
	}

	// DNS-SD
	_, portString, err := net.SplitHostPort(config.Storage.Address)
	if err != nil {
		return err
	}

	port, err := strconv.Atoi(portString)
	if err != nil {
		return err
	}

	op, err := newRegisterOp("", dnssdServiceType, port, map[string]string{
		dnssdSPKIKey: spkiHash.String(),
	})
	if err != nil {
		return err
	}

	go func() {
		<-done
		err = op.Stop()
		done <- struct{}{}
	}()

	// Listen
	log.Printf("Storage server listening on %s with spki: %s", config.Storage.Address, spkiHash)
	log.Printf("\tserving files from %s", strings.Join(config.Archives, ", "))

	if len(config.ArchiveFiles) != 0 {
		log.Printf("\talso serving %s", strings.Join(config.ArchiveFiles, ", "))
	}

	return server.ListenAndServeTLS("", "")
}
