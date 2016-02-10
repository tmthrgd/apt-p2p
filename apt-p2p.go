package main

// BUILD
//
// build: go fmt github.com/tmthrgd/apt-p2p && go install -race -tags gnutls2 -ldflags "-X 'main.xBuildTime=`date -R`'" github.com/tmthrgd/apt-p2p && (rsync -a $(which apt-p2p) tom@xenox:~/apt-p2p; apt-p2p -v)
// alt build (DO NOT USE): goimports -l -w $GOPATH/src/github.com/tmthrgd/apt-p2p && go install -race -tags gnutls2 -ldflags "-X 'main.xBuildTime=`date -R`'" github.com/tmthrgd/apt-p2p && (rsync -a $(which apt-p2p) tom@xenox:~/apt-p2p; apt-p2p -v)
//
// "-X 'main.version=`date -u +%Y.%j`.`date -u +"%H*60*60 + %M*60 + %S" | bc`-dev'"
// "-X 'main.version=`date -u +%Y.%j`-`git rev-parse --short HEAD`-dev'"
// "-X 'main.version=`git describe --tags`'"
//
// get custom go: git clone https://github.com/golang/go.git .go && cd .go && git remote add patch https://github.com/tmthrgd/go.git && git pull patch VerifyCertificate && git checkout VerifyCertificate && git rebase master
// build custom go: cd src && GOROOT=$HOME/go GOROOT_FINAL=$HOME/.go ./make.bash && cd ..
// alt build custom go: cd src && GOROOT_BOOTSTRAP=$HOME/.go GOROOT=$HOME/go GOROOT_FINAL=$HOME/.go ./make.bash && cd ..
//
// custom dbus: cd $GOPATH/src/github.com/godbus/dbus && git origin remote add patch https://github.com/tmthrgd/dbus.git && git pull patch remove-signal && git checkout remove-signal && git rebase master
//
// apt versions supporting https proxy auto detect: curl -s https://mirrors.kernel.org/ubuntu/pool/main/a/apt/ | hxselect -c -s '\n' 'a[href$=".tar.xz"]' 2>/dev/null | xargs -I '{}' sh -c "curl -s 'https://mirrors.kernel.org/ubuntu/pool/main/a/apt/{}' | tar -xJ --to-command='grep --label=\"{}\" -H AutoDetectProxy' --wildcards '*/methods/https.cc' 2>/dev/null"
//
// VET
//
// go tool vet $GOPATH/src/github.com/tmthrgd/apt-p2p/*
//
// golint github.com/tmthrgd/apt-p2p
//
// errcheck -asserts -blank github.com/tmthrgd/apt-p2p
//
// TEST
//
// curl storage testing: curl -k -v -I --cert curl-cert.pem --key curl-key.pem https://thrax.local:3128/
// curl proxy testing: curl -k -v -I -x http://127.0.0.1:3142/ https://www.google.com/
//
// ssl testing: testssl.sh -e -p -y -U -s -H --assuming-http --quiet https://127.0.0.1:3128/
//
// get spki: dbus-send --system --print-reply=literal --dest=com.github.tmthrgd.AptP2P / org.freedesktop.DBus.Properties.Get string:com.github.tmthrgd.AptP2P string:Hash | sed -e 's/\s\+variant\s\+//' && echo
//
// SETUP
//
// peer certificate: ./apt-p2p --generate --peer-cert peer-cert.pem --peer-key peer-key.pem && sudo mv peer-{cert,key}.pem /etc/apt-p2p/
// proxy certificate: ./apt-p2p --generate --proxy-cert proxy-cert.pem --proxy-key proxy-key.pem && sudo mv proxy-{cert,key}.pem /etc/apt-p2p/
//
// curl ca certs: wget http://curl.haxx.se/ca/cacert.pem && sudo mv cacert.pem /etc/apt-p2p/curl-cacert.pem && (echo && echo "APT-P2P - Root CA" && echo "=================") | sudo tee -a /etc/apt-p2p/curl-cacert.pem && </etc/apt-p2p/proxy-cert.pem sudo tee -a /etc/apt-p2p/curl-cacert.pem
//
/* IF apt >= apt_1.0.9.7ubuntu4.tar.xz
 * apt proxy: sudo tee /etc/apt/apt.conf.d/01proxy <<'EOF'
# undocumented feature which was found in the source. It should be an absolute
# path to the program, no arguments are allowed. stdout contains the proxy
# server, stderr is shown (in stderr) but ignored by APT
Acquire::http::ProxyAutoDetect "/etc/apt-p2p/apt-detect-http-proxy";

Acquire::https::CaInfo "/etc/apt-p2p/curl-cacert.pem";
EOF
 * ELSE
 * apt proxy: sudo tee /etc/apt/apt.conf.d/01proxy <<'EOF'
Acquire::http::Proxy "http://127.0.0.1:3142";

Acquire::https::CaInfo "/etc/apt-p2p/proxy-cert.pem";

# undocumented feature which was found in the source. It should be an absolute
# path to the program, no arguments are allowed. stdout contains the proxy
# server, stderr is shown (in stderr) but ignored by APT
#Acquire::http::ProxyAutoDetect "/etc/apt-p2p/apt-detect-http-proxy";
#
#Acquire::https::CaInfo "/etc/apt-p2p/curl-cacert.pem";
EOF */
//
/* apt proxy detect: sudo tee /etc/apt-p2p/apt-detect-http-proxy <<'EOF' && sudo chmod +x /etc/apt-p2p/apt-detect-http-proxy
#!/bin/bash
# detect-http-proxy - Returns an APT-P2P proxy server which is available for use

proxy=$(dbus-send --system --print-reply=literal --dest=com.github.tmthrgd.AptP2P / org.freedesktop.DBus.Properties.Get string:com.github.tmthrgd.AptP2P string:ProxyAddress 2>/dev/null | sed -e 's/\s\+variant\s\+//')

if [ -n "$proxy" ]; then
        echo "http://$proxy"
else
        echo DIRECT
fi
EOF */
//
/* dbus permissions: sudo tee /etc/dbus-1/system.d/apt-p2p.conf <<'EOF'
<!DOCTYPE busconfig PUBLIC
          "-//freedesktop//DTD D-BUS Bus Configuration 1.0//EN"
          "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
        <policy user="apt-p2p">
                <allow own="com.github.tmthrgd.AptP2P"/>
        </policy>

        <policy user="root">
                <allow own="com.github.tmthrgd.AptP2P"/>

                <allow send_destination="com.github.tmthrgd.AptP2P" send_interface="com.github.tmthrgd.AptP2P" send_member="AddPeer"/>
                <allow send_destination="com.github.tmthrgd.AptP2P" send_interface="com.github.tmthrgd.AptP2P.Peer" send_member="Remove"/>
        </policy>

        <policy context="default">
                <deny own="com.github.tmthrgd.AptP2P"/>

                <allow send_destination="com.github.tmthrgd.AptP2P"/>
                <allow receive_sender="com.github.tmthrgd.AptP2P"/>

                <deny send_destination="com.github.tmthrgd.AptP2P" send_interface="com.github.tmthrgd.AptP2P" send_member="AddPeer"/>
                <deny send_destination="com.github.tmthrgd.AptP2P" send_interface="com.github.tmthrgd.AptP2P.Peer" send_member="Remove"/>

                <allow send_destination="com.github.tmthrgd.AptP2P" send_interface="org.freedesktop.DBus.Introspectable"/>
                <allow send_destination="com.github.tmthrgd.AptP2P" send_interface="org.freedesktop.DBus.Properties"/>
        </policy>
</busconfig>
EOF */

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/signal"
	"runtime"
	"runtime/pprof"
	"strings"
	"syscall"
	"time"

	"github.com/naoina/toml"
)

var (
	xBuildTime string
	buildTime  time.Time

	version string
)

var (
	serverName = "apt-p2p (" + version + ")"
	userAgent  = "apt-p2p (" + version + ")"
)

// TLS
var errKeyTypeUnsupported = errors.New("apt: x509: only RSA and ECDSA private keys supported")

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

// Main
func init() {
	runtime.GOMAXPROCS(runtime.NumCPU())

	if len(version) == 0 {
		panic("version not set at compile-time")
	}

	var err error

	if buildTime, err = time.Parse(time.RFC1123Z, xBuildTime); err != nil {
		panic(err)
	}

	flag.BoolVar(&config.Verbose, "verbose", config.Verbose, "verbose")
	flag.BoolVar(&config.Verbose, "v", config.Verbose, "verbose")

	flag.BoolVar(&config.Quiet, "quiet", config.Quiet, "quiet")
	flag.BoolVar(&config.Quiet, "q", config.Quiet, "quiet")
	flag.BoolVar(&config.Quiet, "silent", config.Quiet, "silent")

	flag.StringVar(&configPath, "config", configPath, "path to configuration file")
	flag.StringVar(&configPath, "c", configPath, "path to configuration file")
}

func main() {
	// DEBUG
	if f, err := os.Create("cpu.prof"); err != nil {
		if err = pprof.StartCPUProfile(f); err != nil {
			defer pprof.StopCPUProfile()
		}
	}

	storageAddress := flag.String("address", "", "storage server address")
	storageAddressShort := flag.String("a", "", "storage server address")

	storageCert := flag.String("peer-cert", "", "storage server x509 certificate")
	storageKey := flag.String("peer-key", "", "storage server x509 private key")

	proxyAddress := flag.String("proxy", "", "proxy server address")
	proxyAddressShort := flag.String("p", "", "proxy server address")

	proxyCert := flag.String("proxy-cert", "", "proxy server x509 certificate")
	proxyKey := flag.String("proxy-key", "", "proxy server x509 private key")

	generateCert := flag.Bool("generate", false, "generate a x509 certificate")

	versionFlag := flag.Bool("version", false, "print program version")
	versionFlagShort := flag.Bool("V", false, "print program version")

	flag.Parse()

	if *versionFlag || *versionFlagShort {
		fmt.Printf("apt-p2p %s\n\n", version)
		fmt.Printf("Compiled date: %s\n", buildTime)
		fmt.Printf("With compiler: go version %s %s/%s\n", runtime.Version(), runtime.GOOS, runtime.GOARCH)
		return
	}

	if *generateCert {
		certFile, keyFile := *storageCert, *storageKey

		var certBytes []byte
		var privBytes []byte
		var privType string
		var err error

		if len(*proxyCert) != 0 || len(*proxyKey) != 0 {
			certFile, keyFile = *proxyCert, *proxyKey

			var priv crypto.PrivateKey
			certBytes, priv, err = generateCertificate(&generateCertConfig{
				Subject: pkix.Name{
					Organization: []string{"APT-P2P RSA Proxy CA"},
				},

				ValidForever: true,

				IsCA: true,
			})
			must(err)

			privBytes = x509.MarshalPKCS1PrivateKey(priv.(*rsa.PrivateKey))
			privType = "RSA PRIVATE KEY"
		} else {
			var priv *ecdsa.PrivateKey
			certBytes, priv, err = generatePeerCertificate(true)
			must(err)

			privBytes, err = x509.MarshalECPrivateKey(priv)
			must(err)

			privType = "EC PRIVATE KEY"

			hash, err := spkiHashForCertificate(&priv.PublicKey, crypto.SHA384)
			must(err)

			fmt.Println(hash)
		}

		if len(certFile) == 0 && len(keyFile) == 0 {
			certFile, keyFile = "cert.pem", "key.pem"
		}

		certOut, err := os.Create(certFile)
		must(err)

		defer func() {
			must(certOut.Close())
		}()

		must(pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes}))

		keyOut, err := os.OpenFile(keyFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		must(err)

		defer func() {
			must(keyOut.Close())
		}()

		must(pem.Encode(keyOut, &pem.Block{Type: privType, Bytes: privBytes}))
		return
	}

	quiet, verbose := config.Quiet, config.Verbose

	// Banner
	if !config.Quiet {
		fmt.Printf("apt-p2p %s\n\n", version)
	}

	if f, err := os.Open(os.ExpandEnv(configPath)); err == nil {
		err = toml.NewDecoder(f).Decode(&config)
		must(f.Close())
		must(err)

		if !config.Quiet || config.Verbose {
			log.Printf("Loaded configuration file %s", configPath)
		}
	} else if !os.IsNotExist(err) {
		log.Println(err)
	}

	// Command line and Defaults
	if quiet && !verbose {
		config.Verbose = false
	}

	if config.Quiet && !config.Verbose {
		log.SetOutput(ioutil.Discard)
	}

	if len(config.Archives) == 0 {
		config.Archives = []string{"/var/cache/apt/archives"}
	}

	for addr, addrs := range map[*string][3]string{
		&config.Storage.Address: [...]string{*storageAddress, *storageAddressShort, ":3128"},
		&config.Proxy.Address:   [...]string{*proxyAddress, *proxyAddressShort, "127.0.0.1:3142"},
	} {
		switch {
		case len(addrs[0]) != 0:
			*addr = addrs[0]
		case len(addrs[1]) != 0:
			*addr = addrs[1]
		case len(*addr) == 0:
			*addr = addrs[2]
		}
	}

	for path, files := range map[*string][2]string{
		&config.Storage.CertFile: [...]string{*storageCert, configPeerCertPath},
		&config.Storage.KeyFile:  [...]string{*storageKey, configPeerKeyPath},
		&config.Proxy.CertFile:   [...]string{*proxyCert, configProxyCertPath},
		&config.Proxy.KeyFile:    [...]string{*proxyKey, configProxyKeyPath},
	} {
		if len(files[0]) != 0 {
			*path = files[0]
		}

		if len(*path) != 0 {
			continue
		}

		if _, err := os.Stat(files[1]); !os.IsNotExist(err) {
			*path = files[1]
		}
	}

	for _, path := range flag.Args() {
		stat, err := os.Stat(path)
		must(err)

		if stat.IsDir() {
			config.Archives = append(config.Archives, path)
		} else {
			config.ArchiveFiles = append(config.ArchiveFiles, path)
		}
	}

	for key, cert := range map[*string]*string{
		&config.Storage.KeyFile: &config.Storage.CertFile,
		&config.Proxy.KeyFile:   &config.Proxy.CertFile,
	} {
		if len(*key) == 0 {
			continue
		}

		stat, err := os.Stat(*key)

		if err != nil {
			continue
		}

		switch stat.Mode() {
		case 0400, 0600:
		default:
			w := len("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@")

			paddingLeft := strings.Repeat(" ", (w-4-len(*key))/2)
			paddingRight := paddingLeft

			if 4+len(paddingLeft)+len(paddingRight)+len(*key) == w-1 {
				paddingRight = paddingLeft + " "
			}

			fmt.Println("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@")
			fmt.Println("@  WARNING: UNPROTECTED PRIVATE KEY FILE! @")
			fmt.Println("@                                         @")
			fmt.Printf("@          Permissions %#o for           @\n", stat.Mode())
			fmt.Printf("@%s'%s'%s@\n", paddingLeft, *key, paddingRight)
			fmt.Println("@              are too open.              @")
			fmt.Println("@                                         @")
			fmt.Println("@   It is recommended that your private   @")
			fmt.Println("@ key files are NOT accessible by others. @")
			fmt.Println("@                                         @")
			fmt.Println("@    This private key will be ignored.    @")
			fmt.Println("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@")

			*key, *cert = "", ""
		}
	}

	// Servers
	storageDone := make(chan struct{})
	defer close(storageDone)

	must(storageServerPrepare())

	go func() {
		must(storageServer(storageDone))
	}()

	go func() {
		must(aptProxy())
	}()

	dbusDone := make(chan struct{})
	defer close(dbusDone)

	go func() {
		must(dbusServe(dbusDone))
	}()

	// DNS-SD
	op, err := startBrowse()
	must(err)

	defer func() {
		must(op.Stop())
	}()

	// Termination
	// http://stackoverflow.com/a/18158859
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	signal.Notify(c, syscall.SIGTERM)
	<-c

	for _, done := range [...]chan struct{}{dbusDone, storageDone} {
		done <- struct{}{}
		<-done
	}

	pprof.StopCPUProfile()

	os.Exit(1)
}
