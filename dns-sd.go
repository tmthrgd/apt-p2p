package main

import (
	"log"
	"strings"

	"github.com/tmthrgd/apt-p2p/hash"
)

// DNS-SD
const (
	dnssdServiceType   = "_apt-p2p._tcp"
	dnssdDefaultDomain = "local"

	dnssdSPKIKey = "spki"
)

func dnssdBrowseAddedCallback(result *dnssdBrowseResult) {
	if config.Verbose {
		log.Printf(`Detected addition of name "%s" with service "%s" on domain "%s"`, result.Name, result.ServiceType, result.Domain)
	}

	resolveResults := make(chan *dnssdResolveResult, 1)

	op, err := newResolveOp(result.InterfaceIndex, result.Name, result.ServiceType, result.Domain, resolveResults)
	if err != nil {
		log.Println(err)
		return
	}

	resolve := <-resolveResults

	if err = op.Stop(); err != nil {
		log.Println(err)
	}

	if resolve.Err != nil {
		log.Println(resolve.Err)
		return
	}

	spkiString, ok := resolve.TXT[dnssdSPKIKey]
	if !ok {
		return
	}

	spki, err := hash.Parse(spkiString)
	if err != nil {
		log.Println(err)
		return
	}

	if spki.Equal(spkiHash) {
		return
	}

	host := strings.TrimSuffix(resolve.Host, ".")

	if len(config.Trusted) != 0 {
		isTrusted := false

		for _, peer := range config.Trusted {
			if isTrusted = spki.EqualString(peer.SPKI); isTrusted {
				log.Printf(`Found trusted host "%s" running on port %d with spki: %s`, resolve.Host, resolve.Port, spki)
				break
			}
		}

		if !isTrusted {
			if err = untrustedPeer(result.Name, host, resolve.Port, spki); err != nil {
				log.Println(err)
			}

			if config.Verbose {
				log.Printf(`Found untrusted host "%s" running on port %d with spki: %s`, resolve.Host, resolve.Port, spki)
			}

			return
		}
	} else if config.Verbose {
		log.Printf(`Found host "%s" running on port %d with spki: %s`, resolve.Host, resolve.Port, spki)
	}

	peers.RLock()
	_, ok = peers.m[host]
	peers.RUnlock()

	if ok {
		return
	}

	newPeer(result.Name, host, resolve.Port, spki).Add()
}

func dnssdBrowseRemovedCallback(result *dnssdBrowseResult) {
	if config.Verbose {
		log.Printf(`Detected removal of name "%s" with service "%s" on domain "%s"`, result.Name, result.ServiceType, result.Domain)
	}

	peerNamesToHosts.RLock()
	host, ok := peerNamesToHosts.m[result.Name]
	peerNamesToHosts.RUnlock()

	if ok {
		peers.RLock()
		peer := peers.m[host]
		peers.RUnlock()

		peer.Remove()
	}

	return
}

func startBrowse() (*dnssdBrowseOp, error) {
	results := make(chan *dnssdBrowseResult)

	go func() {
		for result := range results {
			if result.Err != nil {
				log.Println(result.Err)
			} else if result.Added {
				go dnssdBrowseAddedCallback(result)
			} else {
				go dnssdBrowseRemovedCallback(result)
			}
		}
	}()

	return newBrowseOp(dnssdServiceType, results)
}
