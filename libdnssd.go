// +build libdnssd,!go1.6

package main

import (
	"os"

	"github.com/andrewtj/dnssd"
)

type dnssdBrowseResult struct {
	Err            error
	Added          bool
	InterfaceIndex int
	Name           string
	ServiceType    string
	Domain         string
}

type dnssdBrowseOp struct {
	op      *dnssd.BrowseOp
	results chan<- *dnssdBrowseResult
}

func newBrowseOp(service string, results chan<- *dnssdBrowseResult) (*dnssdBrowseOp, error) {
	op, err := dnssd.StartBrowseOp(service, func(_ *dnssd.BrowseOp, err error, add bool, interfaceIndex int, name string, serviceType string, domain string) {
		if err == nil {
			// This is a hack because github.com/andrewtj/dnssd does not expose flags
			// As a result we cannot check for AVAHI_LOOKUP_RESULT_OUR_OWN
			// Although this test is more like a check for AVAHI_LOOKUP_RESULT_LOCAL
			if hostname, e := os.Hostname(); e == nil && hostname == name {
				return
			}
		}

		select {
		case results <- &dnssdBrowseResult{err, add, interfaceIndex, name, serviceType, domain}:
		default:
		}
	})

	if err != nil {
		return nil, err
	}

	return &dnssdBrowseOp{op, results}, nil
}

func (b *dnssdBrowseOp) Stop() error {
	b.op.Stop()
	close(b.results)
	return nil
}

type dnssdResolveResult struct {
	Err  error
	Host string
	Port int
	TXT  map[string]string
}

type dnssdResolveOp struct {
	op      *dnssd.ResolveOp
	results chan<- *dnssdResolveResult
}

func newResolveOp(interfaceIndex int, name, service, domain string, results chan<- *dnssdResolveResult) (*dnssdResolveOp, error) {
	op, err := dnssd.StartResolveOp(interfaceIndex, name, service, domain, func(_ *dnssd.ResolveOp, err error, host string, port int, txt map[string]string) {
		select {
		case results <- &dnssdResolveResult{err, host, port, txt}:
		default:
		}
	})

	if err != nil {
		return nil, err
	}

	return &dnssdResolveOp{op, results}, nil
}

func (b *dnssdResolveOp) Stop() error {
	b.op.Stop()
	close(b.results)
	return nil
}

func nullDNSSDRegisterCallback(_ *dnssd.RegisterOp, _ error, _ bool, _, _, _ string) {}

type dnssdRegisterOp struct {
	op *dnssd.RegisterOp
}

func newRegisterOp(name, service string, port int, txt map[string]string) (*dnssdRegisterOp, error) {
	op := dnssd.NewRegisterOp(name, service, port, nullDNSSDRegisterCallback)

	for k, v := range txt {
		if err = op.SetTXTPair(k, v); err != nil {
			return nil, err
		}
	}

	if err = op.Start(); err != nil {
		return nil, err
	}

	return &dnssdRegisterOp{op}, nil
}

func (b *dnssdRegisterOp) Stop() error {
	b.op.Stop()
	return nil
}
