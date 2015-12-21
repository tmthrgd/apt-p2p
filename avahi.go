// +build !libdnssd

package main

import (
	"errors"
	"os"
	"strings"

	"github.com/godbus/dbus"
)

const avahiDefaultDomain = "local"

const avahiLookupRresultOurOwn = 16

type dnssdBrowseResult struct {
	Err            error
	Added          bool
	InterfaceIndex int
	Name           string
	ServiceType    string
	Domain         string
}

type dnssdBrowseOp struct {
	conn    *dbus.Conn
	obj     dbus.BusObject
	newItem chan *dbus.Signal
	results chan<- *dnssdBrowseResult
}

func newBrowseOp(service string, results chan<- *dnssdBrowseResult) (*dnssdBrowseOp, error) {
	dconn, err := dbus.SystemBus()

	if err != nil {
		return nil, err
	}

	newItem := make(chan *dbus.Signal, 16)
	dconn.Signal(newItem)

	obj := dconn.Object("org.freedesktop.Avahi", "/")

	var path dbus.ObjectPath

	if err = obj.Call("org.freedesktop.Avahi.Server.ServiceBrowserNew", 0,
		int32(-1),          // avahi.IF_UNSPEC
		int32(-1),          // avahi.PROTO_UNSPEC
		service,            // stype
		avahiDefaultDomain, // sdomain
		uint32(0),          // flags
	).Store(&path); err != nil {
		dconn.RemoveSignal(newItem)
		close(newItem)

		return nil, err
	}

	b := &dnssdBrowseOp{dconn, dconn.Object("org.freedesktop.Avahi", path), newItem, results}
	go b.waitForSignal()

	return b, nil
}

func (b *dnssdBrowseOp) waitForSignal() {
	for item := range b.newItem {
		if item == nil || item.Path != b.obj.Path() {
			continue
		}

		result := dnssdBrowseResult{Added: item.Name == "org.freedesktop.Avahi.ServiceBrowser.ItemNew"}

		switch item.Name {
		case "org.freedesktop.Avahi.ServiceBrowser.ItemNew", "org.freedesktop.Avahi.ServiceBrowser.ItemRemove":
			if len(item.Body) != 6 {
				continue
			}

			ifaceIdx, ok0 := item.Body[0].(int32)
			result.InterfaceIndex = int(ifaceIdx)

			_, ok1 := item.Body[1].(int32)

			var ok2 bool
			result.Name, ok2 = item.Body[2].(string)

			var ok3 bool
			result.ServiceType, ok3 = item.Body[3].(string)

			var ok4 bool
			result.Domain, ok4 = item.Body[4].(string)

			flags, ok5 := item.Body[5].(uint32)

			if !ok0 || !ok1 || !ok2 || !ok3 || !ok4 || !ok5 || flags&avahiLookupRresultOurOwn != 0 {
				continue
			}
		case "org.freedesktop.Avahi.ServiceBrowser.Failure":
			if len(item.Body) != 1 {
				continue
			}

			err, ok := item.Body[0].(string)

			if !ok {
				continue
			}

			result.Err = errors.New("avahi: " + err)
		default:
			continue
		}

		select {
		case b.results <- &result:
		default:
		}
	}
}

func (b *dnssdBrowseOp) Stop() error {
	b.conn.RemoveSignal(b.newItem)
	close(b.newItem)
	close(b.results)

	return b.obj.Call("org.freedesktop.Avahi.ServiceBrowser.Free", 0).Err
}

type dnssdResolveResult struct {
	Err  error
	Host string
	Port int
	TXT  map[string]string
}

type dnssdResolveOp struct {
	conn    *dbus.Conn
	obj     dbus.BusObject
	newItem chan *dbus.Signal
	results chan<- *dnssdResolveResult
}

func newResolveOp(interfaceIndex int, name, service, domain string, results chan<- *dnssdResolveResult) (*dnssdResolveOp, error) {
	dconn, err := dbus.SystemBus()

	if err != nil {
		return nil, err
	}

	newItem := make(chan *dbus.Signal, 16)
	dconn.Signal(newItem)

	obj := dconn.Object("org.freedesktop.Avahi", "/")

	var path dbus.ObjectPath

	if err = obj.Call("org.freedesktop.Avahi.Server.ServiceResolverNew", 0,
		int32(interfaceIndex), // iinterface
		int32(-1),             // avahi.PROTO_UNSPEC
		name,                  // sname
		service,               // stype
		domain,                // sdomain
		int32(-1),             // avahi.PROTO_UNSPEC, iaprotocol
		uint32(0),             // flags
	).Store(&path); err != nil {
		dconn.RemoveSignal(newItem)
		close(newItem)

		return nil, err
	}

	r := &dnssdResolveOp{dconn, dconn.Object("org.freedesktop.Avahi", path), newItem, results}
	go r.waitForSignal()

	return r, nil
}

func (r *dnssdResolveOp) waitForSignal() {
	for item := range r.newItem {
		if item == nil || item.Path != r.obj.Path() {
			continue
		}

		var result dnssdResolveResult

		switch item.Name {
		case "org.freedesktop.Avahi.ServiceResolver.Found":
			if len(item.Body) != 11 {
				continue
			}

			_, ok0 := item.Body[0].(int32)
			_, ok1 := item.Body[1].(int32)
			_, ok2 := item.Body[2].(string)
			_, ok3 := item.Body[3].(string)
			_, ok4 := item.Body[4].(string)

			var ok5 bool
			result.Host, ok5 = item.Body[5].(string)

			_, ok6 := item.Body[6].(int32)
			_, ok7 := item.Body[7].(string)

			port, ok8 := item.Body[8].(uint16)
			result.Port = int(port)

			AAY, ok9 := item.Body[9].([][]byte)

			_, ok10 := item.Body[10].(uint32)

			if !ok0 || !ok1 || !ok2 || !ok3 || !ok4 || !ok5 || !ok6 || !ok7 || !ok8 || !ok9 || !ok10 {
				continue
			}

			result.TXT = make(map[string]string, len(AAY))

			for _, rec := range AAY {
				kv := strings.SplitN(string(rec), "=", 2)

				switch len(kv) {
				case 2:
					result.TXT[kv[0]] = kv[1]
				case 1:
					result.TXT[kv[0]] = ""
				}
			}
		case "org.freedesktop.Avahi.ServiceResolver.Failure":
			if len(item.Body) != 1 {
				continue
			}

			err, ok := item.Body[0].(string)

			if !ok {
				continue
			}

			result.Err = errors.New("avahi: " + err)
		default:
			continue
		}

		select {
		case r.results <- &result:
		default:
		}
	}
}

func (r *dnssdResolveOp) Stop() error {
	r.conn.RemoveSignal(r.newItem)
	close(r.newItem)
	close(r.results)

	return r.obj.Call("org.freedesktop.Avahi.ServiceResolver.Free", 0).Err
}

type dnssdRegisterOp struct {
	obj dbus.BusObject
}

func newRegisterOp(name, service string, port int, txt map[string]string) (*dnssdRegisterOp, error) {
	dconn, err := dbus.SystemBus()

	if err != nil {
		return nil, err
	}

	host, err := os.Hostname()

	if err != nil {
		return nil, err
	}

	if len(name) == 0 {
		name = host
	}

	var aay [][]byte

	for k, v := range txt {
		aay = append(aay, []byte(k+"="+v))
	}

	obj := dconn.Object("org.freedesktop.Avahi", "/")

	var path dbus.ObjectPath

	if err = obj.Call("org.freedesktop.Avahi.Server.EntryGroupNew", 0).Store(&path); err != nil {
		return nil, err
	}

	obj = dconn.Object("org.freedesktop.Avahi", path)

	if err = obj.Call("org.freedesktop.Avahi.EntryGroup.AddService", 0,
		int32(-1),                   // avahi.IF_UNSPEC
		int32(-1),                   // avahi.PROTO_UNSPEC
		uint32(0),                   // flags
		name,                        // sname
		service,                     // stype
		avahiDefaultDomain,          // sdomain
		host+"."+avahiDefaultDomain, // shost
		uint16(port),                // port
		aay,                         // text record
	).Err; err != nil {
		return nil, err
	}

	if err = obj.Call("org.freedesktop.Avahi.EntryGroup.Commit", 0).Err; err != nil {
		return nil, err
	}

	// http://avahi.org/download/doxygen/defs_8h.html#a141829383c5b97e9c0fa75ca0e590217

	// failure?

	return &dnssdRegisterOp{obj}, nil
}

func (r *dnssdRegisterOp) Stop() error {
	if err := r.obj.Call("org.freedesktop.Avahi.EntryGroup.Reset", 0).Err; err != nil {
		return err
	}

	return r.obj.Call("org.freedesktop.Avahi.EntryGroup.Free", 0).Err
}
