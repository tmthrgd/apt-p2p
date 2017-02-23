package main

import (
	"bytes"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/ioutil"
	"log"
	"mime"
	"net/http"
	"path"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/godbus/dbus"
	"github.com/godbus/dbus/introspect"
	"github.com/godbus/dbus/prop"
	"github.com/tmthrgd/apt-p2p/hash"
)

const (
	dbusIface = "com.github.tmthrgd.AptP2P"
	dbusPath  = "/"

	dbusNameUntrustedPeer = dbusIface + ".UntrustedPeer"
	dbusNamePeerAdded     = dbusIface + ".PeerAdded"
	dbusNamePeerRemoved   = dbusIface + ".PeerRemoved"

	dbusPeerIface = dbusIface + ".Peer"
	dbusPeerPath  = "/com/github/tmthrgd/AptP2P/peer/%d"

	dbusPeerNameRemoved = dbusPeerIface + ".Removed"

	dbusIntrospectableIface = "org.freedesktop.DBus.Introspectable"
)

var errDBusNameTaken = errors.New("D-Bus name " + dbusIface + " already taken")

var intro = template.Must(template.New("dbus-intro").Funcs(map[string]interface{}{"relativepath": relativePath}).Parse(`<node>
	<interface name="` + dbusIface + `">
		<annotation name="org.freedesktop.DBus.Property.EmitsChangedSignal" value="const"/>

		<property name="ProxyAddress" type="s" access="read">
			<annotation name="org.freedesktop.DBus.Property.EmitsChangedSignal" value="true"/>
		</property>

		<property name="Hash" type="s" access="read"/>

		<property name="Peers" type="ao" access="read">
			<annotation name="org.freedesktop.DBus.Property.EmitsChangedSignal" value="invalidates"/>
		</property>

		<method name="AddPeer">
			<arg name="name" type="s" direction="in"/>
			<arg name="host" type="s" direction="in"/>
			<arg name="port" type="q" direction="in"/>
			<arg name="hash" type="s" direction="in"/>

			<arg name="path" type="o" direction="out"/>
		</method>

		<signal name="PeerAdded">
			<arg name="path" type="o"/>
		</signal>
		<signal name="PeerRemoved">
			<arg name="path" type="o"/>
		</signal>

		<signal name="UntrustedPeer">
			<arg name="name" type="s"/>
			<arg name="host" type="s"/>
			<arg name="port" type="q"/>
			<arg name="hash" type="s"/>
		</signal>
	</interface>
` + introspect.IntrospectDataString + prop.IntrospectDataString + `{{range .}}
	<node name="{{relativepath . "/"}}"/>
{{end}}</node>`))

const peerIntro = `<node>
	<interface name="` + dbusPeerIface + `">
		<annotation name="org.freedesktop.DBus.Property.EmitsChangedSignal" value="const"/>

		<property name="Name" type="s" access="read"/>
		<property name="Hash" type="s" access="read"/>
		<property name="Address" type="s" access="read"/>

		<method name="HasFile">
			<arg name="hash" type="s" direction="in"/>
			<arg name="name" type="s" direction="in"/>

			<arg name="yes" type="b" direction="out"/>
		</method>

		<method name="Remove"/>

		<signal name="Removed"/>
	</interface>
` + introspect.IntrospectDataString + prop.IntrospectDataString + `</node>`

func relativePath(path, base dbus.ObjectPath) dbus.ObjectPath {
	return dbus.ObjectPath(strings.TrimPrefix(string(path), string(base)))
}

type dBusExport struct{}

func (dBusExport) AddPeer(name, host string, port uint16, spki string) (dbus.ObjectPath, *dbus.Error) {
	for _, param := range [...]struct {
		name  string
		valid bool
	}{
		{"string:name", len(name) != 0},
		{"string:host", len(host) != 0},
		{"uint16:port", int(port) != 0},
		{"string:spki", len(spki) != 0},
	} {
		if !param.valid {
			return "", dbus.NewError("org.freedesktop.DBus.Error.InvalidArgs", []interface{}{"Invalid arg " + param.name})
		}
	}

	spkiHash, err := hash.Parse(spki)
	if err != nil {
		log.Println(err)
		return "", dbus.NewError("org.freedesktop.DBus.Error.InvalidArgs", []interface{}{"Invalid arg string:spki"})
	}

	peers.Lock()
	peer, ok := peers.m[host]
	peers.Unlock()

	if !ok {
		log.Printf(`Trusting peer "%s" running on port %d with spki: %s`, host, port, spki)

		peer = newPeer(name, strings.TrimSuffix(host, "."), int(port), spkiHash)
		peer.Add()
	}

	exportedPeers.Lock()
	defer exportedPeers.Unlock()

	for _, p := range exportedPeers.s {
		if p.peer == peer {
			return p.path, nil
		}
	}

	return "", dbus.NewError("org.freedesktop.DBus.Error.Failed", []interface{}{"exportedPeers does not contain peer"})
}

type dbusPeerExport struct {
	path dbus.ObjectPath
	peer *aptPeer
}

var exportedPeers = struct {
	sync.Mutex
	s     []*dbusPeerExport
	paths []dbus.ObjectPath
}{}

func (e *dbusPeerExport) HasFile(hash, name string) (bool, *dbus.Error) {
	for _, param := range [...]struct {
		name  string
		valid bool
	}{
		{"string:hash", len(hash) != 0},
		{"string:name", len(name) != 0},
	} {
		if !param.valid {
			return false, dbus.NewError("org.freedesktop.DBus.Error.InvalidArgs", []interface{}{"Invalid arg " + param.name})
		}
	}

	headers := http.Header{}

	if mimeType := mime.TypeByExtension(path.Ext(name)); len(mimeType) != 0 && !strings.Contains(mimeType, ";") {
		headers.Add("Accept", mimeType+"; q=1.0, */*; q=0.1")
	}

	resp, err := e.peer.Head(path.Join("/get", hash, name), headers)
	if err != nil {
		log.Println(err)
		return false, dbus.NewError("org.freedesktop.DBus.Error.Failed", []interface{}{err.Error()})
	}

	// https://golang.org/src/net/http/client.go#L570
	// Read the body if small so underlying TCP connection will be re-used.
	// No need to check for errors: if it fails, Transport won't reuse it anyway.
	const maxBodySlurpSize = 2 << 10
	if resp.ContentLength == -1 || resp.ContentLength <= maxBodySlurpSize {
		io.CopyN(ioutil.Discard, resp.Body, maxBodySlurpSize)
	}
	resp.Body.Close()

	return resp.StatusCode >= 200 && resp.StatusCode < 300, nil
}

func (e *dbusPeerExport) Remove() *dbus.Error {
	if e.peer.Removed() {
		return dbus.NewError("org.freedesktop.DBus.Error.Failed", []interface{}{"Peer does not exist"})
	}

	if config.Verbose {
		log.Printf(`Removing trust in peer "%s" running on port %d with spki: %s`, e.peer.host, e.peer.port, e.peer.spki)
	}

	e.peer.Remove()
	return nil
}

var dbusProps *prop.Properties

func dbusServe(done chan struct{}) error {
	conn, err := dbus.SystemBus()
	if err != nil {
		return err
	}

	reply, err := conn.RequestName(dbusIface, dbus.NameFlagDoNotQueue)
	if err != nil {
		return err
	}

	if reply != dbus.RequestNameReplyPrimaryOwner {
		return errDBusNameTaken
	}

	var buf bytes.Buffer

	if err = conn.Export(dBusExport{}, dbusPath, dbusIface); err != nil {
		goto handleError
	}

	exportedPeers.Lock()

	if err = intro.Execute(&buf, exportedPeers.paths); err != nil {
		exportedPeers.Unlock()
		goto handleError
	}

	if err = conn.Export(introspect.Introspectable(buf.String()), dbusPath, dbusIntrospectableIface); err != nil {
		exportedPeers.Unlock()
		goto handleError
	}

	exportedPeers.paths = exportedPeers.paths[:0]

	for _, peer := range exportedPeers.s {
		exportedPeers.paths = append(exportedPeers.paths, peer.path)
	}

	dbusProps = prop.New(conn, dbusPath, map[string]map[string]*prop.Prop{
		dbusIface: map[string]*prop.Prop{
			"ProxyAddress": &prop.Prop{Value: config.Proxy.Address, Emit: prop.EmitTrue},
			"Hash":         &prop.Prop{Value: spkiHash.String()},
			"Peers":        &prop.Prop{Value: exportedPeers.paths, Emit: prop.EmitInvalidates},
		},
	})
	exportedPeers.Unlock()

	<-done

	if _, err = conn.ReleaseName(dbusIface); err != nil {
		return err
	}

	done <- struct{}{}
	return nil

handleError:
	if _, err := conn.ReleaseName(dbusIface); err != nil {
		log.Println(err)
	}

	return err
}

func untrustedPeer(name, host string, port int, spki *hash.Hash) error {
	conn, err := dbus.SystemBus()
	if err != nil {
		return err
	}

	return conn.Emit(dbusPath, dbusNameUntrustedPeer, name, host, uint16(port), spki.String())
}

var peerID uint64

func addedPeer(peer *aptPeer) error {
	conn, err := dbus.SystemBus()
	if err != nil {
		return err
	}

	exportedPeers.Lock()
	defer exportedPeers.Unlock()

	e := &dbusPeerExport{dbus.ObjectPath(fmt.Sprintf(dbusPeerPath, atomic.AddUint64(&peerID, 1))), peer}

	if err = conn.Export(e, e.path, dbusPeerIface); err != nil {
		return err
	}

	var buf bytes.Buffer

	if err = conn.Export(introspect.Introspectable(peerIntro), e.path, dbusIntrospectableIface); err != nil {
		goto handleError
	}

	exportedPeers.s = append(exportedPeers.s, e)
	exportedPeers.paths = append(exportedPeers.paths, e.path)

	if dbusProps != nil {
		dbusProps.SetMust(dbusIface, "Peers", exportedPeers.paths)
	}

	if err = intro.Execute(&buf, exportedPeers.paths); err != nil {
		goto handleError
	}

	if err = conn.Export(introspect.Introspectable(buf.String()), dbusPath, dbusIntrospectableIface); err != nil {
		goto handleError
	}

	prop.New(conn, e.path, map[string]map[string]*prop.Prop{
		dbusPeerIface: map[string]*prop.Prop{
			"Name":    &prop.Prop{Value: peer.name},
			"Hash":    &prop.Prop{Value: peer.spki.String()},
			"Address": &prop.Prop{Value: peer.address},
		},
	})

	return conn.Emit(dbusPath, dbusNamePeerAdded, e.path)

handleError:
	for _, iface := range [...]string{"org.freedesktop.DBus.Properties", dbusIntrospectableIface, dbusPeerIface} {
		if err := conn.Export(nil, e.path, iface); err != nil {
			log.Println(err)
		}
	}

	return err
}

func removedPeer(peer *aptPeer) error {
	conn, err := dbus.SystemBus()
	if err != nil {
		return err
	}

	exportedPeers.Lock()
	defer exportedPeers.Unlock()

	var e *dbusPeerExport

	for i, p := range exportedPeers.s {
		if p.peer == peer {
			if p.path != exportedPeers.paths[i] {
				panic("order of exportedPeers.s and exportedPeers.paths differ")
			}

			e = p

			copy(exportedPeers.s[i:], exportedPeers.s[i+1:])
			exportedPeers.s[len(exportedPeers.s)-1] = nil
			exportedPeers.s = exportedPeers.s[:len(exportedPeers.s)-1]

			exportedPeers.paths = append(exportedPeers.paths[:i], exportedPeers.paths[i+1:]...)
			break
		}
	}

	if e == nil {
		panic("Peer removed but not added")
	}

	if dbusProps != nil {
		dbusProps.SetMust(dbusIface, "Peers", exportedPeers.paths)
	}

	var buf bytes.Buffer

	if err = intro.Execute(&buf, exportedPeers.paths); err != nil {
		return err
	}

	if err = conn.Export(introspect.Introspectable(buf.String()), dbusPath, dbusIntrospectableIface); err != nil {
		return err
	}

	for _, iface := range [...]string{"org.freedesktop.DBus.Properties", dbusIntrospectableIface, dbusPeerIface} {
		if err = conn.Export(nil, e.path, iface); err != nil {
			return err
		}
	}

	if err = conn.Emit(dbusPath, dbusNamePeerRemoved, e.path); err != nil {
		return err
	}

	return conn.Emit(e.path, dbusPeerNameRemoved)
}
