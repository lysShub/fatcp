package ports

import (
	"net/netip"
	"sort"
	"sync"

	"github.com/pkg/errors"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

type Adapter struct {
	mgr *Manager

	mu sync.RWMutex

	ports map[portKey]*AddrSet // {local-port, proto} : {remote-addrs}
}

type portKey struct {
	proto     uint8
	loaclPort uint16
}

// NewAdapter for reuse local machine port, reduce port consume
func NewAdapter(addr netip.Addr) *Adapter {
	return &Adapter{
		mgr:   NewMgr(addr),
		ports: make(map[portKey]*AddrSet, 16),
	}
}

// GetPort get a local machine port
func (a *Adapter) GetPort(proto tcpip.TransportProtocolNumber, remote netip.AddrPort) (port uint16, err error) {
	// try reuse alloced port, require remote-addr differently
	a.mu.RLock()
	for k, v := range a.ports {
		if k.proto != uint8(proto) {
			continue
		}

		if !v.Has(remote) {
			port = k.loaclPort
			break
		}
	}
	a.mu.RUnlock()

	// alloc new port
	if port == 0 {
		switch proto {
		case header.TCPProtocolNumber:
			port, err = a.mgr.GetTCPPort()
			if err != nil {
				return 0, err
			}
		case header.UDPProtocolNumber:
			port, err = a.mgr.GetUDPPort()
			if err != nil {
				return 0, err
			}
		default:
			return 0, errors.Errorf("unknown transport protocol %d", proto)
		}
	}

	// update map
	pk := portKey{proto: uint8(proto), loaclPort: port}
	a.mu.Lock()
	if as := a.ports[pk]; as != nil {
		as.Add(remote)
	} else {
		as = &AddrSet{}
		as.Add(remote)
		a.ports[pk] = as
	}
	a.mu.Unlock()

	if proto == header.TCPProtocolNumber && port == 443 {
		panic("")
	}
	return port, nil
}

// todo: idle timeout delete
func (a *Adapter) DelPort(proto tcpip.TransportProtocolNumber, port uint16, remote netip.AddrPort) error {
	pk := portKey{
		proto:     uint8(proto),
		loaclPort: port,
	}

	notuse := false
	a.mu.Lock()
	a.ports[pk].Del(remote)
	if a.ports[pk].Len() == 0 {
		delete(a.ports, pk)
		notuse = true
	}
	a.mu.Unlock()

	if notuse {
		switch proto {
		case header.TCPProtocolNumber:
			return a.mgr.DelTCPPort(port)
		case header.UDPProtocolNumber:
			return a.mgr.DelUDPPort(port)
		default:
			return errors.Errorf("unknown transport protocol %d", proto)
		}
	}
	return nil
}

func (a *Adapter) Close() (err error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	for pk := range a.ports {
		var e error
		switch pk.proto {
		case uint8(header.TCPProtocolNumber):
			e = a.mgr.DelTCPPort(pk.loaclPort)
		case uint8(header.UDPProtocolNumber):
			e = a.mgr.DelUDPPort(pk.loaclPort)
		default:
		}
		if e != nil {
			err = e
		}
	}

	a.ports = map[portKey]*AddrSet{}
	return err
}

type AddrSet struct {
	addrs addrs
}

type addrs []netip.AddrPort

func (a addrs) Len() int           { return len(a) }
func (a addrs) Less(i, j int) bool { return less(a[i], a[j]) }
func less(a, b netip.AddrPort) bool {
	if a.Addr() != b.Addr() {
		return a.Addr().Less(b.Addr())
	} else {
		return a.Port() < b.Port()
	}
}
func (a addrs) Swap(i, j int) { a[i], a[j] = a[j], a[i] }

// idx<0 not Find
func (a AddrSet) Find(addr netip.AddrPort) (idx int) {
	i := sort.Search(len(a.addrs), func(i int) bool {
		return !less(a.addrs[i], addr)
	})
	if i < len(a.addrs) && a.addrs[i] == addr {
		return i
	}
	return -1
}
func (a AddrSet) Has(addr netip.AddrPort) bool {
	return a.Find(addr) >= 0
}
func (a *AddrSet) Add(addr netip.AddrPort) {
	if !a.Has(addr) {
		a.addrs = append(a.addrs, addr)
		sort.Sort(a.addrs)
	}
}
func (a *AddrSet) Del(addr netip.AddrPort) {
	i := a.Find(addr)
	if i < 0 {
		return
	}
	copy(a.addrs[i:], a.addrs[i+1:])
	a.addrs = a.addrs[:len(a.addrs)-1]
}
func (a *AddrSet) Len() int { return len(a.addrs) }
