package maps

import (
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lysShub/fatcp/links"
	"github.com/lysShub/fatcp/ports"
)

type linkManager struct {
	addr     netip.Addr
	ap       *ports.Adapter
	duration time.Duration

	uplinkMap map[links.Uplink]*port
	ttl       *links.Heap[ttlkey]
	uplinkMu  sync.RWMutex

	downlinkMap map[links.Downlink]*links.Downlinker
	donwlinkMu  sync.RWMutex
}

var _ links.LinksManager = (*linkManager)(nil)

func NewLinkManager(ttl time.Duration, addr netip.Addr) *linkManager {
	return newLinkManager(ports.NewAdapter(addr), ttl)
}

func newLinkManager(ap *ports.Adapter, ttl time.Duration) *linkManager {
	return &linkManager{
		addr:     ap.Addr(),
		ap:       ap,
		duration: ttl,

		uplinkMap: map[links.Uplink]*port{},
		ttl:       links.NewHeap[ttlkey](64),

		downlinkMap: map[links.Downlink]*links.Downlinker{},
	}
}

type ttlkey struct {
	s links.Uplink
	t time.Time
}

func (t ttlkey) valid() bool {
	return t.s.Process.IsValid() && t.s.Server.IsValid() && t.t != time.Time{}
}

type port atomic.Uint64

func NewPort(p uint16) *port {
	var a = &atomic.Uint64{}
	a.Store(uint64(p) << 48)
	return (*port)(a)
}
func (p *port) p() *atomic.Uint64 { return (*atomic.Uint64)(p) }
func (p *port) Idle() bool {
	d := p.p().Load()
	const flags uint64 = 0xffff000000000000

	p.p().Store(d & flags)
	return d&(^flags) == 0
}
func (p *port) Port() uint16 { return uint16(p.p().Add(1) >> 48) }

func (t *linkManager) cleanup() {
	var (
		ls     []links.Uplink
		lports []uint16
	)
	t.uplinkMu.Lock()
	for i := 0; i < t.ttl.Size(); i++ {
		i := t.ttl.Pop()
		if i.valid() && time.Since(i.t) > t.duration {
			p := t.uplinkMap[i.s]
			if p.Idle() {
				ls = append(ls, i.s)
				lports = append(lports, p.Port())
				delete(t.uplinkMap, i.s)
			} else {
				t.ttl.Put(ttlkey{i.s, time.Now()})
			}
		} else {
			t.ttl.Put(ttlkey{i.s, time.Now()})
			break
		}
	}
	t.uplinkMu.Unlock()
	if len(ls) == 0 {
		return
	}

	var conns []*links.Conn
	t.donwlinkMu.Lock()
	for i, e := range ls {
		s := links.Downlink{Server: e.Server, Proto: e.Proto, Local: netip.AddrPortFrom(t.addr, lports[i])}
		conns = append(conns, t.downlinkMap[s].Conn)
		delete(t.downlinkMap, s)
	}
	t.donwlinkMu.Unlock()

	for i, e := range ls {
		t.ap.DelPort(e.Proto, lports[i], e.Server)
	}
	for _, e := range conns {
		if e != nil {
			e.Dec()
		}
	}
}

func (t *linkManager) Add(s links.Uplink, c *links.Conn) (localPort uint16, err error) {
	t.cleanup()

	localPort, err = t.ap.GetPort(s.Proto, s.Server)
	if err != nil {
		return 0, err
	}

	t.uplinkMu.Lock()
	t.uplinkMap[s] = NewPort(localPort)
	t.ttl.Put(ttlkey{s: s, t: time.Now()})
	t.uplinkMu.Unlock()

	t.donwlinkMu.Lock()
	t.downlinkMap[links.Downlink{
		Server: s.Server,
		Proto:  s.Proto,
		Local:  netip.AddrPortFrom(t.addr, localPort),
	}] = &links.Downlinker{
		Conn: c, Port: s.Process.Port(),
	}
	t.donwlinkMu.Unlock()

	return localPort, nil
}

// Uplink get uplink packet local port
func (t *linkManager) Uplink(s links.Uplink) (localPort uint16, has bool) {
	t.uplinkMu.RLock()
	defer t.uplinkMu.RUnlock()
	p, has := t.uplinkMap[s]
	if !has {
		return 0, false
	}
	return p.Port(), true
}

// Downlink get donwlink packet proxyer and client port
func (t *linkManager) Downlink(s links.Downlink) (p *links.Downlinker, has bool) {
	t.donwlinkMu.RLock()
	defer t.donwlinkMu.RUnlock()

	key, has := t.downlinkMap[s]
	if !has {
		return nil, false
	}
	return key, true
}

func (t *linkManager) Close() error {
	return t.ap.Close()
}
