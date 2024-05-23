package link

import (
	"context"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pkg/errors"

	"github.com/lysShub/netkit/packet"

	"github.com/lysShub/netkit/debug"
	"github.com/lysShub/rawsock/test"
	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type List struct {
	id   string
	list listIface

	dispatcher   stack.NetworkDispatcher
	dispatcherMu sync.RWMutex

	mtu                int
	LinkEPCapabilities stack.LinkEndpointCapabilities
	SupportedGSOKind   stack.SupportedGSO
	closed             atomic.Bool
}

var _ Link = (*List)(nil)

func NewList(buff, mtu int) *List {
	buff = max(buff, 4)
	return &List{
		// list:         newHeap(size), // todo: heap can't pass ut, fix bug
		list: newSlice(buff),
		mtu:  mtu,
	}
}

func NewListWithID(buff, mut int, id string) *List {
	l := NewList(buff, mut)
	l.id = id
	return l
}

var _ stack.LinkEndpoint = (*List)(nil)

func (l *List) SynClose(timeout time.Duration) error {
	if l.closed.CompareAndSwap(false, true) {
		if err := l.list.Close(); err != nil {
			return err
		}

		dead := time.Now().Add(timeout)
		for l.list.Size() > 0 || time.Now().Before(dead) {
			time.Sleep(time.Millisecond * 10)
		}

		n := l.list.Size()
		if n > 0 {
			return errors.Errorf("SynClose timeout %s", timeout.String())
		}
	}
	return nil
}

func (l *List) Outbound(ctx context.Context, tcp *packet.Packet) error {
	return l.outboundBy(ctx, netip.AddrPort{}, tcp)
}

func (l *List) OutboundBy(ctx context.Context, dst netip.AddrPort, tcp *packet.Packet) error {
	return l.outboundBy(ctx, dst, tcp)
}

func (l *List) outboundBy(ctx context.Context, dst netip.AddrPort, tcp *packet.Packet) error {
	var pkb *stack.PacketBuffer
	if dst.IsValid() {
		pkb = l.list.GetBy(ctx, dst)
	} else {
		pkb = l.list.Get(ctx)
	}
	if pkb.IsNil() {
		return errors.WithStack(ctx.Err())
	}
	defer pkb.DecRef()

	tcp.SetData(0)
	if debug.Debug() {
		require.LessOrEqual(test.T(), pkb.Size(), l.mtu)
		require.GreaterOrEqual(test.T(), tcp.Tail(), pkb.Size())
	}
	for _, e := range pkb.AsSlices() {
		tcp.Append(e)
	}
	tcp.SetHead(tcp.Head() + len(pkb.NetworkHeader().Slice()))

	return nil
}

func (l *List) Inbound(ip *packet.Packet) {
	if debug.Debug() {
		test.ValidIP(test.T(), ip.Bytes())
	}

	pkb := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(ip.Bytes()),
	})

	l.dispatcherMu.RLock()
	d := l.dispatcher
	l.dispatcherMu.RUnlock()
	if d != nil {
		l.dispatcher.DeliverNetworkPacket(header.IPv4ProtocolNumber, pkb)
	}
}

func (l *List) WritePackets(pkts stack.PacketBufferList) (int, tcpip.Error) {
	if l.closed.Load() {
		return 0, &tcpip.ErrClosedForSend{}
	}

	for i, pkb := range pkts.AsSlice() {
		ok := l.list.Put(pkb)
		if !ok {
			return i, &tcpip.ErrNoBufferSpace{}
		}
	}
	return pkts.Len(), nil
}

func (l *List) ARPHardwareType() header.ARPHardwareType { return header.ARPHardwareNone }
func (l *List) AddHeader(*stack.PacketBuffer)           {}
func (l *List) Attach(dispatcher stack.NetworkDispatcher) {
	l.dispatcherMu.Lock()
	defer l.dispatcherMu.Unlock()
	l.dispatcher = dispatcher
}
func (l *List) Capabilities() stack.LinkEndpointCapabilities { return l.LinkEPCapabilities }
func (l *List) GSOMaxSize() uint32                           { return 1 << 15 }
func (l *List) IsAttached() bool {
	l.dispatcherMu.RLock()
	defer l.dispatcherMu.RUnlock()
	return l.dispatcher != nil
}
func (l *List) LinkAddress() tcpip.LinkAddress       { return "" }
func (l *List) MTU() uint32                          { return uint32(l.mtu) }
func (l *List) MaxHeaderLength() uint16              { return 0 }
func (l *List) NumQueued() int                       { return l.list.Size() }
func (l *List) ParseHeader(*stack.PacketBuffer) bool { return true }
func (l *List) SupportedGSO() stack.SupportedGSO     { return l.SupportedGSOKind }
func (l *List) Wait()                                {}

type listIface interface {
	Put(pkb *stack.PacketBuffer) (ok bool)
	Get(ctx context.Context) (pkb *stack.PacketBuffer)
	GetBy(ctx context.Context, dst netip.AddrPort) (pkb *stack.PacketBuffer)
	Size() int
	Close() error
}

type slice struct {
	s           []*stack.PacketBuffer
	mu          sync.RWMutex
	writeNotify *sync.Cond
}

func newSlice(size int) *slice {
	var s = &slice{
		s: make([]*stack.PacketBuffer, 0, size),
	}
	s.writeNotify = sync.NewCond(&s.mu)
	return s
}

var _ listIface = (*slice)(nil)

func (s *slice) Put(pkb *stack.PacketBuffer) (ok bool) {
	defer s.writeNotify.Broadcast()
	if pkb.IsNil() {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.s) == cap(s.s) {
		// 如果已经Put的包长时间没被读取，需要将其丢弃
		// todo: 优化, 写得太直接了
		if debug.Debug() {
			println("link endpoint buff too small")
		}
		s.get().DecRef()
	}

	s.s = append(s.s, pkb.IncRef())
	return true
}

func (s *slice) Get(ctx context.Context) (pkb *stack.PacketBuffer) {
	pkb = s.get()
	if !pkb.IsNil() {
		return pkb
	}

	for {
		// todo: ctx isn't timely
		select {
		case <-ctx.Done():
			return nil
		default:
			s.mu.Lock()
			s.writeNotify.Wait()
			s.mu.Unlock()

			pkb = s.get()
			if !pkb.IsNil() {
				return pkb
			}
		}
	}
}

func (s *slice) GetBy(ctx context.Context, dst netip.AddrPort) (pkb *stack.PacketBuffer) {
	pkb = s.getBy(dst)
	if !pkb.IsNil() {
		return pkb
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
			s.mu.Lock()
			s.writeNotify.Wait()
			s.mu.Unlock()

			pkb = s.getBy(dst)
			if !pkb.IsNil() {
				return pkb
			}
		}
	}
}

func (s *slice) get() (pkb *stack.PacketBuffer) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.s) > 0 {
		pkb = s.s[0]
		n := copy(s.s, s.s[1:])
		s.s = s.s[:n]
		return pkb
	} else {
		return nil
	}
}

func (s *slice) getBy(dst netip.AddrPort) (pkb *stack.PacketBuffer) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i, e := range s.s {
		if match(e, dst) {
			pkb = s.s[i]

			n := copy(s.s[i:], s.s[i+1:])
			s.s = s.s[:i+n]
			return pkb
		}
	}
	return nil
}

func (s *slice) Size() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.s)
}

func (s *slice) Close() error {
	return nil // todo:
}
