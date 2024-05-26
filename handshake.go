package fatcp

import (
	"context"
	"net/netip"
	"sync/atomic"

	"github.com/lysShub/fatcp/crypto"
	"github.com/lysShub/fatcp/faketcp"
	"github.com/lysShub/fatcp/ustack"
	"github.com/lysShub/fatcp/ustack/gonet"
	"github.com/lysShub/netkit/debug"
	"github.com/lysShub/netkit/packet"
	"github.com/lysShub/rawsock/test"
	"github.com/pkg/errors"
	"golang.org/x/sync/errgroup"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

/*
	fatcp 中, TCP数据包分为fake和非fake, 握手完成之前, 发送的是非fake数据包, 和正常的tcp连接没有区别。
	握手：
		handshake1 阶段将发送和接收所有数据, 但不保证发送的数据被对方接收, 也不保证接收的数据回复了ACK;
		handshake2 阶段等待对方完成握手, 即发送的数据被对方接收 ---	WaitSentDataRecvByPeer。此时双方
			应收的数据包都均已收到，结束握手。

		a. 对于outboundService，在handshak2完成后，发送的是fake-builtin包, 而不是原始的tcp数据包。
		b. 如果handshakeInboundService运行时收到fake包；若此时hanshake1已经完成，应该尝试decode，如果是builtin数据包
			必须inbound stack；否则应该将其暂存。
		d. 如果Recv收到非fake包，应该忽略。

		c/d 属于边界情况，一般不会有太多数据包处于这种状态。
*/

type state = atomic.Uint32

const (
	initial    uint32 = 0
	handshake1 uint32 = 1 // handshake send data stage
	handshake2 uint32 = 2 // wait peer recved all data
	transmit   uint32 = 3
	closed     uint32 = 4
)

func (c *conn) handshake(ctx context.Context) (err error) {
	if !c.state.CompareAndSwap(initial, handshake1) {
		c.handshakedNotify.Wait() // handshake started, wait finish
		return nil
	}

	handshakeCtx, cancel := context.WithCancel(ctx)
	wg, _ := errgroup.WithContext(handshakeCtx)
	defer wg.Wait()
	defer cancel()
	wg.Go(func() error {
		c.handshakeInboundService(handshakeCtx)
		return nil
	})

	tcp, err := c.factory.factory(ctx)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			tcp.Close()
		}
	}()

	var key crypto.Key
	if c.role == server {
		if key, err = c.config.Handshake.Server(ctx, tcp); err != nil {
			return err
		}
	} else if c.role == client {
		if key, err = c.config.Handshake.Client(ctx, tcp); err != nil {
			return err
		}
	} else {
		return errors.Errorf("fatcp invalid role %d", c.role)
	}

	pseudoSum1 := header.PseudoHeaderChecksum(
		header.TCPProtocolNumber,
		tcpip.AddrFromSlice(c.raw.LocalAddr().Addr().AsSlice()),
		tcpip.AddrFromSlice(c.raw.RemoteAddr().Addr().AsSlice()),
		0,
	)

	var opt func(*faketcp.FakeTCP)
	if key == (crypto.Key{}) {
		opt = faketcp.PseudoSum1(pseudoSum1)
	} else {
		cpt, err := crypto.NewTCP(key, pseudoSum1)
		if err != nil {
			return err
		}
		opt = faketcp.Crypto(cpt)

	}
	c.fake = faketcp.New(c.raw.LocalAddr().Port(), c.raw.RemoteAddr().Port(), opt)

	c.state.CompareAndSwap(handshake1, handshake2)

	// wait before writen data be recved by peer.
	if sndnxt, rcvnxt, err := tcp.WaitSentDataRecvByPeer(ctx); err != nil {
		return err
	} else {
		c.fake.InitNxt(sndnxt, rcvnxt)
	}

	c.tcp = tcp
	c.state.CompareAndSwap(handshake2, transmit)
	c.handshakedNotify.Done()
	return nil
}

func (c *conn) handshakeInboundService(ctx context.Context) (_ error) {
	_ = ctx
	// todo
	// stop := context.AfterFunc(ctx, func() { c.raw.SetReadDeadline(time.Now()) })
	// defer stop()

	var tcp = packet.Make(c.config.MTU)
	for {
		err := c.raw.Read(tcp.Sets(0, c.config.MTU))
		if err != nil {
			return c.close(err)
		}

		if debug.Debug() {
			old := tcp.Head()
			tcp.SetHead(0)
			test.ValidIP(test.P(), tcp.Bytes())
			tcp.SetHead(old)
		}

		if faketcp.Is(tcp.Bytes()) {
			switch state := c.state.Load(); state {
			case handshake1:
				// handshake1 state can't call c.fake, only ignore it
			case handshake2:
				// try DetachRecv, if builtin should Inbound, otherwise temporary cache
				if tmp := c.tryDecodeBuiltinFakePacket(tcp.Clone()); tmp != nil {
					c.inboundBuitinPacket(tmp)
				} else {
					c.handshakeRecvedFakePackets.put(tcp)
				}
			case transmit:
				// try DetachRecv, if builtin should Inbound, otherwise ignore it
				if tmp := c.tryDecodeBuiltinFakePacket(tcp.Clone()); tmp != nil {
					c.inboundBuitinPacket(tmp)
				}
				return nil
			default:
				return c.close(errors.Errorf("unexpect state %d", state))
			}
		} else {
			c.ep.Inbound(tcp)
		}
	}
}

func (c *conn) tryDecodeBuiltinFakePacket(pkt *packet.Packet) (tcp *packet.Packet) {
	if c.state.Load() <= handshake1 {
		return nil
	}

	if err := c.fake.DetachRecv(pkt); err != nil {
		return nil
	}
	var a = c.a.Builtin() // Decode will overwrite a, so a.IsBuiltin() depend on pkt data
	if a.Decode(pkt) == nil && a.IsBuiltin() {
		return pkt
	}
	return nil
}

type tcpFactory interface {
	factory(ctx context.Context) (*gonet.TCPConn, error)
	Close() error
}

type clientFactory struct {
	local, remote netip.AddrPort
	stack         ustack.Ustack
}

func (c *clientFactory) factory(ctx context.Context) (*gonet.TCPConn, error) {
	tcp, err := gonet.DialTCPWithBind(
		ctx, c.stack,
		c.local, c.remote,
		header.IPv4ProtocolNumber,
	)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return tcp, nil
}

func (c *clientFactory) Close() error { return c.stack.Close() }

type serverFactory struct {
	l      *gonet.TCPListener
	remote netip.AddrPort
}

func (s *serverFactory) factory(ctx context.Context) (*gonet.TCPConn, error) {
	tcp, err := s.l.AcceptBy(ctx, s.remote)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return tcp, nil
}

func (s *serverFactory) Close() error { return nil }

// heap simple heap buff, only support concurrent pop,
// and not support cross pop/put or concurrent put operate.
type heap struct {
	data [heapsize]*packet.Packet // desc operate
	idx  atomic.Int32
}

const heapsize = 8

func (h *heap) put(pkt *packet.Packet) bool {
	if h.data[heapsize-1] != nil {
		return false
	}

	for i := 0; i < heapsize; i++ {
		if h.data[i] == nil {
			h.data[i] = pkt.Clone()
			return true
		}
	}
	return false
}

func (h *heap) pop(pkt *packet.Packet) bool {
	idx := h.idx.Add(1) - 1
	if idx >= heapsize {
		h.idx.Store(heapsize) // avoid h.idx inc overflow
		return false
	}

	if h.data[idx] != nil {
		pkt.SetData(0).Append(h.data[idx].Bytes())
		return true
	}
	return false
}
