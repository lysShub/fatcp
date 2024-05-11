package fatcp

import (
	"context"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/lysShub/fatcp/crypto"
	"github.com/lysShub/fatcp/faketcp"
	"github.com/lysShub/fatcp/ustack"
	"github.com/lysShub/fatcp/ustack/gonet"
	"github.com/lysShub/netkit/debug"
	"github.com/lysShub/netkit/packet"
	"github.com/lysShub/rawsock/test"
	"github.com/pkg/errors"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

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

/*
	握手关键需要处理好边界情况；关键函数是gonet.WaitBeforeDataTransmitted。
	流程：
		handshake1完成后，（handshak2阶段）等待对方握手完成，期间将不会主动发送数据包。判定对方握手完成的依据是我方
		在握手期间发送的数据包全部被对方收到--WaitBeforeDataTransmitted。
		a. 对于outboundService，在handshak2完成后，发送的是control-segment包, 而不是原始的tcp数据包。
		b. 对于handshakeInboundService，在handshak2完成后，才能退出。
		c. 如果handshakeInboundService运行时收到segment包，若此时hanshake1已经完成，应该尝试decode，session-id是CtrSessID
			必须inbound stack，否则应该将其暂存。
		d. 如果Recv收到非segment包，应该忽略。

		c/d 属于边界情况，一般不会有太多数据包处于这种状态。
*/

func (c *Conn) handshake(ctx context.Context) (err error) {
	if !c.state.CompareAndSwap(initial, handshake1) {
		c.handshakedNotify.Wait() // handshake started, wait finish
		return nil
	}

	srvCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go c.handshakeInboundService(srvCtx)

	tcp, err := c.factory.factory(ctx)
	if err != nil {
		return err
	}

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
		return errors.Errorf("sconn invalid role %d", c.role)
	}

	pseudoSum1 := header.PseudoHeaderChecksum(
		header.TCPProtocolNumber,
		tcpip.AddrFromSlice(c.raw.LocalAddr().Addr().AsSlice()),
		tcpip.AddrFromSlice(c.raw.RemoteAddr().Addr().AsSlice()),
		0,
	)
	if cpt, err := crypto.NewTCP(key, pseudoSum1); err != nil {
		return err
	} else {
		c.fake = faketcp.New(
			c.raw.LocalAddr().Port(),
			c.raw.RemoteAddr().Port(),
			faketcp.Crypto(cpt),
		)
	}
	c.state.CompareAndSwap(handshake1, handshake2)

	// wait before writen data be recved by peer.
	if sndnxt, rcvnxt, err := tcp.WaitBeforeDataTransmitted(ctx); err != nil {
		return err
	} else {
		c.fake.InitNxt(sndnxt, rcvnxt)
	}

	c.handshakedTime = time.Now()
	c.tcp = tcp
	c.state.CompareAndSwap(handshake2, transmit)
	c.handshakedNotify.Done()
	return nil
}

func (c *Conn) handshakeInboundService(ctx context.Context) error {
	var (
		pkt = packet.Make(c.config.MaxRecvBuffSize)
	)

	for {
		err := c.raw.Read(ctx, pkt.SetHead(0))
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return nil
			}
			return c.close(err)
		}

		if debug.Debug() {
			old := pkt.Head()
			pkt.SetHead(0)
			test.ValidIP(test.P(), pkt.Bytes())
			pkt.SetHead(old)
		}

		if faketcp.Is(pkt.Bytes()) {
			seg := pkt.Clone()

			if c.state.Load() >= handshake2 &&
				c.fake.DetachRecv(seg) == nil &&
				decode(seg) == ControlPeer {

				c.inboundControlPacket(seg)
			} else {
				c.handshakeRecvSegs.put(pkt)
			}

			if c.state.Load() == transmit {
				return nil
			}
		} else {
			c.ep.Inbound(pkt)
		}
	}
}

// heap simple heap buff, only support concurrent pop,
// and not support cross pop/put operate.
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
