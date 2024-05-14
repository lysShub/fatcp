package fatcp

import (
	"context"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lysShub/fatcp/faketcp"
	"github.com/lysShub/fatcp/ustack"
	"github.com/lysShub/fatcp/ustack/gonet"
	"github.com/lysShub/netkit/errorx"
	"github.com/lysShub/netkit/packet"
	"github.com/lysShub/rawsock"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/tcpip/header"

	"github.com/lysShub/netkit/debug"
	"github.com/lysShub/rawsock/test"
)

// security datagram conn
type Conn[A Attacher] struct {
	config     *Config
	raw        rawsock.RawConn
	clientPort uint16
	role       role
	state      state
	tinyCnt    int

	handshakedTime    time.Time
	handshakedNotify  sync.WaitGroup
	handshakeRecvSegs *heap

	ep      *ustack.LinkEndpoint
	factory tcpFactory
	tcp     net.Conn // builtin tcp conn

	fake *faketcp.FakeTCP //

	srvCtx    context.Context
	srvCancel context.CancelFunc
	closeErr  atomic.Pointer[error]
}

type role uint8

const (
	client role = 1
	server role = 2
)

func newConn[A Attacher](raw rawsock.RawConn, ep *ustack.LinkEndpoint, role role, config *Config) (*Conn[A], error) {
	var c = &Conn[A]{
		config: config,
		raw:    raw,
		role:   role,

		handshakeRecvSegs: &heap{},
		ep:                ep,
	}
	switch role {
	case client:
		c.clientPort = raw.LocalAddr().Port()
	case server:
		c.clientPort = raw.RemoteAddr().Port()
	default:
		return nil, errors.Errorf("unknown role %d", role)
	}
	c.handshakedNotify.Add(1)
	c.srvCtx, c.srvCancel = context.WithCancel(context.Background())

	go c.outboundService()
	return c, nil
}

func (c *Conn[A]) close(cause error) error {
	if c.closeErr.CompareAndSwap(nil, &os.ErrClosed) {
		if c.tcp != nil {
			// maybe closed before, ignore return error
			c.tcp.Close()

			// wait tcp close finished
			if gotcp, ok := c.tcp.(*gonet.TCPConn); ok {
				ctx, cancel := context.WithTimeout(context.Background(), time.Second*3)
				defer cancel()
				gotcp.WaitSentDataRecvByPeer(ctx)
			}
		}
		if c.ep != nil {
			if err := c.ep.Close(); err != nil {
				cause = err
			}
		}

		if c.srvCancel != nil {
			c.srvCancel()
		}

		if c.raw != nil {
			if err := c.raw.Close(); err != nil {
				cause = err
			}
		}

		if cause != nil {
			c.closeErr.Store(&cause)
		}
		return cause
	}
	return *c.closeErr.Load()
}

func (c *Conn[A]) outboundService() error {
	var (
		pkt      = packet.Make(c.config.MTU)
		builtin  = ((*new(A)).Builtin()).(A)
		overhead = Overhead[A]()
	)

	for {
		err := c.ep.Outbound(c.srvCtx, pkt.Sets(overhead, 0xffff))
		if err != nil {
			return c.close(err)
		}
		if debug.Debug() {
			require.GreaterOrEqual(test.T(), pkt.Head(), overhead)
		}

		if c.state.Load() == transmit {
			err = c.Send(c.srvCtx, pkt, builtin)
			if err != nil {
				return c.close(err)
			}
		} else {
			err = c.raw.Write(context.Background(), faketcp.ToNot(pkt))
			if err != nil {
				return c.close(err)
			}
		}
	}
}

func Overhead[A Attacher]() int {
	var a A
	return a.Overhead() + faketcp.Overhead
}

func (c *Conn[A]) MTU() int { return c.config.MTU }

// BuiltinTCP get builtin tcp connect, require call c.Recv asynchronous, at the same time.
func (c *Conn[A]) BuiltinTCP(ctx context.Context) (net.Conn, error) {
	if err := c.handshake(ctx); err != nil {
		return nil, err
	}
	return c.tcp, nil
}

func (c *Conn[A]) Send(ctx context.Context, payload *packet.Packet, id A) (err error) {
	if err := c.handshake(ctx); err != nil {
		return err
	}

	if debug.Debug() {
		require.True(test.T(), id.Valid())
	}
	if err := id.Encode(payload); err != nil {
		return errorx.WrapTemp(err)
	}
	c.fake.AttachSend(payload)

	err = c.raw.Write(ctx, payload)
	return err
}

func (c *Conn[A]) recv(ctx context.Context, pkt *packet.Packet) error {
	if c.handshakeRecvSegs.pop(pkt) {
		return nil
	}
	return c.raw.Read(ctx, pkt)
}

func (c *Conn[A]) Recv(ctx context.Context, payload *packet.Packet) (id A, err error) {
	id = id.New().(A)
	if err := c.handshake(ctx); err != nil {
		return id, err
	}

	head := payload.Head()
	for {
		err = c.recv(ctx, payload.Sets(head, 0xffff))
		if err != nil {
			return id, err
		}

		err = c.fake.DetachRecv(payload)
		if err != nil {
			if c.tinyCnt++; c.tinyCnt > c.config.RecvErrLimit {
				return id, errors.New("recv too many error")
			}
			return id, errorx.WrapTemp(err)
		}

		if err := id.Decode(payload); err != nil {
			if c.tinyCnt++; c.tinyCnt > c.config.RecvErrLimit {
				return id, errors.New("recv too many error")
			}
			return id, errorx.WrapTemp(err)
		}
		if debug.Debug() {
			require.True(test.T(), id.Valid())
		}

		if id.IsBuiltin() {
			c.inboundBuitinPacket(payload)
			continue
		}
		return id, nil
	}
}

func (c *Conn[A]) inboundBuitinPacket(tcp *packet.Packet) {
	// if the data packet passes through the NAT gateway, on handshake
	// step, the client port will be change automatically, after handshake, need manually
	// change client port.
	if c.role == client {
		header.TCP(tcp.Bytes()).SetDestinationPortWithChecksumUpdate(c.clientPort)
	} else {
		header.TCP(tcp.Bytes()).SetSourcePortWithChecksumUpdate(c.clientPort)
	}
	c.ep.Inbound(tcp)
}

func (c *Conn[A]) LocalAddr() netip.AddrPort  { return c.raw.LocalAddr() }
func (c *Conn[A]) RemoteAddr() netip.AddrPort { return c.raw.RemoteAddr() }
func (c *Conn[A]) Close() error               { return c.close(nil) }
