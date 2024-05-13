package fatcp

import (
	"context"
	"fmt"
	"log/slog"
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

func (c *Conn[A]) Send(ctx context.Context, pkt *packet.Packet, id A) (err error) {
	if err := c.handshake(ctx); err != nil {
		return err
	}

	if err := id.Encode(pkt); err != nil {
		return err
	}
	c.fake.AttachSend(pkt)

	if debug.Debug() {
		require.True(test.T(), id.Valid())
	}
	err = c.raw.Write(ctx, pkt)
	return err
}

func (c *Conn[A]) recv(ctx context.Context, pkt *packet.Packet) error {
	if c.handshakeRecvSegs.pop(pkt) {
		return nil
	}
	return c.raw.Read(ctx, pkt)
}

func (c *Conn[A]) Recv(ctx context.Context, pkt *packet.Packet) (id A, err error) {
	if err := c.handshake(ctx); err != nil {
		return *new(A), err
	}

	head := pkt.Head()
	for {
		// todo: 如果server之间close, 可以导致接受到原始的RST, 可能导致decode等出现panic
		err = c.recv(ctx, pkt.Sets(head, 0xffff))
		if err != nil {
			return *new(A), err
		}

		err = c.fake.DetachRecv(pkt)
		if err != nil {
			if time.Since(c.handshakedTime) < time.Second*3 {
				continue
			}
			if c.tinyCnt++; c.tinyCnt > c.config.RecvErrLimit {
				return *new(A), errors.WithStack(&ErrRecvTooManyErrors{err})
			}

			// todo: temporary
			var attr = slog.String("ip", fmt.Sprintf("%+v", pkt.SetHead(head).Bytes()))
			slog.Error(err.Error(), attr)

			return *new(A), errorx.WrapTemp(err)
		}

		if err := id.Decode(pkt); err != nil {
			return *new(A), err
		}
		if debug.Debug() {
			require.True(test.T(), id.Valid())
		}
		if id.IsBuiltin() {
			c.inboundControlPacket(pkt)
			continue
		}
		return id, nil
	}
}

type ErrRecvTooManyErrors struct{ error }

func (e *ErrRecvTooManyErrors) Error() string {
	return fmt.Sprintf("fatcp recv too many error: %s", e.error.Error())
}

type ErrInvalidPacket struct{}

func (e *ErrInvalidPacket) Error() string   { return "invalid packet" }
func (e *ErrInvalidPacket) Temporary() bool { return true }

func (c *Conn[A]) inboundControlPacket(pkt *packet.Packet) {
	// if the data packet passes through the NAT gateway, on handshake
	// step, the client port will be change automatically, after handshake, need manually
	// change client port.
	if c.role == client {
		header.TCP(pkt.Bytes()).SetDestinationPortWithChecksumUpdate(c.clientPort)
	} else {
		header.TCP(pkt.Bytes()).SetSourcePortWithChecksumUpdate(c.clientPort)
	}
	c.ep.Inbound(pkt)
}

func (c *Conn[A]) LocalAddr() netip.AddrPort  { return c.raw.LocalAddr() }
func (c *Conn[A]) RemoteAddr() netip.AddrPort { return c.raw.RemoteAddr() }
func (c *Conn[A]) Close() error               { return c.close(nil) }
