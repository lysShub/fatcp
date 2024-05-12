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

	"github.com/lysShub/fatcp/crypto"
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

const Overhead = faketcp.Overhead + peerSize

// security datagram conn
type Conn struct {
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

func newConn(raw rawsock.RawConn, ep *ustack.LinkEndpoint, role role, config *Config) (*Conn, error) {
	var c = &Conn{
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

func (c *Conn) close(cause error) error {
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

func (c *Conn) outboundService() error {
	var pkt = packet.Make(c.config.MTU)

	for {
		err := c.ep.Outbound(c.srvCtx, pkt.Sets(Overhead, 0xffff))
		if err != nil {
			return c.close(err)
		}
		if debug.Debug() {
			require.GreaterOrEqual(test.T(), pkt.Head(), Overhead)
			require.GreaterOrEqual(test.T(), pkt.Tail(), crypto.Overhead)
		}

		if c.state.Load() == transmit {
			err = c.Send(c.srvCtx, pkt, BuiltinPeer)
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

func (c *Conn) MTU() int { return c.ep.MTU() + Overhead }

// BuiltinTCP get builtin tcp conn, require call c.Recv asynchronous, at the same time.
func (c *Conn) BuiltinTCP(ctx context.Context) (net.Conn, error) {
	if err := c.handshake(ctx); err != nil {
		return nil, err
	}
	return c.tcp, nil
}

func (c *Conn) Send(ctx context.Context, pkt *packet.Packet, id Peer) (err error) {
	if err := c.handshake(ctx); err != nil {
		return err
	}

	encode(pkt, id)
	c.fake.AttachSend(pkt)

	if debug.Debug() {
		require.True(test.T(), id.Valid())
	}
	err = c.raw.Write(ctx, pkt)
	return err
}

func (c *Conn) recv(ctx context.Context, pkt *packet.Packet) error {
	if c.handshakeRecvSegs.pop(pkt) {
		return nil
	}
	return c.raw.Read(ctx, pkt)
}

func (c *Conn) Recv(ctx context.Context, pkt *packet.Packet) (id Peer, err error) {
	if err := c.handshake(ctx); err != nil {
		return Peer{}, err
	}

	head := pkt.Head()
	for {
		// todo: 如果server之间close, 可以导致接受到原始的RST, 可能导致decode等出现panic
		err = c.recv(ctx, pkt.Sets(head, 0xffff))
		if err != nil {
			return Peer{}, err
		}

		err = c.fake.DetachRecv(pkt)
		if err != nil {
			if time.Since(c.handshakedTime) < time.Second*3 {
				continue
			}
			if c.tinyCnt++; c.tinyCnt > c.config.RecvErrLimit {
				return Peer{}, errors.WithStack(&ErrRecvTooManyErrors{err})
			}

			// todo: temporary
			var attr = slog.String("ip", fmt.Sprintf("%+v", pkt.SetHead(head).Bytes()))
			slog.Error(err.Error(), attr)

			return Peer{}, errorx.WrapTemp(err)
		}

		id = decode(pkt)
		if debug.Debug() {
			require.True(test.T(), id.Valid())
		}
		if id == BuiltinPeer {
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

func (c *Conn) inboundControlPacket(pkt *packet.Packet) {
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

func (c *Conn) LocalAddr() netip.AddrPort  { return c.raw.LocalAddr() }
func (c *Conn) RemoteAddr() netip.AddrPort { return c.raw.RemoteAddr() }
func (c *Conn) Close() error               { return c.close(nil) }
