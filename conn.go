package fatcp

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/lysShub/fatcp/faketcp"
	"github.com/lysShub/fatcp/ustack"
	"github.com/lysShub/netkit/errorx"
	"github.com/lysShub/netkit/packet"
	"github.com/lysShub/rawsock"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/tcpip/header"

	"github.com/lysShub/netkit/debug"
	"github.com/lysShub/rawsock/test"
)

type conn struct {
	config     *Config
	raw        rawsock.RawConn
	clientPort uint16
	role       role
	state      state
	tinyCnt    int

	handshakedNotify           sync.WaitGroup
	handshakeRecvedFakePackets *heap

	ep      *ustack.LinkEndpoint
	factory tcpFactory
	tcp     net.Conn // builtin tcp conn

	fake *faketcp.FakeTCP //

	a         Attacher
	srvCtx    context.Context
	srvCancel context.CancelFunc
	closeErr  errorx.CloseErr
}

type role uint8

const (
	client role = 1
	server role = 2
)

func (c *conn) init(raw rawsock.RawConn, ep *ustack.LinkEndpoint, role role, config *Config) error {
	c.config = config
	c.raw = raw
	c.role = role
	c.handshakeRecvedFakePackets = &heap{}
	c.ep = ep

	switch role {
	case client:
		c.clientPort = raw.LocalAddr().Port()
	case server:
		c.clientPort = raw.RemoteAddr().Port()
	default:
		return errors.Errorf("unknown role %d", role)
	}
	c.handshakedNotify.Add(1)
	c.srvCtx, c.srvCancel = context.WithCancel(context.Background())

	go c.outboundService()
	return nil
}

func (c *conn) close(cause error) error {
	return c.closeErr.Close(func() (errs []error) {
		errs = append(errs, cause)

		if c.tcp != nil {
			errs = append(errs, c.tcp.Close())

			if gconn, ok := c.tcp.(interface {
				WaitSentDataRecvByPeer(context.Context) (uint32, uint32, error)
			}); ok {
				ctx, cancel := context.WithTimeout(c.srvCtx, time.Second*3)
				defer cancel()
				gconn.WaitSentDataRecvByPeer(ctx)
			}
		}
		if c.ep != nil {
			errs = append(errs, c.ep.Close())
		}
		if c.srvCancel != nil {
			c.srvCancel()
		}
		if c.raw != nil {
			errs = append(errs, c.raw.Close())
		}
		return
	})
}

func (c *conn) outboundService() error {
	var (
		pkt      = packet.Make(c.config.MTU)
		builtin  = c.a.Builtin()
		overhead = c.Overhead()
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
			err = c.Send(c.srvCtx, builtin, pkt)
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

func (c *conn) Overhead() int { return c.a.Overhead() + faketcp.Overhead }
func (c *conn) MTU() int      { return c.config.MTU }

// BuiltinTCP get builtin tcp connect, require call c.Recv asynchronous, at the same time.
func (c *conn) BuiltinTCP(ctx context.Context) (net.Conn, error) {
	if err := c.handshake(ctx); err != nil {
		return nil, err
	}
	return c.tcp, nil
}

func (c *conn) Send(ctx context.Context, atter Attacher, payload *packet.Packet) (err error) {
	if err := c.handshake(ctx); err != nil {
		return err
	}

	if debug.Debug() {
		require.True(test.T(), atter.Valid())
	}
	if err := atter.Encode(payload); err != nil {
		return errorx.WrapTemp(err)
	}
	c.fake.AttachSend(payload)

	err = c.raw.Write(ctx, payload)
	return err
}

func (c *conn) recv(ctx context.Context, pkt *packet.Packet) error {
	if c.handshakeRecvedFakePackets.pop(pkt) {
		return nil
	}
	return c.raw.Read(ctx, pkt)
}

func (c *conn) Recv(ctx context.Context, id Attacher, payload *packet.Packet) (err error) {
	if err := c.handshake(ctx); err != nil {
		return err
	}

	head := payload.Head()
	for {
		err = c.recv(ctx, payload.Sets(head, 0xffff))
		if err != nil {
			return err
		}

		err = c.fake.DetachRecv(payload)
		if err != nil {
			if c.tinyCnt++; c.tinyCnt > c.config.RecvErrLimit {
				return errors.New("recv too many error")
			}
			return errorx.WrapTemp(err)
		}

		if err := id.Decode(payload); err != nil {
			if c.tinyCnt++; c.tinyCnt > c.config.RecvErrLimit {
				return errors.New("recv too many error")
			}
			return errorx.WrapTemp(err)
		}
		if debug.Debug() {
			require.True(test.T(), id.Valid())
		}

		if id.IsBuiltin() {
			c.inboundBuitinPacket(payload)
			continue
		}
		return nil
	}
}

func (c *conn) inboundBuitinPacket(tcp *packet.Packet) {
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

func (c *conn) LocalAddr() netip.AddrPort  { return c.raw.LocalAddr() }
func (c *conn) RemoteAddr() netip.AddrPort { return c.raw.RemoteAddr() }
func (c *conn) Close() error               { return c.close(nil) }
