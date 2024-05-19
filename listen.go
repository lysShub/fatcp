package fatcp

import (
	"context"
	"net"
	"net/netip"
	"sync/atomic"

	"github.com/lysShub/fatcp/faketcp"
	"github.com/lysShub/fatcp/ustack"
	"github.com/lysShub/fatcp/ustack/gonet"
	"github.com/lysShub/fatcp/ustack/link"
	"github.com/lysShub/rawsock"
	"github.com/pkg/errors"

	rawtcp "github.com/lysShub/rawsock/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

type listener[A Attacher] struct {
	config *Config
	raw    rawsock.Listener

	stack ustack.Ustack
	l     *gonet.TCPListener

	closeErr atomic.Pointer[error]
}

func Listen[A Attacher](addr string, config *Config) (Listener[A], error) {
	laddr, err := resolve(addr, true)
	if err != nil {
		return nil, err
	}

	rawl, err := rawtcp.Listen(laddr)
	if err != nil {
		return nil, err
	}
	return NewListener[A](rawl, config)
}

func NewListener[A Attacher](l rawsock.Listener, config *Config) (Listener[A], error) {
	if err := config.Init(l.Addr().Addr()); err != nil {
		return nil, err
	}
	var li = &listener[A]{config: config, raw: l}
	var err error

	if li.stack, err = ustack.NewUstack(
		link.NewList(64, config.MTU-new(conn[A]).Overhead()), l.Addr().Addr(),
	); err != nil {
		return nil, li.close(err)
	}
	// li.stack = utest.MustWrapPcap("server.pcap", li.stack)

	if li.l, err = gonet.ListenTCP(
		li.stack, l.Addr(),
		header.IPv4ProtocolNumber,
	); err != nil {
		return nil, li.close(err)
	}

	return li, nil
}

func (l *listener[A]) close(cause error) error {
	if l.closeErr.CompareAndSwap(nil, &net.ErrClosed) {
		if l.l != nil {
			if err := l.l.Close(); err != nil {
				cause = errors.WithStack(err)
			}
		}
		if l.stack != nil {
			if err := l.stack.Close(); err != nil {
				cause = err
			}
		}
		if l.raw != nil {
			if err := l.raw.Close(); err != nil {
				cause = err
			}
		}

		if cause != nil {
			l.closeErr.Store(&cause)
		}
		return cause
	}
	return *l.closeErr.Load()
}

func (l *listener[A]) Accept() (Conn[A], error) {
	return l.AcceptCtx(context.Background())
}

func (l *listener[A]) AcceptCtx(ctx context.Context) (Conn[A], error) {
	raw, err := l.raw.Accept() // todo: raw support context
	if err != nil {
		return nil, err
	}

	ep, err := l.stack.LinkEndpoint(l.Addr().Port(), raw.RemoteAddr())
	if err != nil {
		return nil, err
	}

	var conn = &conn[A]{}
	if err := conn.init(raw, ep, server, l.config); err != nil {
		return nil, err
	}
	conn.factory = &serverFactory{l: l.l, remote: conn.RemoteAddr()}
	return conn, nil
}

func (l *listener[A]) Addr() netip.AddrPort { return l.raw.Addr() }
func (l *listener[A]) MTU() int             { return l.config.MTU }
func (l *listener[A]) Overhead() int        { return (*new(A)).Overhead() + faketcp.Overhead }
func (l *listener[A]) Close() error         { return l.close(nil) }
