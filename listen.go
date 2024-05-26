package fatcp

import (
	"context"
	"net"
	"net/netip"
	"sync/atomic"

	"github.com/lysShub/fatcp/ustack"
	"github.com/lysShub/fatcp/ustack/gonet"
	"github.com/lysShub/fatcp/ustack/link"
	"github.com/lysShub/rawsock"
	"github.com/pkg/errors"

	rawtcp "github.com/lysShub/rawsock/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

type listener struct {
	config *Config
	raw    rawsock.Listener

	stack ustack.Ustack
	l     *gonet.TCPListener

	a        Attacher
	closeErr atomic.Pointer[error]
}

func Listen[A Attacher](addr string, config *Config) (Listener, error) {
	laddr, err := resolve(addr, true)
	if err != nil {
		return nil, err
	}

	rawl, err := rawtcp.Listen(laddr, config.RawConnOpts...)
	if err != nil {
		return nil, err
	}
	return NewListener[A](rawl, config)
}

func NewListener[A Attacher](l rawsock.Listener, config *Config) (Listener, error) {
	if err := config.init(l.Addr().Addr()); err != nil {
		return nil, err
	}
	var li = &listener{config: config, raw: l, a: *(new(A))}
	var err error

	if li.stack, err = ustack.NewUstack(
		link.NewList(64, calcMTU[A](config)), l.Addr().Addr(),
	); err != nil {
		return nil, li.close(err)
	}
	if config.BuiltinPcapFile != "" {
		li.stack = ustack.MustWrapPcap(li.stack, config.BuiltinPcapFile)
	}

	if li.l, err = gonet.ListenTCP(
		li.stack, l.Addr(),
		header.IPv4ProtocolNumber,
	); err != nil {
		return nil, li.close(err)
	}

	return li, nil
}

func (l *listener) close(cause error) error {
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

func (l *listener) Accept() (Conn, error) {
	return l.AcceptCtx(context.Background())
}

func (l *listener) AcceptCtx(ctx context.Context) (Conn, error) {
	raw, err := l.raw.Accept() // todo: raw support context
	if err != nil {
		return nil, err
	}

	ep, err := l.stack.LinkEndpoint(l.Addr().Port(), raw.RemoteAddr())
	if err != nil {
		return nil, err
	}

	var conn = &conn{a: l.a.Builtin()}
	if err := conn.init(raw, ep, server, l.config); err != nil {
		return nil, err
	}
	conn.factory = &serverFactory{l: l.l, remote: conn.RemoteAddr()}
	return conn, nil
}

func (l *listener) Addr() netip.AddrPort { return l.raw.Addr() }
func (l *listener) MTU() int             { return l.config.MTU }
func (l *listener) Close() error         { return l.close(nil) }
