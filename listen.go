package fatcp

import (
	"context"
	"net"
	"net/netip"
	"sync/atomic"

	fconn "github.com/lysShub/fatun/conn"
	"github.com/lysShub/fatun/ustack"
	"github.com/lysShub/fatun/ustack/gonet"
	"github.com/lysShub/fatun/ustack/link"
	"github.com/lysShub/rawsock"
	"github.com/pkg/errors"

	rawtcp "github.com/lysShub/rawsock/tcp"
	"github.com/lysShub/rawsock/test"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

type listener struct {
	config *Config
	raw    rawsock.Listener

	stack ustack.Ustack
	l     *gonet.TCPListener

	a        fconn.Peer
	closeErr atomic.Pointer[error]
}

func Listen[A fconn.Peer](addr string, config *Config) (fconn.Listener, error) {
	laddr, err := resolve(addr, true)
	if err != nil {
		return nil, err
	}

	rawl, err := rawtcp.Listen(laddr, config.RawConnOpts...)
	if err != nil {
		return nil, err
	}
	return newListener[A](rawl, config)
}

func NewListener[A fconn.Peer](l rawsock.Listener, config *Config) (fconn.Listener, error) {
	return newListener[A](l, config)
}

func newListener[A fconn.Peer](l rawsock.Listener, config *Config) (*listener, error) {
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
	if config.PcapBuiltinPath != "" {
		li.stack = ustack.MustWrapPcap(li.stack, config.PcapBuiltinPath)
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

func (l *listener) Accept() (fconn.Conn, error) {
	return l.AcceptCtx(context.Background())
}

func (l *listener) AcceptCtx(ctx context.Context) (fconn.Conn, error) {
	raw, err := l.raw.Accept() // todo: raw support context
	if err != nil {
		return nil, err
	}

	if l.config.PcapRawConnPath != "" {
		raw, err = test.WrapPcap(raw, l.config.PcapRawConnPath)
		if err != nil {
			return nil, err
		}
	}

	ep, err := l.stack.LinkEndpoint(l.Addr().Port(), raw.RemoteAddr())
	if err != nil {
		return nil, err
	}

	var c = &conn{a: l.a.Builtin()}
	if err := c.init(raw, ep, server, l.config); err != nil {
		return nil, c.close(err)
	}
	c.factory = &serverFactory{l: l.l, remote: c.RemoteAddr()}
	return c, nil
}

func (l *listener) Addr() netip.AddrPort { return l.raw.Addr() }
func (l *listener) MTU() int             { return l.config.MTU }
func (l *listener) Close() error         { return l.close(nil) }
