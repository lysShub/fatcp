package fatcp

import (
	"context"
	"net"
	"net/netip"

	fconn "github.com/lysShub/fatun/conn"
	"github.com/lysShub/fatun/ustack"
	"github.com/lysShub/fatun/ustack/link"
	"github.com/lysShub/rawsock"
	rawtcp "github.com/lysShub/rawsock/tcp"
	"github.com/lysShub/rawsock/test"
	"github.com/pkg/errors"
)

func Dial[A fconn.Peer](server string, config *Config) (fconn.Conn, error) {
	return DialCtx[A](context.Background(), server, config)
}

func DialCtx[A fconn.Peer](ctx context.Context, server string, config *Config) (fconn.Conn, error) {
	raddr, err := resolve(server, false)
	if err != nil {
		return nil, err
	}
	raw, err := rawtcp.Connect(netip.AddrPortFrom(netip.IPv4Unspecified(), 0), raddr, config.RawConnOpts...)
	if err != nil {
		return nil, err
	}

	c, err := newConn[A](raw, config)
	if err != nil {
		return nil, c.close(err)
	}

	if err = c.handshake(ctx); err != nil {
		return nil, c.close(err)
	}
	return c, nil
}

func NewConn[A fconn.Peer](raw rawsock.RawConn, config *Config) (fconn.Conn, error) {
	return newConn[A](raw, config)
}

func newConn[A fconn.Peer](raw rawsock.RawConn, config *Config) (*conn, error) {
	if err := config.init(raw.LocalAddr().Addr()); err != nil {
		return nil, err
	}
	var c = &conn{config: config, a: *(new(A))}

	stack, err := ustack.NewUstack(
		link.NewList(8, calcMTU[A](config)),
		raw.LocalAddr().Addr(),
	)
	if err != nil {
		return nil, c.close(err)
	}
	if config.PcapBuiltinPath != "" {
		stack = ustack.MustWrapPcap(stack, config.PcapBuiltinPath)
	}

	ep, err := ustack.NewLinkEndpoint(stack, raw.LocalAddr().Port(), raw.RemoteAddr())
	if err != nil {
		return nil, c.close(err)
	}

	if config.PcapRawConnPath != "" {
		raw, err = test.WrapPcap(raw, config.PcapRawConnPath) // todo: move out test
		if err != nil {
			return nil, c.close(err)
		}
	}
	if err := c.init(raw, ep, fconn.Client, config); err != nil {
		return nil, c.close(err)
	}
	c.factory = &clientFactory{
		local: c.LocalAddr(), remote: c.RemoteAddr(),
		stack: stack,
	}
	return c, nil
}

func resolve(addr string, local bool) (netip.AddrPort, error) {
	if taddr, err := net.ResolveTCPAddr("tcp", addr); err != nil {
		return netip.AddrPort{}, errors.WithStack(err)
	} else {
		if taddr.Port == 0 {
			taddr.Port = 443
		}
		if len(taddr.IP) == 0 || taddr.IP.IsUnspecified() {
			if local {
				s, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: []byte{8, 8, 8, 8}, Port: 53})
				if err != nil {
					return netip.AddrPort{}, errors.WithStack(err)
				}
				defer s.Close()
				taddr.IP = s.LocalAddr().(*net.UDPAddr).IP
			} else {
				return netip.AddrPort{}, errors.Errorf("server address %s require ip or domain", addr)
			}
		}
		return netip.MustParseAddrPort(taddr.String()), nil
	}
}
