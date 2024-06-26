package fatcp

import (
	"context"
	"net"
	"net/netip"

	"github.com/lysShub/fatcp/ustack"
	"github.com/lysShub/fatcp/ustack/link"
	"github.com/lysShub/rawsock"
	rawtcp "github.com/lysShub/rawsock/tcp"
	"github.com/lysShub/rawsock/test"
	"github.com/pkg/errors"
)

func Dial[A Attacher](server string, config *Config) (Conn, error) {
	return DialCtx[A](context.Background(), server, config)
}

func DialCtx[A Attacher](ctx context.Context, server string, config *Config) (Conn, error) {
	raddr, err := resolve(server, false)
	if err != nil {
		return nil, err
	}
	raw, err := rawtcp.Connect(netip.AddrPortFrom(netip.IPv4Unspecified(), 0), raddr, config.RawConnOpts...)
	if err != nil {
		return nil, err
	}

	conn, err := newConn[A](raw, config)
	if err != nil {
		return nil, conn.close(err)
	}

	if err = conn.handshake(ctx); err != nil {
		return nil, conn.close(err)
	}
	return conn, nil
}

func NewConn[A Attacher](raw rawsock.RawConn, config *Config) (Conn, error) {
	return newConn[A](raw, config)
}

func newConn[A Attacher](raw rawsock.RawConn, config *Config) (*conn, error) {
	if err := config.init(raw.LocalAddr().Addr()); err != nil {
		return nil, err
	}
	var conn = &conn{config: config, a: *(new(A))}

	stack, err := ustack.NewUstack(
		link.NewList(8, calcMTU[A](config)),
		raw.LocalAddr().Addr(),
	)
	if err != nil {
		return nil, conn.close(err)
	}
	if config.PcapBuiltinPath != "" {
		stack = ustack.MustWrapPcap(stack, config.PcapBuiltinPath)
	}

	ep, err := ustack.NewLinkEndpoint(stack, raw.LocalAddr().Port(), raw.RemoteAddr())
	if err != nil {
		return nil, conn.close(err)
	}

	if config.PcapRawConnPath != "" {
		raw, err = test.WrapPcap(raw, config.PcapRawConnPath) // todo: move out test
		if err != nil {
			return nil, conn.close(err)
		}
	}
	if err := conn.init(raw, ep, client, config); err != nil {
		return nil, conn.close(err)
	}
	conn.factory = &clientFactory{
		local: conn.LocalAddr(), remote: conn.RemoteAddr(),
		stack: stack,
	}
	return conn, nil
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
