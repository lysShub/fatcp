package fatcp

import (
	"context"
	"net"
	"net/netip"

	"github.com/lysShub/fatcp/ustack"
	"github.com/lysShub/fatcp/ustack/link"
	"github.com/lysShub/rawsock"
	rawtcp "github.com/lysShub/rawsock/tcp"
	"github.com/pkg/errors"
)

func Dial(server string, config *Config) (*Conn, error) {
	return DialCtx(context.Background(), server, config)
}

func DialCtx(ctx context.Context, server string, config *Config) (*Conn, error) {
	raddr, err := resolve(server, false)
	if err != nil {
		return nil, err
	}
	raw, err := rawtcp.Connect(netip.AddrPortFrom(netip.IPv4Unspecified(), 0), raddr)
	if err != nil {
		return nil, err
	}

	conn, err := NewConn(raw, config)
	if err != nil {
		raw.Close()
		return nil, err
	}

	if conn.handshake(ctx); err != nil {
		raw.Close()
		conn.Close()
		return nil, err
	}

	return conn, nil
}

func NewConn(raw rawsock.RawConn, config *Config) (*Conn, error) {
	if err := config.Init(); err != nil {
		return nil, err
	}

	mtu, err := mtuByAddr(raw.LocalAddr().Addr())
	if err != nil {
		return nil, err
	}
	stack, err := ustack.NewUstack(
		link.NewList(8, mtu-Overhead),
		raw.LocalAddr().Addr(),
	)
	if err != nil {
		return nil, err
	}
	// stack = test.MustWrapPcap(fmt.Sprintf("client-ctr-%d.pcap", raw.LocalAddr().Port()), stack)

	ep, err := stack.LinkEndpoint(raw.LocalAddr().Port(), raw.RemoteAddr())
	if err != nil {
		return nil, err
	}

	conn, err := newConn(raw, ep, client, config)
	if err != nil {
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

// todo: optimzie
func mtuByAddr(laddr netip.Addr) (int, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return 0, errors.WithStack(err)
	}
	for _, i := range ifs {
		if i.Flags&net.FlagRunning == 0 {
			continue
		}

		addrs, err := i.Addrs()
		if err != nil {
			return 0, errors.WithStack(err)
		}
		for _, addr := range addrs {
			if e, ok := addr.(*net.IPNet); ok && e.IP.To4() != nil {
				if netip.AddrFrom4([4]byte(e.IP.To4())) == laddr {
					return i.MTU, nil
				}
			}
		}
	}

	return 0, errors.Errorf("not found adapter %s mtu", laddr.String())
}
