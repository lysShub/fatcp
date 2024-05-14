package ustack

import (
	"context"
	"net/netip"
	"time"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"

	"github.com/lysShub/fatcp/ustack/link"
	"github.com/lysShub/netkit/packet"
	"github.com/lysShub/rawsock/helper/ipstack"

	"github.com/lysShub/netkit/debug"
	"github.com/lysShub/rawsock/test"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

// user tcp stack
type Ustack interface {
	Close() error
	Stack() *stack.Stack
	Addr() netip.Addr
	MTU() int
	LinkEndpoint(localPort uint16, remoteAddr netip.AddrPort) (*LinkEndpoint, error)

	Inbound(ip *packet.Packet)
	OutboundBy(ctx context.Context, dst netip.AddrPort, tcp *packet.Packet) error
	Outbound(ctx context.Context, tcp *packet.Packet) error
}

// user mode tcp stack
type ustack struct {
	stack *stack.Stack

	addr  netip.Addr
	proto tcpip.NetworkProtocolNumber

	link link.Link
}

var _ Ustack = (*ustack)(nil)

const nicid tcpip.NICID = 1234

// todo: set no tcp delay
func NewUstack(link link.Link, addr netip.Addr) (Ustack, error) {
	if !addr.Is4() {
		return nil, errors.New("only support ipv4")
	}
	var u = &ustack{
		addr:  addr,
		proto: header.IPv4ProtocolNumber,
		link:  link,
	}

	u.stack = stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
		HandleLocal:        false,
	})

	if err := u.stack.CreateNIC(nicid, u.link); err != nil {
		return nil, errors.New(err.String())
	}
	if err := u.stack.AddProtocolAddress(nicid, tcpip.ProtocolAddress{
		Protocol:          u.proto,
		AddressWithPrefix: tcpip.AddrFromSlice(u.addr.AsSlice()).WithPrefix(),
	}, stack.AddressProperties{}); err != nil {
		return nil, errors.New(err.String())
	}
	u.stack.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: nicid},
		{Destination: header.IPv6EmptySubnet, NIC: nicid},
	})

	return u, nil
}

func (u *ustack) Close() error {
	u.stack.Close()
	return u.link.SynClose(time.Second)
}

func (u *ustack) Stack() *stack.Stack { return u.stack }
func (u *ustack) Addr() netip.Addr    { return u.addr }
func (u *ustack) MTU() int            { return int(u.link.MTU()) }
func (u *ustack) LinkEndpoint(localPort uint16, remoteAddr netip.AddrPort) (*LinkEndpoint, error) {
	return NewLinkEndpoint(u, localPort, remoteAddr)
}

func (u *ustack) Inbound(ip *packet.Packet) { u.link.Inbound(ip) }

// OutboundBy only use by server, read stack outbound tcp packet
func (u *ustack) OutboundBy(ctx context.Context, dst netip.AddrPort, tcp *packet.Packet) error {
	return u.link.OutboundBy(ctx, dst, tcp)
}

// Outbound only use by client
func (u *ustack) Outbound(ctx context.Context, tcp *packet.Packet) error {
	return u.link.Outbound(ctx, tcp)
}

type LinkEndpoint struct {
	stack      Ustack
	localPort  uint16
	remoteAddr netip.AddrPort
	ipstack    *ipstack.IPStack
}

func NewLinkEndpoint(stack Ustack, localPort uint16, remoteAddr netip.AddrPort) (*LinkEndpoint, error) {
	var ep = &LinkEndpoint{
		stack:      stack,
		localPort:  localPort,
		remoteAddr: remoteAddr,
	}
	var err error
	ep.ipstack, err = ipstack.New(
		ep.LocalAddr().Addr(),
		ep.RemoteAddr().Addr(),
		header.TCPProtocolNumber,
	)
	if err != nil {
		return nil, err
	}
	return ep, nil
}

func (e *LinkEndpoint) Close() error  { return nil }
func (e *LinkEndpoint) Stack() Ustack { return e.stack }
func (e *LinkEndpoint) MTU() int      { return e.stack.MTU() }
func (e *LinkEndpoint) LocalAddr() netip.AddrPort {
	return netip.AddrPortFrom(e.stack.Addr(), e.localPort)
}
func (e *LinkEndpoint) RemoteAddr() netip.AddrPort { return e.remoteAddr }
func (e *LinkEndpoint) Inbound(tcp *packet.Packet) {
	e.ipstack.AttachInbound(tcp)
	if debug.Debug() {
		test.ValidIP(test.T(), tcp.Bytes())

		ip := header.IPv4(tcp.Bytes())
		tcp := header.TCP(ip.Payload())
		src := netip.AddrPortFrom(netip.MustParseAddr(ip.SourceAddress().String()), tcp.SourcePort())
		require.Equal(test.T(), e.RemoteAddr(), src)
		dst := netip.AddrPortFrom(netip.MustParseAddr(ip.DestinationAddress().String()), tcp.DestinationPort())
		require.Equal(test.T(), e.LocalAddr(), dst)
	}
	e.stack.Inbound(tcp)
}
func (e *LinkEndpoint) Outbound(ctx context.Context, tcp *packet.Packet) error {
	return e.stack.OutboundBy(ctx, e.remoteAddr, tcp)
}
