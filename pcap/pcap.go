package pcap

import (
	"context"
	"net/netip"

	"github.com/lysShub/fatcp"
	"github.com/lysShub/netkit/packet"
	"github.com/lysShub/netkit/pcap"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

type ConnWrap struct {
	fatcp.Conn

	server bool
	pcap   *pcap.BindPcap
}

func WrapConn(child fatcp.Conn, path string) (*ConnWrap, error) {
	return newConnWrap(child, path, child.LocalAddr().Addr(), false)
}

func newConnWrap(child fatcp.Conn, path string, src netip.Addr, server bool) (*ConnWrap, error) {
	var c = &ConnWrap{
		Conn:   child,
		server: server,
	}
	if p, err := pcap.File(path); err != nil {
		return nil, err
	} else {
		c.pcap, err = pcap.Bind(p, src)
		if err != nil {
			return nil, err
		}
	}
	return c, nil
}

func (p *ConnWrap) Recv(atter fatcp.Attacher, payload *packet.Packet) (err error) {
	err = p.Conn.Recv(atter, payload)
	if err != nil {
		return err
	}

	var proto = header.TCPProtocolNumber
	if header.UDP(payload.Bytes()).Length() == uint16(payload.Data()) {
		proto = header.UDPProtocolNumber // not strict
	}
	if p.server {
		return p.pcap.Outbound(netip.IPv4Unspecified(), proto, payload.Bytes())
	} else {
		return p.pcap.Inbound(netip.IPv4Unspecified(), proto, payload.Bytes())
	}
}

func (p *ConnWrap) Send(atter fatcp.Attacher, payload *packet.Packet) (err error) {
	var proto = header.TCPProtocolNumber
	if header.UDP(payload.Bytes()).Length() == uint16(payload.Data()) {
		proto = header.UDPProtocolNumber // not strict
	}
	if p.server {
		err = p.pcap.Inbound(netip.IPv4Unspecified(), proto, payload.Bytes())
	} else {
		err = p.pcap.Outbound(netip.IPv4Unspecified(), proto, payload.Bytes())
	}
	if err != nil {
		return err
	}

	return p.Conn.Send(atter, payload)
}

type ListenerWrap struct {
	fatcp.Listener
	path string
}

func WrapListener(child fatcp.Listener, path string) fatcp.Listener {
	return &ListenerWrap{Listener: child, path: path}
}

func (l *ListenerWrap) AcceptCtx(ctx context.Context) (fatcp.Conn, error) {
	conn, err := l.Listener.AcceptCtx(ctx)
	if err != nil {
		return nil, err
	}
	return newConnWrap(conn, l.path, conn.RemoteAddr().Addr(), true)
}

func (l *ListenerWrap) Accept() (fatcp.Conn, error) {
	return l.AcceptCtx(context.Background())
}
