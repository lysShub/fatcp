package test

import (
	"context"
	"net/netip"

	"github.com/lysShub/fatcp/ustack"
	"github.com/lysShub/netkit/packet"
	"github.com/lysShub/netkit/pcap"
)

type UstackPcapWrap struct {
	ustack.Ustack
	pcap *pcap.Pcap
}

func WrapPcap(file string, child ustack.Ustack) (ustack.Ustack, error) {
	p, err := pcap.File(file)
	if err != nil {
		return nil, err
	}

	return &UstackPcapWrap{
		Ustack: child,
		pcap:   p,
	}, nil
}

func MustWrapPcap(file string, child ustack.Ustack) ustack.Ustack {
	p, err := WrapPcap(file, child)
	if err != nil {
		panic(err)
	}
	return p
}

func (u *UstackPcapWrap) LinkEndpoint(localPort uint16, remoteAddr netip.AddrPort) (*ustack.LinkEndpoint, error) {
	return ustack.NewLinkEndpoint(u, localPort, remoteAddr)
}

func (u *UstackPcapWrap) Inbound(ip *packet.Packet) {
	if err := u.pcap.WriteIP(ip.Bytes()); err != nil {
		panic(err)
	}
	u.Ustack.Inbound(ip)
}
func (u *UstackPcapWrap) OutboundBy(ctx context.Context, dst netip.AddrPort, tcp *packet.Packet) error {
	old := tcp.Head()
	if err := u.Ustack.OutboundBy(ctx, dst, tcp); err != nil {
		return err
	}
	new := tcp.Head()

	tcp.SetHead(old)
	if err := u.pcap.WriteIP(tcp.Bytes()); err != nil {
		return err
	}
	tcp.SetHead(new)
	return nil
}
func (u *UstackPcapWrap) Outbound(ctx context.Context, tcp *packet.Packet) error {
	old := tcp.Head()
	if err := u.Ustack.Outbound(ctx, tcp); err != nil {
		return err
	}
	new := tcp.Head()

	tcp.SetHead(old)
	if err := u.pcap.WriteIP(tcp.Bytes()); err != nil {
		return err
	}
	tcp.SetHead(new)
	return nil
}
