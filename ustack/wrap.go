package ustack

import (
	"context"
	"net/netip"

	"github.com/lysShub/netkit/packet"
	"github.com/lysShub/netkit/pcap"
)

type ustackNotCloseWrap struct{ Ustack }

func (ustackNotCloseWrap) Close() error { return nil }

type UstackPcapWrap struct {
	Ustack
	pcap *pcap.Pcap
}

func WrapPcap(child Ustack, file string) (Ustack, error) {
	p, err := pcap.File(file)
	if err != nil {
		return nil, err
	}

	return &UstackPcapWrap{
		Ustack: child,
		pcap:   p,
	}, nil
}

func MustWrapPcap(child Ustack, file string) Ustack {
	if p, err := WrapPcap(child, file); err != nil {
		panic(err)
	} else {
		return p
	}
}

func (u *UstackPcapWrap) LinkEndpoint(localPort uint16, remoteAddr netip.AddrPort) (*LinkEndpoint, error) {
	return NewLinkEndpoint(ustackNotCloseWrap{u}, localPort, remoteAddr)
}

func (u *UstackPcapWrap) Inbound(ip *packet.Packet) {
	if err := u.pcap.WriteIP(ip.Bytes()); err != nil {
		panic(err)
	}
	u.Inbound(ip)
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
