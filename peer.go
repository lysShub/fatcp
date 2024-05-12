package fatcp

import (
	"fmt"
	"net/netip"

	"github.com/lysShub/netkit/debug"
	"github.com/lysShub/netkit/packet"
	"github.com/lysShub/rawsock/test"
	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

type Peer struct {
	Remote netip.Addr
	Proto  tcpip.TransportProtocolNumber
}

func (id Peer) String() string {
	return fmt.Sprintf("%s:%s", "ProtoStr(id.Proto)", id.Remote.String())
}

func (id Peer) Valid() bool {
	return id.Remote.IsValid() &&
		(id.Proto == tcp.ProtocolNumber || id.Proto == udp.ProtocolNumber)
}

func encode(pkt *packet.Packet, p Peer) {
	if debug.Debug() {
		require.True(test.T(), p.Remote.Is4())
	}
	pkt.Attach(p.Remote.AsSlice())
	switch p.Proto {
	case tcp.ProtocolNumber, udp.ProtocolNumber:
		pkt.Attach([]byte{byte(p.Proto)})
	default:
		panic("")
	}
}

func decode(seg *packet.Packet) Peer {
	b := seg.Bytes()
	seg.SetHead(seg.Head() + peerOverhead)
	return Peer{
		Proto:  tcpip.TransportProtocolNumber(b[off1]),
		Remote: netip.AddrFrom4([4]byte(b[off2:off3])),
	}
}

var ControlPeer Peer = Peer{Remote: netip.IPv4Unspecified(), Proto: tcp.ProtocolNumber}

const (
	off1         = 0
	off2         = 1
	off3         = 5
	peerOverhead = off3
)
