package fatcp

import (
	"fmt"
	"net/netip"

	"github.com/lysShub/netkit/debug"
	"github.com/lysShub/netkit/packet"
	"github.com/lysShub/rawsock/test"
	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
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
		(id.Proto == header.TCPProtocolNumber || id.Proto == header.UDPProtocolNumber)
}

const (
	tcp = 0
	udp = 1
)

func encode(pkt *packet.Packet, p Peer) {
	if debug.Debug() {
		require.True(test.T(), p.Remote.Is4())
	}
	pkt.Attach(p.Remote.AsSlice())
	if p.Proto == header.TCPProtocolNumber {
		pkt.Attach([]byte{tcp})
	} else if p.Proto == header.UDPProtocolNumber {
		pkt.Attach([]byte{udp})
	} else {
		panic("")
	}
}

func decode(seg *packet.Packet) Peer {
	b := seg.Bytes()
	seg.SetHead(seg.Head() + Overhead)
	return Peer{
		Proto:  proto(b[off1:off2]),
		Remote: netip.AddrFrom4([4]byte(b[off2:off3])),
	}
}

func proto(b []byte) tcpip.TransportProtocolNumber {
	switch b[0] {
	case tcp:
		return header.TCPProtocolNumber
	case udp:
		return header.UDPProtocolNumber
	default:
		panic("")
	}
}

var ControlPeer Peer = Peer{Remote: netip.IPv4Unspecified(), Proto: header.TCPProtocolNumber}

const (
	off1         = 0
	off2         = 1
	off3         = 5
	peerOverhead = off3
)
