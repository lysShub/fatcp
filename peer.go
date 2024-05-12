package fatcp

import (
	"fmt"
	"net/netip"
	"syscall"

	"github.com/lysShub/netkit/debug"
	"github.com/lysShub/netkit/packet"
	"github.com/lysShub/rawsock/test"
	"github.com/stretchr/testify/require"
)

type Peer struct {
	Remote netip.Addr
	Proto  uint8
}

func (id Peer) String() string {
	return fmt.Sprintf("%s:%s", "ProtoStr(id.Proto)", id.Remote.String())
}

func (id Peer) Valid() bool {
	return id.Remote.IsValid() &&
		(id.Proto == syscall.IPPROTO_TCP || id.Proto == syscall.IPPROTO_UDP)
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
	if p.Proto == syscall.IPPROTO_TCP {
		pkt.Attach([]byte{tcp})
	} else if p.Proto == syscall.IPPROTO_UDP {
		pkt.Attach([]byte{udp})
	} else {
		panic("")
	}
}

func decode(seg *packet.Packet) Peer {
	b := seg.Bytes()
	seg.SetHead(seg.Head() + peerOverhead)
	return Peer{
		Proto:  proto(b[off1:off2]),
		Remote: netip.AddrFrom4([4]byte(b[off2:off3])),
	}
}

func proto(b []byte) uint8 {
	switch b[0] {
	case tcp:
		return syscall.IPPROTO_TCP
	case udp:
		return syscall.IPPROTO_UDP
	default:
		panic("")
	}
}

var ControlPeer Peer = Peer{Remote: netip.IPv4Unspecified(), Proto: syscall.IPPROTO_TCP}

const (
	off1         = 0
	off2         = 1
	off3         = 5
	peerOverhead = off3
)
