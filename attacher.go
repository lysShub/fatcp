package fatcp

import (
	"fmt"
	"net/netip"

	"github.com/lysShub/netkit/debug"
	"github.com/lysShub/netkit/packet"
	"github.com/lysShub/rawsock/test"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

type Attacher interface {
	// new a Attacher vaiable(not nil if pointer), require New().IsBuiltin()==false and
	// New().Valid()==false.
	New() Attacher

	Builtin() Attacher
	IsBuiltin() bool
	Valid() bool
	Overhead() int
	String() string
	Encode(pkt *packet.Packet) error
	Decode(pkt *packet.Packet) error
}

type Peer struct {
	Remote netip.Addr // only ipv4
	Proto  tcpip.TransportProtocolNumber
}

var _ Attacher = (*Peer)(nil)

func (p *Peer) New() Attacher { return &Peer{} }

var _builtinPeer = &Peer{Remote: netip.IPv4Unspecified(), Proto: tcp.ProtocolNumber}

func (p *Peer) Builtin() Attacher { return _builtinPeer }
func (id *Peer) IsBuiltin() bool {
	return id.Valid() && id.Remote.IsUnspecified() && id.Proto == tcp.ProtocolNumber
}
func (p *Peer) Overhead() int { return 5 }
func (id *Peer) Valid() bool {
	return id != nil && id.Remote.IsValid() && id.Remote.Is4() &&
		(id.Proto == tcp.ProtocolNumber || id.Proto == udp.ProtocolNumber)
}

func (id *Peer) String() string {
	if id == nil {
		return "nil"
	}
	var proto string
	switch id.Proto {
	case tcp.ProtocolNumber:
		proto = "tcp"
	case udp.ProtocolNumber:
		proto = "udp"
	default:
		proto = fmt.Sprintf("unknown(%d)", id.Proto)
	}
	return fmt.Sprintf("%s:%s", id.Remote.String(), proto)
}

func (p *Peer) Encode(pkt *packet.Packet) error {
	if !p.Valid() {
		return errors.Errorf("invalid peer: %s", p.String())
	}
	if debug.Debug() {
		require.True(test.T(), p.Remote.Is4())
	}

	pkt.Attach(p.Remote.AsSlice())
	switch p.Proto {
	case tcp.ProtocolNumber, udp.ProtocolNumber:
		pkt.Attach([]byte{byte(p.Proto)})
	default:
		return errors.Errorf("not support protocol %d", p.Proto)
	}
	return nil
}

func (p *Peer) Decode(seg *packet.Packet) (err error) {
	if p == nil {
		return errors.Errorf("invalid peer: %s", p.String())
	}

	b := seg.Bytes()
	if len(b) < 5 {
		return errors.WithStack(&ErrInvalidPacket{})
	}

	p.Proto = tcpip.TransportProtocolNumber(b[0])
	p.Remote = netip.AddrFrom4([4]byte(b[1:5]))
	seg.SetHead(seg.Head() + 5)
	return nil
}
