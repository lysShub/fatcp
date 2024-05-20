package fatcp

import (
	"github.com/lysShub/netkit/packet"
)

type Attacher interface {
	Valid() bool
	String() string
	Overhead() int
	Builtin() Attacher
	IsBuiltin() bool
	Encode(pkt *packet.Packet) error
	Decode(pkt *packet.Packet) error
}
