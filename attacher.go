package fatcp

import (
	"github.com/lysShub/netkit/packet"
)

type Attacher interface {
	Valid() bool
	String() string
	Builtin() Attacher
	IsBuiltin() bool
	Overhead() int
	Encode(pkt *packet.Packet) error
	Decode(pkt *packet.Packet) error
}
