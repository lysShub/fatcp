package fatcp

import (
	"github.com/lysShub/netkit/packet"
)

type Attacher interface {
	Builtin() Attacher
	IsBuiltin() bool
	Valid() bool
	Overhead() int
	String() string
	Encode(pkt *packet.Packet) error
	Decode(pkt *packet.Packet) error
}
