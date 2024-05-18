package fatcp

import (
	"github.com/lysShub/netkit/packet"
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
