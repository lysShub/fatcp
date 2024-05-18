package fatcp

import "github.com/lysShub/netkit/packet"

type Mocker struct {
	valid   bool
	builtin bool
}

var _ Attacher = &Mocker{}

func (m Mocker) New() Attacher                   { return Mocker{} }
func (m Mocker) Builtin() Attacher               { return Mocker{valid: true, builtin: true} }
func (m Mocker) IsBuiltin() bool                 { return m.builtin }
func (m Mocker) Valid() bool                     { return m.builtin }
func (m Mocker) Overhead() int                   { return 0 }
func (m Mocker) String() string                  { return "mocker" }
func (m Mocker) Encode(pkt *packet.Packet) error { return nil }
func (m Mocker) Decode(pkt *packet.Packet) error { return nil }
