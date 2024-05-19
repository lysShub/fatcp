package fatcp

import (
	"github.com/lysShub/netkit/packet"
)

type Mocker = *mocker

type mocker struct {
	valid   bool
	builtin bool
}

var _ Attacher = &mocker{}

func (m *mocker) Builtin() Attacher               { return &mocker{valid: true, builtin: true} }
func (m *mocker) IsBuiltin() bool                 { return m.builtin }
func (m *mocker) Valid() bool                     { return m.valid }
func (m *mocker) Overhead() int                   { return 0 }
func (m *mocker) String() string                  { return "mocker" }
func (m *mocker) Encode(pkt *packet.Packet) error { return nil }
func (m *mocker) Decode(pkt *packet.Packet) error {
	m.valid = true
	return nil
}
