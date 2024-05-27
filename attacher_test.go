package fatcp_test

import (
	"errors"

	"github.com/lysShub/fatcp"
	"github.com/lysShub/netkit/packet"
)

type Mocker = *mocker

type mocker struct {
	valid   bool
	builtin bool
}

var _ fatcp.Attacher = &mocker{}

func (m *mocker) Builtin() fatcp.Attacher { return &mocker{valid: true, builtin: true} }
func (m *mocker) IsBuiltin() bool         { return m.builtin }
func (m *mocker) Valid() bool             { return m.valid }
func (m *mocker) Overhead() int           { return 1 }
func (m *mocker) String() string          { return "mocker" }
func (m *mocker) Encode(pkt *packet.Packet) error {
	if m.builtin {
		pkt.Attach([]byte{1})
	} else {
		pkt.Attach([]byte{0})
	}
	return nil
}
func (m *mocker) Decode(pkt *packet.Packet) error {
	b := pkt.Detach(make([]byte, 1))
	if b[0] == 1 {
		m.builtin = true
		m.valid = true
	} else if b[0] == 0 {
		m.builtin = false
		m.valid = true
	} else {
		return errors.New("invalid  packet")
	}
	return nil
}
