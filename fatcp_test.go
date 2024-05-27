package fatcp_test

import (
	"net/netip"

	fconn "github.com/lysShub/fatun/conn"
	"github.com/lysShub/netkit/packet"
	"github.com/pkg/errors"
	"gvisor.dev/gvisor/pkg/tcpip"
)

type Mocker = *mocker

type mocker struct {
	valid   bool
	builtin bool
}

var _ fconn.Peer = &mocker{}

func (m *mocker) Builtin() fconn.Peer { return &mocker{valid: true, builtin: true} }
func (m *mocker) IsBuiltin() bool     { return m.builtin }
func (m *mocker) Valid() bool         { return m.valid }
func (m *mocker) Overhead() int       { return 1 }
func (m *mocker) String() string      { return "mocker" }
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

func (m *mocker) Reset(proto tcpip.TransportProtocolNumber, remote netip.Addr) fconn.Peer { panic("") }
func (m *mocker) Protocol() tcpip.TransportProtocolNumber                                 { panic("") }
func (m *mocker) Peer() netip.Addr                                                        { panic("") }
