package faketcp

import (
	"math"
	"math/rand"
	"sync/atomic"

	"github.com/lysShub/fatcp/crypto"
	"github.com/lysShub/netkit/errorx"
	"github.com/lysShub/netkit/packet"
	"github.com/stretchr/testify/require"

	"github.com/lysShub/netkit/debug"
	"github.com/lysShub/rawsock/test"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

const Overhead = 20 + crypto.Bytes

// record tcp seq/ack, not care handshake/clode, etc.
// todo: more reasonable wnd
type FakeTCP struct {
	lport, rport uint16
	sndNxt       atomic.Uint32
	rcvNxt       atomic.Uint32

	pseudoSum1 *uint16
	crypto     crypto.Crypto
	speed      *speed
}

// PseudoSum1 if set, will calc tcp header checksum
func PseudoSum1(s uint16) func(f *FakeTCP) {
	return func(opt *FakeTCP) { opt.pseudoSum1 = &s }
}

func Crypto(c crypto.Crypto) func(f *FakeTCP) {
	return func(f *FakeTCP) { f.crypto = c }
}

// New set fake tcp header
func New(localPort, remotePort uint16, opts ...func(*FakeTCP)) *FakeTCP {
	var f = &FakeTCP{
		lport: localPort,
		rport: remotePort,

		speed: NewSpeed(0xffff),
	}
	f.sndNxt.Store(rand.Uint32())
	f.rcvNxt.Store(rand.Uint32())
	for _, opt := range opts {
		opt(f)
	}

	return f
}

func (f *FakeTCP) InitNxt(snd, rcv uint32) {
	f.sndNxt.Store(snd)
	f.rcvNxt.Store(rcv)
}

// calcWnd reverse calc tcp window-size by speed(B/s)
func calcWnd(speed float64) uint16 {
	const rtt = 100 // ms

	const n = float64(1000) / float64(rtt)
	wnd := int(math.Round(speed / n))
	if wnd >= 0xffff {
		wnd = 0xffff
	}
	if wnd < 1024 {
		wnd = 1024
	}
	return uint16(wnd)
}

// AttachSend input tcp payload, attach tcp header, and return
// tcp packet.
func (f *FakeTCP) AttachSend(seg *packet.Packet) {
	f.speed.Add(uint32(seg.Data()))

	payload := seg.Data()
	var hdr = make(header.TCP, header.TCPMinimumSize)
	hdr.Encode(&header.TCPFields{
		SrcPort:    f.lport,
		DstPort:    f.rport,
		SeqNum:     f.sndNxt.Load(),
		AckNum:     f.rcvNxt.Load(),
		DataOffset: header.TCPMinimumSize,
		// todo: if ACK not increase，not set ack，otherwise: TCP segment of a reassembled PDU
		Flags:         header.TCPFlagPsh | header.TCPFlagAck,
		WindowSize:    calcWnd(f.speed.Speed()),
		Checksum:      0,
		UrgentPointer: 0,
	})
	seg.Attach(hdr)

	if f.crypto != nil {
		f.sndNxt.Add(uint32(payload + f.crypto.Overhead()))
		f.crypto.Encrypt(seg)
	} else if f.pseudoSum1 != nil {
		f.sndNxt.Add(uint32(payload))

		tcp := header.TCP(seg.Bytes())
		psum := checksum.Combine(*f.pseudoSum1, uint16(len(tcp)))

		sum := checksum.Checksum(tcp, psum)
		tcp.SetChecksum(^sum)

		if debug.Debug() {
			test.ValidTCP(test.T(), seg.Bytes(), *f.pseudoSum1)
		}
	}
}

// DetachRecv input a tcp packet, update ack, and return
// tcp payload.
func (f *FakeTCP) DetachRecv(tcp *packet.Packet) error {
	if f.crypto != nil {
		if err := f.crypto.Decrypt(tcp); err != nil {
			return errorx.WrapTemp(err)
		}
	} else if f.pseudoSum1 != nil {
		if debug.Debug() {
			hdr := header.TCP(tcp.Bytes())
			require.False(test.T(), Is(hdr))
			test.ValidTCP(test.T(), hdr, *f.pseudoSum1)
		}
	}

	hdr := header.TCP(tcp.Bytes())
	f.rcvNxt.Store(max(f.rcvNxt.Load(), hdr.SequenceNumber()+uint32(len(hdr.Payload()))))
	// f.ack.Store(max(f.ack.Load(), hdr.SequenceNumber()))

	// remove tcp header
	tcp.SetHead(tcp.Head() + int(hdr.DataOffset()))
	return nil
}

const ()

func Is(tcp header.TCP) bool {
	return tcp.DataOffset() == header.TCPMinimumSize
}

// ToNot make to not-fack tcp packet, requir tcp with correct tcp checksume.
func ToNot(tcp *packet.Packet) *packet.Packet {
	if Is(tcp.Bytes()) {
		b := header.TCP(tcp.AttachN(4).Bytes())
		copy(b[:header.TCPMinimumSize], b[4:])
		copy(b[header.TCPMinimumSize:], opts)

		b.SetDataOffset(b.DataOffset() + 4)
		b.SetChecksum(^checksum.Combine(^b.Checksum(), deltaSum))
	}

	return tcp
}

// useless tcp option
var opts = []byte{1, 1, 1, 0}
var deltaSum = checksum.Checksum(
	opts,
	1<<(4+8)+ // data-offset
		4, // pseudo-header totalLen
)
