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

type Peer struct {
	Remote netip.Addr
	Proto  tcpip.TransportProtocolNumber
}

func (id Peer) String() string {
	return fmt.Sprintf("%s:%s", "ProtoStr(id.Proto)", id.Remote.String())
}

func (id Peer) Valid() bool {
	return id.Remote.IsValid() &&
		(id.Proto == tcp.ProtocolNumber || id.Proto == udp.ProtocolNumber)
}

func encode(pkt *packet.Packet, p Peer) {
	if debug.Debug() {
		require.True(test.T(), p.Remote.Is4())
	}
	pkt.Attach(p.Remote.AsSlice())
	switch p.Proto {
	case tcp.ProtocolNumber, udp.ProtocolNumber:
		pkt.Attach([]byte{byte(p.Proto)})
	default:
		panic("")
	}
}

func decode(seg *packet.Packet) (Peer, error) {
	b := seg.Bytes()
	if len(b) < peerSize {
		return Peer{}, errors.WithStack(&ErrInvalidPacket{})
	}

	seg.SetHead(seg.Head() + peerSize)
	return Peer{
		Proto:  tcpip.TransportProtocolNumber(b[off1]),
		Remote: netip.AddrFrom4([4]byte(b[off2:off3])),
	}, nil
}

var BuiltinPeer Peer = Peer{Remote: netip.IPv4Unspecified(), Proto: tcp.ProtocolNumber}

func isBuiltin(seg *packet.Packet) bool {
	p, err := decode(seg)
	return err == nil && p == BuiltinPeer
}

const (
	off1     = 0
	off2     = 1
	off3     = 5
	peerSize = off3
)

/*

func Test_Recv_Invalid_Packet(t *testing.T) {
	var (
		caddr = netip.AddrPortFrom(test.LocIP(), 19986)
		saddr = netip.AddrPortFrom(test.LocIP(), 8080)
		cfg   = &Config{
			Handshake:    sign,
			MTU:          1500,
			RecvErrLimit: 8,
		}
		peer = Peer{Remote: netip.IPv4Unspecified(), Proto: header.UDPProtocolNumber}
	)
	c, s := test.NewMockRaw(
		t, header.TCPProtocolNumber,
		caddr, saddr,
		test.ValidAddr, test.ValidChecksum, test.Delay(time.Millisecond*50),
	)
	eg, ctx := errgroup.WithContext(context.Background())

	// echo server
	eg.Go(func() error {
		l, err := NewListener(test.NewMockListener(t, s), cfg)
		require.NoError(t, err)
		defer l.Close()

		conn, err := l.Accept()
		require.NoError(t, err)
		defer conn.Close()

		var p = packet.From(make([]byte, cfg.MTU))
		for {
			id, err := conn.Recv(ctx, p.Sets(0, cfg.MTU))
			if errorx.Temporary(err) {
				continue
			}
			require.NoError(t, err)
			require.Equal(t, id, peer)

			break
		}
		return nil
	})

	// client
	eg.Go(func() error {
		conn, err := NewConn(c, cfg)
		require.NoError(t, err)
		defer conn.Close()

		err = conn.Send(ctx, packet.Make(), peer)
		require.NoError(t, err)
		return nil
	})

	eg.Wait()
}


*/
