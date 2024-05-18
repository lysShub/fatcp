package fatcp

import (
	"context"
	"io"
	"math/rand"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/lysShub/fatcp/crypto"
	"github.com/pkg/errors"
	"golang.org/x/sync/errgroup"

	"github.com/lysShub/netkit/packet"
	"github.com/lysShub/rawsock/test"
	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

var sign = &Sign{
	Sign: []byte("0123456789abcdef"),
	Parser: func(ctx context.Context, sign []byte) (crypto.Key, error) {
		if string(sign) == "0123456789abcdef" {
			return crypto.Key{9: 1}, nil
		}
		return crypto.Key{}, errors.New("invalid sign")
	},
}

func Test_BuiltinTCP_Connect(t *testing.T) {
	// test builtin-tcp transmit data as normal tcp connect
	var (
		caddr = netip.AddrPortFrom(test.LocIP(), 19986)
		saddr = netip.AddrPortFrom(test.LocIP(), 8080)
		cfg   = &Config{
			Handshake:    sign,
			MTU:          1500,
			RecvErrLimit: 8,
		}
	)
	c, s := test.NewMockRaw(
		t, header.TCPProtocolNumber, caddr, saddr,
		test.ValidAddr, test.ValidChecksum, test.PacketLoss(0.1), test.Delay(time.Millisecond*50),
	)
	eg, ctx := errgroup.WithContext(context.Background())

	// echo server
	eg.Go(func() error {
		l, err := NewListener[*Peer](test.NewMockListener(t, s), cfg)
		require.NoError(t, err)
		defer l.Close()

		conn, err := l.Accept()
		require.NoError(t, err)
		defer conn.Close()

		eg.Go(func() error {
			var p = packet.From(make([]byte, cfg.MTU))
			_, err := conn.Recv(ctx, p)
			require.True(t, errors.Is(err, net.ErrClosed), err)
			return nil
		})

		tcp, err := conn.BuiltinTCP(ctx)
		require.NoError(t, err)
		_, err = io.Copy(tcp, tcp)
		require.Contains(t, []error{io.EOF, nil}, err)
		return nil
	})

	// client
	eg.Go(func() error {
		conn, err := NewConn[*Peer](c, cfg)
		require.NoError(t, err)
		defer conn.Close()

		eg.Go(func() error {
			var p = packet.Make(0, cfg.MTU)
			_, err := conn.Recv(ctx, p)
			require.True(t, errors.Is(err, net.ErrClosed), err)
			return nil
		})

		tcp, err := conn.BuiltinTCP(ctx)
		require.NoError(t, err)
		rander := rand.New(rand.NewSource(0))
		test.ValidPingPongConn(t, rander, tcp, 0xffff)

		return nil
	})

	eg.Wait()
}

func Test_BuiltinTCP_Keepalive(t *testing.T) {
	// test builtin-tcp transmit data as normal tcp connect
	var (
		caddr = netip.AddrPortFrom(test.LocIP(), 19986)
		saddr = netip.AddrPortFrom(test.LocIP(), 8080)
		cfg   = &Config{
			Handshake:    sign,
			MTU:          1500,
			RecvErrLimit: 8,
		}
	)

	t.Run("server-shutdown/client-read", func(t *testing.T) {
		c, s := test.NewMockRaw(
			t, header.TCPProtocolNumber, caddr, saddr,
			test.ValidAddr, test.ValidChecksum, test.PacketLoss(0.1), test.Delay(time.Millisecond*50),
		)
		eg, ctx := errgroup.WithContext(context.Background())

		// echo server
		eg.Go(func() error {
			defer s.Close()
			l, err := NewListener[*Peer](test.NewMockListener(t, s), cfg)
			require.NoError(t, err)

			conn, err := l.Accept()
			require.NoError(t, err)

			eg.Go(func() error {
				var p = packet.From(make([]byte, cfg.MTU))
				_, err := conn.Recv(ctx, p)
				require.True(t, errors.Is(err, net.ErrClosed), err)
				return nil
			})

			tcp, err := conn.BuiltinTCP(ctx)
			require.NoError(t, err)

			io.ReadFull(tcp, make([]byte, 0xff))
			return nil
		})

		// client
		eg.Go(func() error {
			conn, err := NewConn[*Peer](c, cfg)
			require.NoError(t, err)
			defer conn.Close()

			eg.Go(func() error {
				var p = packet.Make(0, cfg.MTU)
				_, err := conn.Recv(ctx, p)
				require.True(t, errors.Is(err, net.ErrClosed), err)
				return nil
			})

			handshakeCtx, cancel := context.WithTimeout(ctx, time.Second*5)
			defer cancel()
			tcp, err := conn.BuiltinTCP(handshakeCtx)
			require.NoError(t, err)
			n, err := tcp.Write(make([]byte, 0xff))
			require.NoError(t, err)
			require.Equal(t, 0xff, n)

			n, err = tcp.Read(make([]byte, 1))
			require.Error(t, err)
			require.Contains(t, err.Error(), "timed out")
			require.Zero(t, n)
			return nil
		})

		eg.Wait()
	})

}
