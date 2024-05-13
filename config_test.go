package fatcp

import (
	"context"
	"io"
	"math/rand"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/lysShub/netkit/packet"
	"github.com/lysShub/rawsock/test"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

func Test_NotCrypto(t *testing.T) {
	var (
		caddr = netip.AddrPortFrom(test.LocIP(), 19986) // test.RandPort()
		saddr = netip.AddrPortFrom(test.LocIP(), 8080)  // test.RandPort()
		cfg   = &Config{
			Handshake:    &NotCrypto{},
			MTU:          1500,
			RecvErrLimit: 8,
		}
	)
	c, s := test.NewMockRaw(
		t, header.TCPProtocolNumber,
		caddr, saddr,
		test.ValidAddr, test.ValidChecksum, test.PacketLoss(0.1), test.Delay(time.Millisecond*50),
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
		conn, err := NewConn(c, cfg)
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

func Test_MTU(t *testing.T) {
	var cfg = &Config{}
	err := cfg.Init(test.LocIP())
	require.NoError(t, err)

	require.Greater(t, cfg.MTU, 512)
}
