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

func Test_BuiltinTCP(t *testing.T) {
	var (
		caddr = netip.AddrPortFrom(test.LocIP(), 19986) // test.RandPort()
		saddr = netip.AddrPortFrom(test.LocIP(), 8080)  // test.RandPort()
		cfg   = &Config{
			Handshake:       sign,
			MTU:             1500,
			MaxRecvBuffSize: 1536,
			RecvErrLimit:    8,
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
			var p = packet.From(make([]byte, cfg.MaxRecvBuffSize))
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
			var p = packet.Make(0, cfg.MaxRecvBuffSize)
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
