package fatcp_test

import (
	"context"
	"math/rand"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/lysShub/fatcp"
	"github.com/lysShub/fatun/conn/crypto"
	"github.com/lysShub/rawsock/test"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

func Test_Handshake_Context_Cancel(t *testing.T) {
	t.Skip("todo: rawsock support deadline")

	t.Run("Handshake-Exceeded", func(t *testing.T) {
		var (
			caddr = netip.AddrPortFrom(test.LocIP(), 19986)
			saddr = netip.AddrPortFrom(test.LocIP(), 8080)
			cfg   = &fatcp.Config{
				Handshake: &fatcp.Sign{
					Sign: func() []byte {
						sign := make([]byte, 1024*1024*8)
						rand.New(rand.NewSource(0)).Read(sign) // avoid gob compress
						return sign
					}(),
					Parser: func(context.Context, []byte) (crypto.Key, error) { return crypto.Key{1: 1}, nil },
				},
				MTU:          1500,
				RecvErrLimit: 8,
			}
		)

		c, s := test.NewMockRaw(
			t, header.TCPProtocolNumber,
			caddr, saddr,
			test.ValidAddr, test.ValidChecksum, test.PacketLoss(0.05), test.Delay(time.Millisecond*50),
		)
		ctx, cancel := context.WithTimeout(context.Background(), time.Second*3)
		defer cancel()
		eg, ctx := errgroup.WithContext(ctx)

		// server
		eg.Go(func() error {
			l, err := fatcp.NewListener[Mocker](test.NewMockListener(t, s), cfg)
			require.NoError(t, err)
			defer l.Close()

			conn, err := l.AcceptCtx(ctx)
			require.NoError(t, err)
			_, err = conn.BuiltinTCP(ctx)
			require.True(t, errors.Is(err, context.DeadlineExceeded), err)
			return nil
		})

		// client
		eg.Go(func() error {
			conn, err := fatcp.NewConn[Mocker](c, cfg)
			require.NoError(t, err)
			_, err = conn.BuiltinTCP(ctx)
			require.True(t, errors.Is(err, os.ErrDeadlineExceeded), err)
			return nil
		})

		eg.Wait()
	})

	t.Run("Handshake-Cancle", func(t *testing.T) {
		var (
			caddr = netip.AddrPortFrom(test.LocIP(), 19986)
			saddr = netip.AddrPortFrom(test.LocIP(), 8080)
			cfg   = &fatcp.Config{
				Handshake: &fatcp.Sign{
					Sign: func() []byte {
						sign := make([]byte, 1024*1024*8)
						rand.New(rand.NewSource(0)).Read(sign) // avoid gob compress
						return sign
					}(),
					Parser: func(context.Context, []byte) (crypto.Key, error) { return crypto.Key{1: 1}, nil },
				},
				MTU:          1500,
				RecvErrLimit: 8,
			}
		)
		c, s := test.NewMockRaw(
			t, header.TCPProtocolNumber,
			caddr, saddr,
			test.ValidAddr, test.ValidChecksum, test.PacketLoss(0.1), test.Delay(time.Millisecond*50),
		)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		eg, ctx := errgroup.WithContext(ctx)

		eg.Go(func() error {
			l, err := fatcp.NewListener[Mocker](test.NewMockListener(t, s), cfg)
			require.NoError(t, err)
			defer l.Close()

			conn, err := l.AcceptCtx(ctx)
			require.NoError(t, err)
			_, err = conn.BuiltinTCP(ctx)
			require.True(t, errors.Is(err, context.Canceled), err)
			return nil
		})

		// client
		eg.Go(func() error {
			conn, err := fatcp.NewConn[Mocker](c, cfg)
			require.NoError(t, err)
			_, err = conn.BuiltinTCP(ctx)

			ok := errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, context.Canceled)
			require.True(t, ok, err)
			return nil
		})

		time.Sleep(time.Second)
		cancel()
		eg.Wait()
	})
}
