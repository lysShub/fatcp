package gonet_test

import (
	"context"
	"errors"
	"io"
	"math/rand"
	"net/netip"
	"testing"

	"github.com/lysShub/fatcp/ustack"
	"github.com/lysShub/fatcp/ustack/gonet"
	"github.com/lysShub/fatcp/ustack/link"
	"github.com/lysShub/netkit/packet"
	"github.com/lysShub/rawsock/test"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

func Test_WaitSentDataRecvByPeer(t *testing.T) {
	var (
		wg, ctx = errgroup.WithContext(context.Background())
		caddr   = netip.AddrPortFrom(test.RandIP(), 19986)
		saddr   = netip.AddrPortFrom(test.RandIP(), 8080)
		cl, sl  = newDuplexLink(t, ctx)
	)

	wg.Go(func() error {
		us, err := ustack.NewUstack(sl, saddr.Addr())
		require.NoError(t, err)

		l, err := gonet.ListenTCP(us, saddr, header.IPv4ProtocolNumber)
		require.NoError(t, err)
		defer l.Close()

		conn, err := l.Accept(ctx)
		require.NoError(t, err)
		defer conn.Close()

		_, err = io.Copy(conn, conn)
		return err
	})

	wg.Go(func() error {
		uc, err := ustack.NewUstack(cl, caddr.Addr())
		require.NoError(t, err)

		conn, err := gonet.DialTCPWithBind(ctx, uc, caddr, saddr, header.IPv4ProtocolNumber)
		require.NoError(t, err)
		defer conn.Close()

		test.ValidPingPongConn(t, rand.New(rand.NewSource(0)), conn, 0xffff)

		_, _, err = conn.WaitSentDataRecvByPeer(ctx)
		require.NoError(t, err)
		return nil
	})

	err := wg.Wait()
	ok := err == nil || // io.EOF
		errors.Is(err, gonet.ErrConnectReset)
	require.True(t, ok)
}

func newDuplexLink(t require.TestingT, ctx context.Context) (c, s link.Link) {
	c = link.NewListWithID(8, 1500, "client")
	s = link.NewListWithID(8, 1500, "server")

	// p, err := test.NewPcap("gonet.pcap")
	// require.NoError(t, err)

	go func() {
		for {
			var pkt = packet.Make(0, 1500)

			err := c.Outbound(ctx, pkt.SetHead(0))
			if errors.Is(err, context.Canceled) {
				return
			}
			require.NoError(t, err)

			s.Inbound(pkt.SetHead(0))
			// require.NoError(t, p.WriteIP(pkt.Bytes()))
		}
	}()
	go func() {
		for {
			var pkt = packet.Make(0, 1500)

			err := s.Outbound(ctx, pkt.SetHead(0))
			if errors.Is(err, context.Canceled) {
				return
			}
			require.NoError(t, err)

			c.Inbound(pkt.SetHead(0))
			// require.NoError(t, p.WriteIP(pkt.Bytes()))
		}
	}()

	return c, s
}
